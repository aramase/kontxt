// Package extauth implements an Envoy ext_authz gRPC service for TxToken
// generation and verification. It handles both entry-point token generation
// and downstream service verification via the standard ext_authz v3 protocol.
package extauth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync/atomic"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/pkg/extauth/celverify"
	"github.com/aramase/kontxt/pkg/token"
	sdktts "github.com/aramase/kontxt/sdk/tts"
	"github.com/aramase/kontxt/sdk/verify"
)

// verificationRuleSet bundles a verification rule with its pre-compiled CEL
// programs. Compilation happens once per rule push in SetVerificationRules so
// the request path never pays for parsing/typechecking.
type verificationRuleSet struct {
	rule        controller.VerificationRule
	celPrograms []celverify.Program
}

// Server implements the Envoy ext_authz v3 Authorization gRPC service.
type Server struct {
	authv3.UnimplementedAuthorizationServer

	verifier *verify.Verifier
	// verificationRules holds the current compiled rule set. Stored as an
	// atomic.Pointer so SetVerificationRules (called from the rule-streaming
	// goroutine) can swap the snapshot without taking a lock that Check
	// handlers would otherwise contend on.
	verificationRules atomic.Pointer[[]verificationRuleSet]
	ttsClient         *sdktts.Client // for auto-narrowing
}

// NewServer creates a new ext auth server in verification mode.
func NewServer(verifier *verify.Verifier) *Server {
	return &Server{
		verifier: verifier,
	}
}

// SetVerificationRules updates the verification rules (from ServiceTokenRequirement CRDs).
// Each rule's CEL expressions are compiled here so malformed CEL fails fast and
// never reaches the request path. If a CEL expression fails to compile, only
// that expression is dropped and logged; the owning rule (and its non-CEL
// constraints — RequiredScope, RequiredTctxFields) stays in the active set so
// enforcement never silently fails open. The controller's reconciler also
// filters invalid CEL before publishing, so a compile failure here typically
// means the controller and runtime have drifted (e.g. cel-go version skew) and
// should be visible in operator logs.
//
// Rules are sorted by (Namespace, Name) before compilation so the first-failing
// rule reported to clients is stable across equivalent snapshots — upstream
// callers (e.g. ruleclient) build the slice from map iteration whose order is
// non-deterministic.
func (s *Server) SetVerificationRules(rules []controller.VerificationRule) {
	sorted := append([]controller.VerificationRule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Namespace != sorted[j].Namespace {
			return sorted[i].Namespace < sorted[j].Namespace
		}
		return sorted[i].Name < sorted[j].Name
	})

	snapshot := make([]verificationRuleSet, 0, len(sorted))
	for _, r := range sorted {
		snapshot = append(snapshot, verificationRuleSet{
			rule:        r,
			celPrograms: compileVerificationRuleCEL(r),
		})
	}
	s.verificationRules.Store(&snapshot)
}

// compileVerificationRuleCEL compiles each CEL expression attached to a single
// verification rule independently. Expressions that fail to compile are
// logged and skipped — the caller still keeps the rule itself so its non-CEL
// constraints continue to apply. Returns nil when the rule has no CEL.
func compileVerificationRuleCEL(r controller.VerificationRule) []celverify.Program {
	if len(r.CELRules) == 0 {
		return nil
	}
	out := make([]celverify.Program, 0, len(r.CELRules))
	for _, c := range r.CELRules {
		programs, err := celverify.Compile([]celverify.Rule{{Name: c.Name, CEL: c.CEL, Message: c.Message}})
		if err != nil {
			log.Printf("extauth: dropping CEL expression %q on rule %s/%s: %v", c.Name, r.Namespace, r.Name, err)
			continue
		}
		out = append(out, programs...)
	}
	return out
}

// loadVerificationRules returns the current snapshot, or nil if no rules have
// been set yet. Ranging over a nil slice is a no-op, so callers can iterate
// without nil-checks. Callers should treat the returned slice as immutable.
func (s *Server) loadVerificationRules() []verificationRuleSet {
	if p := s.verificationRules.Load(); p != nil {
		return *p
	}
	return nil
}

// SetTTSClient sets the TTS client for auto-narrowing support.
func (s *Server) SetTTSClient(client *sdktts.Client) {
	s.ttsClient = client
}

// Register registers the ext auth server with a gRPC server.
func (s *Server) Register(gs *grpc.Server) {
	authv3.RegisterAuthorizationServer(gs, s)
}

// Check implements the ext_authz v3 Authorization/Check RPC.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return denied(codes.InvalidArgument, "missing HTTP request attributes"), nil
	}

	// Extract Txn-Token header
	txTokenStr := getHeader(httpReq.GetHeaders(), token.HeaderName)

	// Check if this endpoint is excluded from verification
	path := httpReq.GetPath()
	method := httpReq.GetMethod()
	if s.isExcluded(path, method) {
		return allowed(), nil
	}

	// If no Txn-Token header, deny
	if txTokenStr == "" {
		return denied(codes.Unauthenticated, "missing Txn-Token header"), nil
	}

	// Verify the TxToken
	claims, err := s.verifier.Verify(ctx, txTokenStr)
	if err != nil {
		return denied(codes.Unauthenticated, fmt.Sprintf("TxToken verification failed: %v", err)), nil
	}

	// Check ServiceTokenRequirement rules
	if err := s.checkVerificationRules(claims, path, method, httpReq.GetHeaders()); err != nil {
		return denied(codes.PermissionDenied, err.Error()), nil
	}

	// Auto-narrowing: if any rule has autoNarrow and the scope is broader, replace the token
	if narrowedToken := s.autoNarrow(ctx, claims, txTokenStr); narrowedToken != "" {
		return allowedWithHeaders(map[string]string{
			token.HeaderName: narrowedToken,
		}), nil
	}

	return allowed(), nil
}

// autoNarrow checks if any verification rule requires scope narrowing and calls the TTS
// to replace the token with a narrower-scoped one.
func (s *Server) autoNarrow(ctx context.Context, claims *token.Claims, originalToken string) string {
	if s.ttsClient == nil {
		return ""
	}

	for _, rs := range s.loadVerificationRules() {
		rule := rs.rule
		if !rule.AutoNarrow || rule.RequiredScope == "" {
			continue
		}

		// Check if the token scope is broader than the required scope
		if claims.Scope != rule.RequiredScope && scopeIsBroader(claims.Scope, rule.RequiredScope) {
			// Request a replacement token with narrowed scope
			narrowedToken, err := s.ttsClient.Exchange(ctx, &sdktts.ExchangeRequest{
				SubjectToken:     originalToken,
				SubjectTokenType: token.SubjectTokenTypeTxnToken,
				Scope:            rule.RequiredScope,
			})
			if err != nil {
				// Log error but don't fail — return original token
				return ""
			}
			return narrowedToken
		}
	}

	return ""
}

// scopeIsBroader checks if scopeA contains all scopes of scopeB plus more.
func scopeIsBroader(broader, narrower string) bool {
	broaderSet := make(map[string]bool)
	for _, s := range strings.Fields(broader) {
		broaderSet[s] = true
	}
	for _, s := range strings.Fields(narrower) {
		if !broaderSet[s] {
			return false // narrower has a scope not in broader
		}
	}
	return len(strings.Fields(broader)) > len(strings.Fields(narrower))
}

// checkVerificationRules checks the TxToken claims against ServiceTokenRequirement rules.
func (s *Server) checkVerificationRules(claims *token.Claims, path, method string, headers map[string]string) error {
	rules := s.loadVerificationRules()

	// Build the CEL activation lazily — only marshal once per request and
	// only if at least one rule actually carries CEL programs.
	var celCtx *celverify.Context
	celCtxFor := func() (*celverify.Context, error) {
		if celCtx != nil {
			return celCtx, nil
		}
		txMap, err := claimsToMap(claims)
		if err != nil {
			return nil, fmt.Errorf("converting txtoken claims for CEL: %w", err)
		}
		celCtx = &celverify.Context{
			TxToken: txMap,
			Request: map[string]any{
				"path":    path,
				"method":  method,
				"headers": headersToCEL(headers),
			},
		}
		return celCtx, nil
	}

	for _, rs := range rules {
		rule := rs.rule
		// Check required scope
		if rule.RequiredScope != "" {
			if !scopeContains(claims.Scope, rule.RequiredScope) {
				return fmt.Errorf("token scope %q does not contain required scope %q (rule: %s)",
					claims.Scope, rule.RequiredScope, rule.Name)
			}
		}

		// Check required tctx fields
		for _, field := range rule.RequiredTctxFields {
			if claims.TransactionContext == nil {
				return fmt.Errorf("tctx is nil but field %q is required (rule: %s)", field, rule.Name)
			}
			if _, ok := claims.TransactionContext[field]; !ok {
				return fmt.Errorf("required tctx field %q missing (rule: %s)", field, rule.Name)
			}
		}

		// Evaluate compiled CEL programs (if any).
		if len(rs.celPrograms) > 0 {
			ctx, err := celCtxFor()
			if err != nil {
				return err
			}
			if err := celverify.Evaluate(rs.celPrograms, ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

// claimsToMap converts a TxToken Claims struct into a generic map for CEL
// access. We round-trip through JSON so the in-CEL field names match the JSON
// tags (sub, scope, tctx, rctx, ...) exactly as documented to operators.
func claimsToMap(c *token.Claims) (map[string]any, error) {
	if c == nil {
		return map[string]any{}, nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// headersToCEL converts a flat header map (Envoy-normalised, lower-case keys)
// into the map[string]any shape CEL expects. We keep it lower-cased so author
// expressions like `request.headers["x-trace-id"]` work consistently.
func headersToCEL(headers map[string]string) map[string]any {
	out := make(map[string]any, len(headers))
	for k, v := range headers {
		out[strings.ToLower(k)] = v
	}
	return out
}

// isExcluded checks if the request path+method matches any excluded endpoint.
func (s *Server) isExcluded(path, method string) bool {
	for _, rs := range s.loadVerificationRules() {
		for _, ep := range rs.rule.ExcludedEndpoints {
			if matchPath(path, ep.Path) && strings.EqualFold(method, ep.Method) {
				return true
			}
		}
	}
	return false
}

// getHeader extracts a header value (case-insensitive) from the request headers map.
func getHeader(headers map[string]string, name string) string {
	// Envoy normalizes header names to lowercase
	lower := strings.ToLower(name)
	if v, ok := headers[lower]; ok {
		return v
	}
	// Also try original case
	if v, ok := headers[name]; ok {
		return v
	}
	return ""
}

// matchPath does simple path matching. Supports exact match and prefix match with trailing /*.
func matchPath(requestPath, pattern string) bool {
	// Strip query string
	if idx := strings.Index(requestPath, "?"); idx >= 0 {
		requestPath = requestPath[:idx]
	}
	return requestPath == pattern || strings.HasPrefix(requestPath, pattern+"/")
}

// scopeContains checks if scopeString (space-delimited) contains the required scope.
func scopeContains(scopeString, required string) bool {
	for _, s := range strings.Fields(scopeString) {
		if s == required {
			return true
		}
	}
	return false
}

// allowed creates an OK response that allows the request to proceed.
func allowed() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{},
		},
	}
}

// denied creates a DENIED response with the given HTTP status and message.
// The response body is built via json.Marshal so that messages containing
// quotes (e.g. CEL denial messages or upstream errors) never produce invalid
// JSON or enable injection.
func denied(code codes.Code, message string) *authv3.CheckResponse {
	httpCode := typev3.StatusCode_Unauthorized
	if code == codes.PermissionDenied {
		httpCode = typev3.StatusCode_Forbidden
	} else if code == codes.InvalidArgument {
		httpCode = typev3.StatusCode_BadRequest
	}

	body, err := json.Marshal(struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{Error: code.String(), Message: message})
	if err != nil {
		// json.Marshal on a struct with two string fields cannot fail in
		// practice; fall back to a static body to keep the response well-formed.
		body = []byte(`{"error":"Internal","message":"failed to encode denial body"}`)
	}

	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(code), Message: message},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpCode},
				Body:   string(body),
			},
		},
	}
}
