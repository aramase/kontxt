// Package extauth implements an Envoy ext_authz gRPC service for TxToken
// generation and verification. It handles both entry-point token generation
// and downstream service verification via the standard ext_authz v3 protocol.
package extauth

import (
	"context"
	"fmt"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/pkg/token"
	sdktts "github.com/aramase/kontxt/sdk/tts"
	"github.com/aramase/kontxt/sdk/verify"
)

// Server implements the Envoy ext_authz v3 Authorization gRPC service.
type Server struct {
	authv3.UnimplementedAuthorizationServer

	verifier          *verify.Verifier
	verificationRules []controller.VerificationRule
	ttsClient         *sdktts.Client // for auto-narrowing
}

// NewServer creates a new ext auth server in verification mode.
func NewServer(verifier *verify.Verifier) *Server {
	return &Server{
		verifier: verifier,
	}
}

// SetVerificationRules updates the verification rules (from ServiceTokenRequirement CRDs).
func (s *Server) SetVerificationRules(rules []controller.VerificationRule) {
	s.verificationRules = rules
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
	if err := s.checkVerificationRules(claims, path, method); err != nil {
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

	for _, rule := range s.verificationRules {
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
func (s *Server) checkVerificationRules(claims *token.Claims, path, method string) error {
	for _, rule := range s.verificationRules {
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

		// CEL rules are evaluated by the ext auth adapter in production
		// For this phase, we do basic string matching on CEL rule names
		// Full CEL evaluation will be added when we integrate with the controller
	}

	return nil
}

// isExcluded checks if the request path+method matches any excluded endpoint.
func (s *Server) isExcluded(path, method string) bool {
	for _, rule := range s.verificationRules {
		for _, ep := range rule.ExcludedEndpoints {
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
func denied(code codes.Code, message string) *authv3.CheckResponse {
	httpCode := typev3.StatusCode_Unauthorized
	if code == codes.PermissionDenied {
		httpCode = typev3.StatusCode_Forbidden
	} else if code == codes.InvalidArgument {
		httpCode = typev3.StatusCode_BadRequest
	}

	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(code), Message: message},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpCode},
				Body:   fmt.Sprintf(`{"error":"%s","message":"%s"}`, code.String(), message),
			},
		},
	}
}
