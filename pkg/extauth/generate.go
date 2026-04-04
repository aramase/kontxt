package extauth

import (
	"context"
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/pkg/token"
	sdktts "github.com/aramase/kontxt/sdk/tts"
)

// RegisterGenerationServer registers the generation server with a gRPC server.
func RegisterGenerationServer(gs *grpc.Server, s *GenerationServer) {
	authv3.RegisterAuthorizationServer(gs, s)
}

// GenerationServer implements ext_authz for TxToken generation at entry points.
// It handles both external traffic (with OAuth AT) and internal traffic (identity
// resolved from CheckRequest metadata).
type GenerationServer struct {
	authv3.UnimplementedAuthorizationServer

	ttsClient        *sdktts.Client
	identityResolver *IdentityResolver
	generationRules  []controller.GenerationRule
}

// NewGenerationServer creates a new ext auth server in generation mode.
func NewGenerationServer(ttsClient *sdktts.Client, resolver *IdentityResolver) *GenerationServer {
	return &GenerationServer{
		ttsClient:        ttsClient,
		identityResolver: resolver,
	}
}

// SetGenerationRules updates the generation rules (from TransactionType CRDs).
func (s *GenerationServer) SetGenerationRules(rules []controller.GenerationRule) {
	s.generationRules = rules
}

// Check implements the ext_authz v3 Authorization/Check RPC for token generation.
func (s *GenerationServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return denied(codes.InvalidArgument, "missing HTTP request attributes"), nil
	}

	path := httpReq.GetPath()
	method := httpReq.GetMethod()

	// Find a matching generation rule
	rule := s.findMatchingRule(path, method)
	if rule == nil {
		// No matching rule — pass through without generating a TxToken
		return allowed(), nil
	}

	// Determine the subject token
	authHeader := getHeader(httpReq.GetHeaders(), "Authorization")
	var subjectToken string
	var subjectTokenType string

	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		// External traffic: use the OAuth access token
		subjectToken = strings.TrimPrefix(authHeader, "Bearer ")
		subjectTokenType = token.SubjectTokenTypeAccessToken
	} else {
		// Internal traffic: resolve identity from CheckRequest metadata
		principal := ""
		sourceIP := ""
		if src := req.GetAttributes().GetSource(); src != nil {
			principal = src.GetPrincipal()
			if addr := src.GetAddress(); addr != nil {
				if sa := addr.GetSocketAddress(); sa != nil {
					sourceIP = sa.GetAddress()
				}
			}
		}

		identity, err := s.identityResolver.Resolve(principal, sourceIP)
		if err != nil {
			return denied(codes.Unauthenticated, fmt.Sprintf("failed to resolve workload identity: %v", err)), nil
		}

		// For internal workloads, we pass the resolved identity as the subject token
		// The TTS handles kubernetes-sa subject tokens
		subjectToken = identity.Subject
		subjectTokenType = "urn:ietf:params:oauth:token-type:kubernetes-sa"
	}

	// Build request details (tctx) from the generation rule
	requestDetails := map[string]any{
		"purpose": rule.Purpose,
	}
	// In a full implementation, we'd extract fields from the request per tctxMapping.
	// For this phase, we include the purpose and any static fields.

	// Build request context (rctx)
	requestContext := map[string]any{}
	if sourceAddr := extractSourceAddress(req); sourceAddr != "" {
		requestContext["req_ip"] = sourceAddr
	}
	if authHeader != "" {
		requestContext["authn"] = "oidc"
	} else {
		requestContext["authn"] = "kubernetes-sa"
	}

	// Call TTS for token exchange
	txToken, err := s.ttsClient.Exchange(ctx, &sdktts.ExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: subjectTokenType,
		Scope:            rule.Scope,
		RequestDetails:   requestDetails,
		RequestContext:   requestContext,
	})
	if err != nil {
		return denied(codes.Internal, fmt.Sprintf("token exchange failed: %v", err)), nil
	}

	// Return OK with Txn-Token header injected
	return allowedWithHeaders(map[string]string{
		token.HeaderName: txToken,
	}), nil
}

// findMatchingRule finds the generation rule that matches the request path and method.
func (s *GenerationServer) findMatchingRule(path, method string) *controller.GenerationRule {
	// Strip query string from path
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}

	for i := range s.generationRules {
		rule := &s.generationRules[i]
		if strings.EqualFold(rule.Endpoint.Method, method) && matchEndpointPath(path, rule.Endpoint.Path) {
			return rule
		}
	}
	return nil
}

// matchEndpointPath matches a request path against a pattern that may contain
// path parameters like {datasetId}.
func matchEndpointPath(requestPath, pattern string) bool {
	// Strip query string
	if idx := strings.Index(requestPath, "?"); idx >= 0 {
		requestPath = requestPath[:idx]
	}

	// Simple implementation: split both paths by "/" and match segments.
	// Segments starting with "{" are wildcards.
	reqParts := strings.Split(strings.Trim(requestPath, "/"), "/")
	patParts := strings.Split(strings.Trim(pattern, "/"), "/")

	if len(reqParts) != len(patParts) {
		return false
	}

	for i := range patParts {
		if strings.HasPrefix(patParts[i], "{") && strings.HasSuffix(patParts[i], "}") {
			continue // wildcard segment
		}
		if reqParts[i] != patParts[i] {
			return false
		}
	}

	return true
}

// extractSourceAddress extracts the source IP from the CheckRequest.
func extractSourceAddress(req *authv3.CheckRequest) string {
	if src := req.GetAttributes().GetSource(); src != nil {
		if addr := src.GetAddress(); addr != nil {
			if sa := addr.GetSocketAddress(); sa != nil {
				return sa.GetAddress()
			}
		}
	}
	return ""
}

// allowedWithHeaders creates an OK response that injects headers into the upstream request.
func allowedWithHeaders(headers map[string]string) *authv3.CheckResponse {
	headerList := make([]*corev3.HeaderValueOption, 0, len(headers))
	for k, v := range headers {
		headerList = append(headerList, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   k,
				Value: v,
			},
		})
	}

	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headerList,
			},
		},
	}
}
