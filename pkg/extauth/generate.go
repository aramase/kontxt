package extauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/aramase/kontxt/api/v1alpha1"
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
		// Internal traffic: resolve identity from the SPIFFE principal on the
		// ext_authz peer (e.g. set by Istio ambient ztunnel mTLS). No pod-IP
		// fallback: missing principal fails closed.
		principal := req.GetAttributes().GetSource().GetPrincipal()

		identity, err := s.identityResolver.Resolve(principal)
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
	// Extract tctx fields from the request based on tctxMapping.
	for fieldName, mapping := range rule.TctxMapping {
		val, err := extractTctxField(httpReq, mapping)
		if err != nil {
			if mapping.Required {
				return denied(codes.InvalidArgument,
					fmt.Sprintf("required tctx field %q extraction failed: %v", fieldName, err)), nil
			}
			continue
		}
		if val != "" {
			requestDetails[fieldName] = val
		} else if mapping.Required {
			return denied(codes.InvalidArgument,
				fmt.Sprintf("required tctx field %q is missing", fieldName)), nil
		}
	}

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

// extractTctxField extracts a single tctx field value from the ext_authz HTTP request
// based on the mapping source (body, query, header, path).
func extractTctxField(httpReq *authv3.AttributeContext_HttpRequest, mapping v1alpha1.TctxFieldMapping) (string, error) {
	switch mapping.Source {
	case "body":
		body := httpReq.GetBody()
		if body == "" {
			return "", nil
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(body), &parsed); err != nil {
			return "", fmt.Errorf("failed to parse request body as JSON: %w", err)
		}
		val, ok := parsed[mapping.Field]
		if !ok {
			return "", nil
		}
		switch v := val.(type) {
		case string:
			return v, nil
		default:
			b, _ := json.Marshal(v)
			return string(b), nil
		}
	case "query":
		rawPath := httpReq.GetPath()
		if idx := strings.Index(rawPath, "?"); idx >= 0 {
			query, err := url.ParseQuery(rawPath[idx+1:])
			if err != nil {
				return "", fmt.Errorf("failed to parse query string: %w", err)
			}
			return query.Get(mapping.Field), nil
		}
		return "", nil
	case "header":
		return getHeader(httpReq.GetHeaders(), strings.ToLower(mapping.Field)), nil
	case "path":
		// Not implemented yet — would need pattern matching against the rule's endpoint path
		return "", nil
	default:
		return "", fmt.Errorf("unknown tctxMapping source: %q", mapping.Source)
	}
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
