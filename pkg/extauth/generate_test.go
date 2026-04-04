package extauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/api/v1alpha1"
	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	pkgtts "github.com/aramase/kontxt/pkg/tts"
	sdktts "github.com/aramase/kontxt/sdk/tts"
)

// setupGenerationTest creates a full test stack: IdP, TTS, and generation server.
func setupGenerationTest(t *testing.T) (*GenerationServer, *keys.Manager, string) {
	t.Helper()

	// Create IdP
	idpKeyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	var idpServerURL string
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpServerURL, idpServerURL+"/.well-known/jwks.json")
	})
	idpMux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(idpMux)
	idpServerURL = idpServer.URL
	t.Cleanup(idpServer.Close)

	// Create TTS
	ttsCfg := &pkgtts.Config{
		TrustDomain: "trust-domain.example.com",
		Issuer:      "https://tts.example.com",
		SubjectTokens: []authn.AuthenticatorConfig{
			{
				Issuer: authn.IssuerConfig{
					URL:       idpServer.URL,
					Audiences: []string{"test-app"},
				},
				ClaimMappings: authn.ClaimMappings{
					Subject: authn.ClaimOrExpression{Claim: "email"},
				},
			},
		},
		Defaults: pkgtts.TokenDefaults{
			TokenLifetime: "15s",
			KeySize:       2048,
		},
	}
	ttsServer, err := pkgtts.NewServer(ttsCfg)
	require.NoError(t, err)
	ttsHTTP := httptest.NewServer(ttsServer.Handler())
	t.Cleanup(ttsHTTP.Close)

	// Create generation server
	ttsClient := sdktts.NewClient(ttsHTTP.URL)
	resolver := NewIdentityResolver()
	genServer := NewGenerationServer(ttsClient, resolver)

	return genServer, idpKeyMgr, idpServer.URL
}

func genCheckRequest(path, method string, headers map[string]string, sourceIP, principal string) *authv3.CheckRequest {
	source := &authv3.AttributeContext_Peer{}
	if sourceIP != "" {
		source.Address = &corev3.Address{
			Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{
					Address: sourceIP,
				},
			},
		}
	}
	if principal != "" {
		source.Principal = principal
	}

	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path:    path,
					Method:  method,
					Headers: headers,
				},
			},
			Source: source,
		},
	}
}

func createOAuthToken(t *testing.T, keyMgr *keys.Manager, issuer string) string {
	t.Helper()
	signingKey, kid := keyMgr.SigningKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuer,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})
	tok.Header["kid"] = kid
	tokenString, err := tok.SignedString(signingKey)
	require.NoError(t, err)
	return tokenString
}

func TestGenerationServer_WithOAuthAT(t *testing.T) {
	genServer, idpKeyMgr, idpURL := setupGenerationTest(t)

	genServer.SetGenerationRules([]controller.GenerationRule{
		{
			Namespace: "team-alpha",
			Name:      "analyze",
			Endpoint:  v1alpha1.EndpointSpec{Path: "/api/v1/analyze", Method: "POST"},
			Purpose:   "analysis",
			Scope:     "read:data",
		},
	})

	oauthToken := createOAuthToken(t, idpKeyMgr, idpURL)

	resp, err := genServer.Check(context.Background(), genCheckRequest(
		"/api/v1/analyze", "POST",
		map[string]string{"authorization": "Bearer " + oauthToken},
		"10.0.0.42", "",
	))
	require.NoError(t, err)

	// Should return OK with Txn-Token header injected
	okResp := resp.GetOkResponse()
	require.NotNil(t, okResp, "expected OkResponse")

	// Find the Txn-Token header
	var txTokenValue string
	for _, h := range okResp.GetHeaders() {
		if h.GetHeader().GetKey() == token.HeaderName {
			txTokenValue = h.GetHeader().GetValue()
			break
		}
	}
	require.NotEmpty(t, txTokenValue, "Txn-Token header should be injected")

	// Verify it's a valid TxToken JWT
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(txTokenValue, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "user@example.com", claims["sub"])
	assert.Equal(t, "read:data", claims["scope"])
	assert.Equal(t, token.TypeHeader, parsed.Header["typ"])
}

func TestGenerationServer_NoMatchingRule(t *testing.T) {
	genServer, idpKeyMgr, idpURL := setupGenerationTest(t)

	genServer.SetGenerationRules([]controller.GenerationRule{
		{
			Endpoint: v1alpha1.EndpointSpec{Path: "/api/v1/analyze", Method: "POST"},
			Purpose:  "analysis",
			Scope:    "read:data",
		},
	})

	oauthToken := createOAuthToken(t, idpKeyMgr, idpURL)

	// Request to a different path — no matching rule
	resp, err := genServer.Check(context.Background(), genCheckRequest(
		"/api/v1/other", "GET",
		map[string]string{"authorization": "Bearer " + oauthToken},
		"10.0.0.42", "",
	))
	require.NoError(t, err)

	// Should pass through without generating a TxToken
	assert.NotNil(t, resp.GetOkResponse())
	assert.Empty(t, resp.GetOkResponse().GetHeaders(), "no headers should be injected")
}

func TestGenerationServer_PathParameterMatching(t *testing.T) {
	genServer, idpKeyMgr, idpURL := setupGenerationTest(t)

	genServer.SetGenerationRules([]controller.GenerationRule{
		{
			Endpoint: v1alpha1.EndpointSpec{Path: "/api/v1/datasets/{datasetId}/analyze", Method: "POST"},
			Purpose:  "analysis",
			Scope:    "read:data",
		},
	})

	oauthToken := createOAuthToken(t, idpKeyMgr, idpURL)

	resp, err := genServer.Check(context.Background(), genCheckRequest(
		"/api/v1/datasets/ds-1234/analyze", "POST",
		map[string]string{"authorization": "Bearer " + oauthToken},
		"10.0.0.42", "",
	))
	require.NoError(t, err)

	// Should match the pattern and generate a TxToken
	okResp := resp.GetOkResponse()
	require.NotNil(t, okResp)
	assert.NotEmpty(t, okResp.GetHeaders(), "Txn-Token header should be injected")
}

func TestGenerationServer_InvalidOAuthToken(t *testing.T) {
	genServer, _, _ := setupGenerationTest(t)

	genServer.SetGenerationRules([]controller.GenerationRule{
		{
			Endpoint: v1alpha1.EndpointSpec{Path: "/api/v1/analyze", Method: "POST"},
			Purpose:  "analysis",
			Scope:    "read:data",
		},
	})

	resp, err := genServer.Check(context.Background(), genCheckRequest(
		"/api/v1/analyze", "POST",
		map[string]string{"authorization": "Bearer invalid-token"},
		"10.0.0.42", "",
	))
	require.NoError(t, err)

	// Should fail — invalid token
	assert.NotNil(t, resp.GetDeniedResponse())
}

func TestGenerationServer_RctxIncluded(t *testing.T) {
	genServer, idpKeyMgr, idpURL := setupGenerationTest(t)

	genServer.SetGenerationRules([]controller.GenerationRule{
		{
			Endpoint: v1alpha1.EndpointSpec{Path: "/api/v1/analyze", Method: "POST"},
			Purpose:  "analysis",
			Scope:    "read:data",
		},
	})

	oauthToken := createOAuthToken(t, idpKeyMgr, idpURL)

	resp, err := genServer.Check(context.Background(), genCheckRequest(
		"/api/v1/analyze", "POST",
		map[string]string{"authorization": "Bearer " + oauthToken},
		"10.0.0.42", "",
	))
	require.NoError(t, err)

	okResp := resp.GetOkResponse()
	require.NotNil(t, okResp)

	var txTokenValue string
	for _, h := range okResp.GetHeaders() {
		if h.GetHeader().GetKey() == token.HeaderName {
			txTokenValue = h.GetHeader().GetValue()
		}
	}
	require.NotEmpty(t, txTokenValue)

	// Parse and check rctx
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(txTokenValue, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)

	rctx, _ := claims["rctx"].(map[string]any)
	assert.Equal(t, "10.0.0.42", rctx["req_ip"])
	assert.Equal(t, "oidc", rctx["authn"])

	tctx, _ := claims["tctx"].(map[string]any)
	assert.Equal(t, "analysis", tctx["purpose"])
}

func TestMatchEndpointPath(t *testing.T) {
	assert.True(t, matchEndpointPath("/api/v1/analyze", "/api/v1/analyze"))
	assert.True(t, matchEndpointPath("/api/v1/datasets/ds-1/analyze", "/api/v1/datasets/{datasetId}/analyze"))
	assert.False(t, matchEndpointPath("/api/v1/other", "/api/v1/analyze"))
	assert.False(t, matchEndpointPath("/api/v1/datasets/ds-1/analyze/extra", "/api/v1/datasets/{datasetId}/analyze"))
	assert.True(t, matchEndpointPath("/api/v1/analyze?query=1", "/api/v1/analyze"))
}

func TestAllowedWithHeaders(t *testing.T) {
	resp := allowedWithHeaders(map[string]string{
		"Txn-Token": "test-token-value",
	})

	okResp := resp.GetOkResponse()
	require.NotNil(t, okResp)
	require.Len(t, okResp.GetHeaders(), 1)
	assert.Equal(t, "Txn-Token", okResp.GetHeaders()[0].GetHeader().GetKey())
	assert.Equal(t, "test-token-value", okResp.GetHeaders()[0].GetHeader().GetValue())
}

// Ensure the response is valid JSON in denied body
func TestGenerationServer_DeniedResponseIsJSON(t *testing.T) {
	genServer, _, _ := setupGenerationTest(t)

	genServer.SetGenerationRules([]controller.GenerationRule{
		{
			Endpoint: v1alpha1.EndpointSpec{Path: "/api/v1/analyze", Method: "POST"},
			Purpose:  "analysis",
			Scope:    "read:data",
		},
	})

	resp, err := genServer.Check(context.Background(), genCheckRequest(
		"/api/v1/analyze", "POST",
		map[string]string{"authorization": "Bearer bad-token"},
		"10.0.0.42", "",
	))
	require.NoError(t, err)

	body := resp.GetDeniedResponse().GetBody()
	assert.True(t, json.Valid([]byte(body)), "denied response body should be valid JSON")
}
