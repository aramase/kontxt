package tts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	pkgtts "github.com/aramase/kontxt/pkg/tts"
)

// setupTestTTS creates a test TTS server and returns the server URL and IdP key manager.
func setupTestTTS(t *testing.T) (ttsURL string, idpKeyMgr *keys.Manager, idpURL string) {
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
	cfg := &pkgtts.Config{
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

	ttsServer, err := pkgtts.NewServer(cfg)
	require.NoError(t, err)

	ttsHTTP := httptest.NewServer(ttsServer.Handler())
	t.Cleanup(ttsHTTP.Close)

	return ttsHTTP.URL, idpKeyMgr, idpServer.URL
}

// createIdPToken creates a valid OIDC token from the test IdP.
func createIdPToken(t *testing.T, keyMgr *keys.Manager, issuer string) string {
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

func TestClient_Exchange_Success(t *testing.T) {
	ttsURL, idpKeyMgr, idpURL := setupTestTTS(t)

	client := NewClient(ttsURL)
	subjectToken := createIdPToken(t, idpKeyMgr, idpURL)

	txToken, err := client.Exchange(context.Background(), &ExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		Scope:            "read:data",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, txToken)

	// Verify it's a valid JWT with the right claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(txToken, jwt.MapClaims{})
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "https://tts.example.com", claims["iss"])
	assert.Equal(t, "trust-domain.example.com", claims["aud"])
	assert.Equal(t, "user@example.com", claims["sub"])
	assert.Equal(t, "read:data", claims["scope"])
	assert.Equal(t, token.TypeHeader, parsed.Header["typ"])
}

func TestClient_Exchange_WithRequestDetails(t *testing.T) {
	ttsURL, idpKeyMgr, idpURL := setupTestTTS(t)

	client := NewClient(ttsURL)
	subjectToken := createIdPToken(t, idpKeyMgr, idpURL)

	txToken, err := client.Exchange(context.Background(), &ExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		Scope:            "read:data",
		RequestDetails: map[string]any{
			"action":    "analyze",
			"datasetId": "ds-1234",
		},
	})
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(txToken, jwt.MapClaims{})
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	tctx, ok := claims["tctx"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "analyze", tctx["action"])
	assert.Equal(t, "ds-1234", tctx["datasetId"])
}

func TestClient_Exchange_WithRequestContext(t *testing.T) {
	ttsURL, idpKeyMgr, idpURL := setupTestTTS(t)

	client := NewClient(ttsURL)
	subjectToken := createIdPToken(t, idpKeyMgr, idpURL)

	txToken, err := client.Exchange(context.Background(), &ExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		Scope:            "read:data",
		RequestContext: map[string]any{
			"req_ip": "10.0.0.42",
			"authn":  "oidc",
		},
	})
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(txToken, jwt.MapClaims{})
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	rctx, ok := claims["rctx"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.42", rctx["req_ip"])
	assert.Equal(t, "oidc", rctx["authn"])
}

func TestClient_Exchange_InvalidSubjectToken(t *testing.T) {
	ttsURL, _, _ := setupTestTTS(t)

	client := NewClient(ttsURL)

	_, err := client.Exchange(context.Background(), &ExchangeRequest{
		SubjectToken:     "invalid-token",
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		Scope:            "read:data",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestClient_Exchange_MissingScope(t *testing.T) {
	ttsURL, idpKeyMgr, idpURL := setupTestTTS(t)

	client := NewClient(ttsURL)
	subjectToken := createIdPToken(t, idpKeyMgr, idpURL)

	_, err := client.Exchange(context.Background(), &ExchangeRequest{
		SubjectToken:     subjectToken,
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		// Scope intentionally omitted
	})
	assert.Error(t, err)
}

func TestClient_Exchange_ServerUnreachable(t *testing.T) {
	client := NewClient("http://localhost:1") // unreachable

	_, err := client.Exchange(context.Background(), &ExchangeRequest{
		SubjectToken:     "some-token",
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		Scope:            "read:data",
	})
	assert.Error(t, err)
}

func TestClient_ConstructsCorrectRequest(t *testing.T) {
	// Create a test server that captures the request
	var capturedForm map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capturedForm = r.Form
		// Return a fake response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token":      "fake-txtoken",
			"issued_token_type": token.RequestedTokenType,
			"token_type":        "N_A",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL)

	_, err := client.Exchange(context.Background(), &ExchangeRequest{
		SubjectToken:     "my-subject-token",
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		Scope:            "read:data write:reports",
		RequestDetails:   map[string]any{"key": "value"},
		RequestContext:   map[string]any{"ip": "1.2.3.4"},
	})
	require.NoError(t, err)

	// Verify the request format
	assert.Equal(t, []string{token.GrantType}, capturedForm["grant_type"])
	assert.Equal(t, []string{"my-subject-token"}, capturedForm["subject_token"])
	assert.Equal(t, []string{token.SubjectTokenTypeAccessToken}, capturedForm["subject_token_type"])
	assert.Equal(t, []string{token.RequestedTokenType}, capturedForm["requested_token_type"])
	assert.Equal(t, []string{"read:data write:reports"}, capturedForm["scope"])
	assert.NotEmpty(t, capturedForm["request_details"])
	assert.NotEmpty(t, capturedForm["request_context"])

	// Verify request_details is valid JSON
	var details map[string]any
	err = json.Unmarshal([]byte(capturedForm["request_details"][0]), &details)
	require.NoError(t, err)
	assert.Equal(t, "value", details["key"])
}
