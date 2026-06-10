package tts

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	"github.com/aramase/kontxt/sdk/verify"
)

// testSetup creates a test OIDC server, key manager, and TTS handler.
func testSetup(t *testing.T) (*httptest.Server, *keys.Manager, *Handler) {
	t.Helper()

	// Create IdP key manager and OIDC server
	idpKeyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	var idpServerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpServerURL, idpServerURL+"/.well-known/jwks.json")
	})
	mux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(mux)
	idpServerURL = idpServer.URL
	t.Cleanup(idpServer.Close)

	// Create TTS key manager
	ttsKeyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	// Create authenticator
	auth, err := authn.NewOIDCAuthenticator(authn.AuthenticatorConfig{
		Issuer: authn.IssuerConfig{
			URL:       idpServer.URL,
			Audiences: []string{"test-app"},
		},
		ClaimMappings: authn.ClaimMappings{
			Subject: authn.ClaimOrExpression{Claim: "email"},
		},
	})
	require.NoError(t, err)
	auth.SetJWKSURL(idpServer.URL + "/.well-known/jwks.json")

	router := authn.NewRouter([]authn.Authenticator{auth})
	handler := NewHandler(router, ttsKeyMgr, "https://tts.example.com", "trust-domain.example.com", 15*time.Second)

	return idpServer, idpKeyMgr, handler
}

// createSubjectToken creates a valid OIDC token for testing.
func createSubjectToken(t *testing.T, keyMgr *keys.Manager, issuer string, claims jwt.MapClaims) string {
	t.Helper()
	signingKey, kid := keyMgr.SigningKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tokenString, err := tok.SignedString(signingKey)
	require.NoError(t, err)
	return tokenString
}

// doTokenExchange sends a token exchange request and returns the response.
func doTokenExchange(handler http.Handler, params url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token_endpoint", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestHandler_ValidTokenExchange(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp TokenExchangeResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, token.RequestedTokenType, resp.IssuedTokenType)
	assert.Equal(t, "N_A", resp.TokenType)

	// Verify the TxToken is a valid JWT
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "https://tts.example.com", claims["iss"])
	assert.Equal(t, "trust-domain.example.com", claims["aud"])
	assert.Equal(t, "user@example.com", claims["sub"])
	assert.Equal(t, "read:data", claims["scope"])
	assert.NotEmpty(t, claims["txn"])
	assert.Equal(t, token.TypeHeader, parsed.Header["typ"])
}

func TestHandler_InvalidSubjectToken(t *testing.T) {
	_, _, handler := testSetup(t)

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {"invalid-token"},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var errResp ErrorResponse
	json.NewDecoder(rec.Body).Decode(&errResp)
	assert.Equal(t, "invalid_token", errResp.Error)
}

func TestHandler_MissingGrantType(t *testing.T) {
	_, _, handler := testSetup(t)

	params := url.Values{
		"subject_token":        {"some-token"},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_WrongGrantType(t *testing.T) {
	_, _, handler := testSetup(t)

	params := url.Values{
		"grant_type":           {"authorization_code"},
		"subject_token":        {"some-token"},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_MissingSubjectToken(t *testing.T) {
	_, _, handler := testSetup(t)

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_WrongRequestedTokenType(t *testing.T) {
	_, _, handler := testSetup(t)

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {"some-token"},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_MissingScope(t *testing.T) {
	_, _, handler := testSetup(t)

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {"some-token"},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_RequestDetails_BecomeTctx(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
		"request_details":      {`{"action":"analyze","datasetId":"ds-1234"}`},
	}

	rec := doTokenExchange(handler, params)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp TokenExchangeResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	tctx, ok := claims["tctx"].(map[string]any)
	require.True(t, ok, "tctx must be present")
	assert.Equal(t, "analyze", tctx["action"])
	assert.Equal(t, "ds-1234", tctx["datasetId"])
}

func TestHandler_RequestContext_BecomesRctx(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
		"request_context":      {`{"req_ip":"10.0.0.42","authn":"oidc"}`},
	}

	rec := doTokenExchange(handler, params)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp TokenExchangeResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(resp.AccessToken, jwt.MapClaims{})
	require.NoError(t, err)

	claims := parsed.Claims.(jwt.MapClaims)
	rctx, ok := claims["rctx"].(map[string]any)
	require.True(t, ok, "rctx must be present")
	assert.Equal(t, "10.0.0.42", rctx["req_ip"])
	assert.Equal(t, "oidc", rctx["authn"])
}

func TestHandler_InvalidRequestDetailsJSON(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
		"request_details":      {`not valid json`},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	_, _, handler := testSetup(t)

	req := httptest.NewRequest(http.MethodGet, "/token_endpoint", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestHandler_ResponseFormat(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)
	require.Equal(t, http.StatusOK, rec.Code)

	// Check response headers
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	// Check response body is valid JSON
	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	assert.True(t, json.Valid(body))
}

func TestServer_HealthEndpoint(t *testing.T) {
	idpKeyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	var idpServerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpServerURL, idpServerURL+"/.well-known/jwks.json")
	})
	mux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(mux)
	idpServerURL = idpServer.URL
	t.Cleanup(idpServer.Close)

	cfg := &Config{
		TrustDomain: "test.example.com",
		Issuer:      "https://tts.test.example.com",
		SubjectTokens: []authn.AuthenticatorConfig{
			{
				Issuer: authn.IssuerConfig{
					URL:       idpServer.URL,
					Audiences: []string{"test-app"},
				},
				ClaimMappings: authn.ClaimMappings{
					Subject: authn.ClaimOrExpression{Claim: "sub"},
				},
			},
		},
		Defaults: TokenDefaults{
			TokenLifetime: "15s",
			KeySize:       2048,
		},
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServer_JWKSEndpoint(t *testing.T) {
	idpKeyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	var idpServerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpServerURL, idpServerURL+"/.well-known/jwks.json")
	})
	mux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(mux)
	idpServerURL = idpServer.URL
	t.Cleanup(idpServer.Close)

	cfg := &Config{
		TrustDomain: "test.example.com",
		Issuer:      "https://tts.test.example.com",
		SubjectTokens: []authn.AuthenticatorConfig{
			{
				Issuer: authn.IssuerConfig{
					URL:       idpServer.URL,
					Audiences: []string{"test-app"},
				},
				ClaimMappings: authn.ClaimMappings{
					Subject: authn.ClaimOrExpression{Claim: "sub"},
				},
			},
		},
		Defaults: TokenDefaults{
			TokenLifetime: "15s",
			KeySize:       2048,
		},
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var jwks keys.JWKSet
	err = json.NewDecoder(rec.Body).Decode(&jwks)
	require.NoError(t, err)
	assert.Len(t, jwks.Keys, 1)
}

func TestHandler_IssuanceRuleDenies(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	// Set an issuance rule that blocks scope "admin:all"
	rules, err := CompileIssuanceRules([]IssuanceRuleConfig{
		{Name: "no-admin", CEL: `scope != "admin:all"`, Message: "admin scope not allowed"},
	})
	require.NoError(t, err)
	handler.SetIssuanceRules(rules)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"admin:all"},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	var errResp ErrorResponse
	json.NewDecoder(rec.Body).Decode(&errResp)
	assert.Equal(t, "policy_denied", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "admin scope not allowed")
}

func TestHandler_IssuanceRuleAllows(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	rules, err := CompileIssuanceRules([]IssuanceRuleConfig{
		{Name: "require-read", CEL: `scope == "read:data"`, Message: "only read allowed"},
	})
	require.NoError(t, err)
	handler.SetIssuanceRules(rules)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}

	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_IssuanceRuleWithTctx(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	rules, err := CompileIssuanceRules([]IssuanceRuleConfig{
		{Name: "public-only", CEL: `tctx.classification == "public"`, Message: "only public data"},
	})
	require.NoError(t, err)
	handler.SetIssuanceRules(rules)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	// Should pass: classification is public
	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
		"request_details":      {`{"classification":"public"}`},
	}
	rec := doTokenExchange(handler, params)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Should fail: classification is pii
	params.Set("request_details", `{"classification":"pii"}`)
	rec = doTokenExchange(handler, params)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandler_TokenReplacement_NarrowScope(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	// Set up a verifier so the handler can verify existing TxTokens
	ttsKeyMgr := handler.keyManager
	jwksServer := httptest.NewServer(ttsKeyMgr.JWKSHandler())
	defer jwksServer.Close()

	verifier := verify.New(jwksServer.URL, "trust-domain.example.com")
	handler.SetVerifier(verifier)

	// First: get a TxToken with broad scope
	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data write:reports execute:analysis"},
	}
	rec := doTokenExchange(handler, params)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp TokenExchangeResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	originalTxToken := resp.AccessToken

	// Parse to get the original txn
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, _ := parser.ParseUnverified(originalTxToken, jwt.MapClaims{})
	originalTxn := parsed.Claims.(jwt.MapClaims)["txn"].(string)

	// Now: replace with narrower scope
	narrowParams := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {originalTxToken},
		"subject_token_type":   {token.SubjectTokenTypeTxnToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}
	rec2 := doTokenExchange(handler, narrowParams)
	require.Equal(t, http.StatusOK, rec2.Code)

	var resp2 TokenExchangeResponse
	json.NewDecoder(rec2.Body).Decode(&resp2)

	// Verify the replacement token
	parsed2, _, _ := parser.ParseUnverified(resp2.AccessToken, jwt.MapClaims{})
	claims2 := parsed2.Claims.(jwt.MapClaims)

	assert.Equal(t, originalTxn, claims2["txn"], "txn must be preserved")
	assert.Equal(t, "user@example.com", claims2["sub"], "sub must be preserved")
	assert.Equal(t, "read:data", claims2["scope"], "scope must be narrowed")
}

func TestHandler_TokenReplacement_ScopeExpansionDenied(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	ttsKeyMgr := handler.keyManager
	jwksServer := httptest.NewServer(ttsKeyMgr.JWKSHandler())
	defer jwksServer.Close()
	handler.SetVerifier(verify.New(jwksServer.URL, "trust-domain.example.com"))

	// Get a TxToken with narrow scope
	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}
	rec := doTokenExchange(handler, params)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp TokenExchangeResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// Try to replace with BROADER scope → should be denied
	expandParams := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {resp.AccessToken},
		"subject_token_type":   {token.SubjectTokenTypeTxnToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data write:reports admin:all"},
	}
	rec2 := doTokenExchange(handler, expandParams)
	assert.Equal(t, http.StatusForbidden, rec2.Code)

	var errResp ErrorResponse
	json.NewDecoder(rec2.Body).Decode(&errResp)
	assert.Equal(t, "invalid_scope", errResp.Error)
}

func TestHandler_TokenReplacement_PreservesTctxRctx(t *testing.T) {
	idpServer, idpKeyMgr, handler := testSetup(t)

	ttsKeyMgr := handler.keyManager
	jwksServer := httptest.NewServer(ttsKeyMgr.JWKSHandler())
	defer jwksServer.Close()
	handler.SetVerifier(verify.New(jwksServer.URL, "trust-domain.example.com"))

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	// Create original token with tctx and rctx
	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data write:reports"},
		"request_details":      {`{"action":"analyze","datasetId":"ds-1"}`},
		"request_context":      {`{"req_ip":"10.0.0.1","authn":"oidc"}`},
	}
	rec := doTokenExchange(handler, params)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp TokenExchangeResponse
	json.NewDecoder(rec.Body).Decode(&resp)

	// Replace with narrower scope
	narrowParams := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {resp.AccessToken},
		"subject_token_type":   {token.SubjectTokenTypeTxnToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	}
	rec2 := doTokenExchange(handler, narrowParams)
	require.Equal(t, http.StatusOK, rec2.Code)

	var resp2 TokenExchangeResponse
	json.NewDecoder(rec2.Body).Decode(&resp2)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, _ := parser.ParseUnverified(resp2.AccessToken, jwt.MapClaims{})
	claims := parsed.Claims.(jwt.MapClaims)

	// tctx and rctx must be preserved from the original
	tctx := claims["tctx"].(map[string]any)
	assert.Equal(t, "analyze", tctx["action"])
	assert.Equal(t, "ds-1", tctx["datasetId"])

	rctx := claims["rctx"].(map[string]any)
	assert.Equal(t, "10.0.0.1", rctx["req_ip"])
	assert.Equal(t, "oidc", rctx["authn"])
}

// TestSetIssuanceRules_ConcurrentSwap exercises SetIssuanceRules under the
// race detector to guard against races between the rule-streaming goroutine
// (controller pushes) and request goroutines reading the rule set during
// token exchanges. Run via `go test -race ./pkg/tts/...`.
func TestSetIssuanceRules_ConcurrentSwap(t *testing.T) {
	h := &Handler{}

	rulesA, err := CompileIssuanceRules([]IssuanceRuleConfig{
		{Name: "a", CEL: "true", Message: "ok"},
	})
	require.NoError(t, err)
	rulesB, err := CompileIssuanceRules([]IssuanceRuleConfig{
		{Name: "b", CEL: "false", Message: "denied"},
	})
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			if i%2 == 0 {
				h.SetIssuanceRules(rulesA)
			} else {
				h.SetIssuanceRules(rulesB)
			}
		}
		close(done)
	}()

	ictx := &IssuanceContext{Subject: "user", WorkloadNS: "ns"}
	for i := 0; i < 1000; i++ {
		if rules := h.loadIssuanceRules(); len(rules) > 0 {
			_ = EvaluateIssuanceRules(rules, ictx)
		}
	}
	<-done
}

// TestSetIssuanceRules_SnapshotIsolated verifies that mutating the slice a
// caller passed to SetIssuanceRules does not affect the handler's stored set.
// This is part of the immutability contract that lets ServeHTTP read the
// slice without locks.
func TestSetIssuanceRules_SnapshotIsolated(t *testing.T) {
	h := &Handler{}

	rules, err := CompileIssuanceRules([]IssuanceRuleConfig{
		{Name: "first", CEL: "true", Message: "ok"},
	})
	require.NoError(t, err)
	h.SetIssuanceRules(rules)

	// Mutate the caller's slice header (zero it out). The handler's stored
	// snapshot must remain unchanged.
	rules = nil
	loaded := h.loadIssuanceRules()
	require.Len(t, loaded, 1)
	assert.Equal(t, "first", loaded[0].Name)
}

// TestSetIssuanceRules_TargetNamespacesDeepCopied verifies that the
// TargetNamespaces slice inside each IssuanceRule is deep-copied on handoff.
// Without the deep copy, a caller mutating the slice it passed in could race
// with ServeHTTP reading the snapshot (data race on the underlying array).
func TestSetIssuanceRules_TargetNamespacesDeepCopied(t *testing.T) {
	h := &Handler{}

	targets := []string{"team-alpha", "team-beta"}
	rules := []IssuanceRule{{
		Name:             "scoped",
		TargetNamespaces: targets,
	}}
	h.SetIssuanceRules(rules)

	// Mutate the caller-owned slice in place after handoff. The handler's
	// stored snapshot must not observe the mutation.
	targets[0] = "MUTATED"
	rules[0].TargetNamespaces[1] = "ALSO-MUTATED"

	loaded := h.loadIssuanceRules()
	require.Len(t, loaded, 1)
	assert.Equal(t, []string{"team-alpha", "team-beta"}, loaded[0].TargetNamespaces)
}
