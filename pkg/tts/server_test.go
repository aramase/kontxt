package tts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
)

// TestServer_TokenReplacement_EndToEnd guards against the regression where
// NewServer constructs a Handler without calling SetVerifier, causing every
// token-replacement request to fail with 500 "token replacement not
// configured (no verifier)" in the deployed binary. The handler-level tests
// passed because they call handler.SetVerifier directly; this test goes
// through NewServer and the real HTTP listener.
func TestServer_TokenReplacement_EndToEnd(t *testing.T) {
	// Pre-bind a listener so cfg.Issuer (stamped as `iss` in issued tokens)
	// matches the URL the test will hit. The in-process verifier does not
	// need cfg.Issuer to be reachable.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ttsURL := "http://" + lis.Addr().String()

	// Stand up an IdP that signs the subject token.
	idpKeyMgr, err := keys.NewManager(2048, time.Hour)
	require.NoError(t, err)

	var idpURL string
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpURL, idpURL+"/.well-known/jwks.json")
	})
	idpMux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()
	idpURL = idpServer.URL

	cfg := &Config{
		TrustDomain: "trust-domain.example.com",
		Issuer:      ttsURL,
		SubjectTokens: []authn.AuthenticatorConfig{{
			Issuer: authn.IssuerConfig{
				URL:       idpServer.URL,
				Audiences: []string{"test-app"},
			},
			ClaimMappings: authn.ClaimMappings{
				Subject: authn.ClaimOrExpression{Claim: "email"},
			},
		}},
	}
	srv, err := NewServer(cfg)
	require.NoError(t, err)

	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: time.Second}
	serveBackground(t, hs, lis)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	broadToken := postExchange(t, ttsURL, url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data write:reports"},
		"request_details":      {`{"action":"analyze","datasetId":"ds-1"}`},
	})

	narrowed := postExchange(t, ttsURL, url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {broadToken},
		"subject_token_type":   {token.SubjectTokenTypeTxnToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	})

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsedBroad, _, err := parser.ParseUnverified(broadToken, jwt.MapClaims{})
	require.NoError(t, err)
	parsedNarrow, _, err := parser.ParseUnverified(narrowed, jwt.MapClaims{})
	require.NoError(t, err)
	broadClaims := parsedBroad.Claims.(jwt.MapClaims)
	narrowClaims := parsedNarrow.Claims.(jwt.MapClaims)

	assert.Equal(t, broadClaims["txn"], narrowClaims["txn"], "txn must be preserved across replacement")
	assert.Equal(t, broadClaims["sub"], narrowClaims["sub"], "sub must be preserved across replacement")
	assert.Equal(t, "read:data", narrowClaims["scope"], "scope must be narrowed")
	assert.Equal(t, broadClaims["tctx"], narrowClaims["tctx"], "tctx must be preserved across replacement")
}

// TestServer_TokenReplacement_ScopeExpansionDenied confirms scope-expansion
// rejection works end-to-end through NewServer (not just the handler).
func TestServer_TokenReplacement_ScopeExpansionDenied(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ttsURL := "http://" + lis.Addr().String()

	idpKeyMgr, err := keys.NewManager(2048, time.Hour)
	require.NoError(t, err)

	var idpURL string
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpURL, idpURL+"/.well-known/jwks.json")
	})
	idpMux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()
	idpURL = idpServer.URL

	cfg := &Config{
		TrustDomain: "trust-domain.example.com",
		Issuer:      ttsURL,
		SubjectTokens: []authn.AuthenticatorConfig{{
			Issuer: authn.IssuerConfig{
				URL:       idpServer.URL,
				Audiences: []string{"test-app"},
			},
			ClaimMappings: authn.ClaimMappings{
				Subject: authn.ClaimOrExpression{Claim: "email"},
			},
		}},
	}
	srv, err := NewServer(cfg)
	require.NoError(t, err)

	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: time.Second}
	serveBackground(t, hs, lis)

	subjectToken := createSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	narrow := postExchange(t, ttsURL, url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	})

	expandReq, err := http.NewRequest(http.MethodPost, ttsURL+"/token_endpoint",
		strings.NewReader(url.Values{
			"grant_type":           {token.GrantType},
			"subject_token":        {narrow},
			"subject_token_type":   {token.SubjectTokenTypeTxnToken},
			"requested_token_type": {token.RequestedTokenType},
			"scope":                {"read:data write:reports admin:all"},
		}.Encode()))
	require.NoError(t, err)
	expandReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpTestClient.Do(expandReq)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	assert.Equalf(t, http.StatusForbidden, resp.StatusCode, "expansion must be rejected; got: %s", string(body))
	var er ErrorResponse
	require.NoError(t, json.Unmarshal(body, &er))
	assert.Equal(t, "invalid_scope", er.Error)
}

// serveBackground runs hs.Serve(lis) in a goroutine and registers a cleanup
// that shuts down the server and asserts the Serve error is the expected
// http.ErrServerClosed. Without capturing the error, an early Serve failure
// (e.g. accept error) would be silently swallowed and the test would fail
// later with a less helpful message.
func serveBackground(t *testing.T, hs *http.Server, lis net.Listener) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() { errCh <- hs.Serve(lis) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		assert.ErrorIs(t, <-errCh, http.ErrServerClosed)
	})
}

// httpTestClient returns an HTTP client with a short timeout suitable for
// in-process server tests. Avoids indefinite hangs if a test server fails to
// start or bind.
var httpTestClient = &http.Client{Timeout: 5 * time.Second}

// postExchange POSTs an RFC 8693 token-exchange request and returns the
// issued token. Fails the test if the response is not 200.
func postExchange(t *testing.T, ttsURL string, params url.Values) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ttsURL+"/token_endpoint",
		strings.NewReader(params.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpTestClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "exchange failed: %s", string(body))

	var er TokenExchangeResponse
	require.NoError(t, json.Unmarshal(body, &er))
	require.NotEmpty(t, er.AccessToken)
	return er.AccessToken
}
