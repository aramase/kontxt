package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	"github.com/aramase/kontxt/sdk/verify"
)

func testMiddlewareSetup(t *testing.T) (*keys.Manager, *verify.Verifier) {
	t.Helper()

	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	jwksServer := httptest.NewServer(keyMgr.JWKSHandler())
	t.Cleanup(jwksServer.Close)

	verifier := verify.New(jwksServer.URL, "trust-domain.example.com")
	return keyMgr, verifier
}

func createTxToken(t *testing.T, keyMgr *keys.Manager) string {
	t.Helper()
	signingKey, kid := keyMgr.SigningKey()
	tokenString, err := token.New(token.Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
		TransactionContext: map[string]any{"action": "test"},
	}, signingKey, kid, 15*time.Second)
	require.NoError(t, err)
	return tokenString
}

func TestVerifyMiddleware_ValidToken(t *testing.T) {
	keyMgr, verifier := testMiddlewareSetup(t)
	txToken := createTxToken(t, keyMgr)

	var capturedClaims *token.Claims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := VerifyTxToken(verifier)(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set(token.HeaderName, txToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedClaims)
	assert.Equal(t, "user@example.com", capturedClaims.Subject)
	assert.Equal(t, "read:data", capturedClaims.Scope)
	assert.Equal(t, "test", capturedClaims.TransactionContext["action"])
}

func TestVerifyMiddleware_MissingToken(t *testing.T) {
	_, verifier := testMiddlewareSetup(t)

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
	})

	handler := VerifyTxToken(verifier)(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	// No Txn-Token header
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, innerCalled, "inner handler should not be called")
}

func TestVerifyMiddleware_InvalidToken(t *testing.T) {
	_, verifier := testMiddlewareSetup(t)

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
	})

	handler := VerifyTxToken(verifier)(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set(token.HeaderName, "invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, innerCalled, "inner handler should not be called")
}

func TestVerifyMiddleware_ExpiredToken(t *testing.T) {
	keyMgr, verifier := testMiddlewareSetup(t)

	// Create token with very short lifetime
	signingKey, kid := keyMgr.SigningKey()
	txToken, err := token.New(token.Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}, signingKey, kid, 1*time.Millisecond)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
	})

	handler := VerifyTxToken(verifier)(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set(token.HeaderName, txToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.False(t, innerCalled, "inner handler should not be called for expired token")
}

func TestVerifyMiddleware_ClaimsInContext(t *testing.T) {
	keyMgr, verifier := testMiddlewareSetup(t)
	txToken := createTxToken(t, keyMgr)

	var ctx context.Context
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		w.WriteHeader(http.StatusOK)
	})

	handler := VerifyTxToken(verifier)(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set(token.HeaderName, txToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Claims should be available via ClaimsFromContext
	claims := ClaimsFromContext(ctx)
	require.NotNil(t, claims)
	assert.Equal(t, "user@example.com", claims.Subject)

	// Token string should also be available
	tokenStr := TokenFromContext(ctx)
	assert.Equal(t, txToken, tokenStr)
}

func TestVerifyMiddleware_ErrorResponseFormat(t *testing.T) {
	_, verifier := testMiddlewareSetup(t)

	handler := VerifyTxToken(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "error")
}
