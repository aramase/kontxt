package verify

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
)

func testVerifierSetup(t *testing.T) (*keys.Manager, *httptest.Server, *Verifier) {
	t.Helper()

	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	jwksServer := httptest.NewServer(keyMgr.JWKSHandler())
	t.Cleanup(jwksServer.Close)

	verifier := New(jwksServer.URL, "trust-domain.example.com")

	return keyMgr, jwksServer, verifier
}

func createTestTxToken(t *testing.T, keyMgr *keys.Manager, claims token.Claims, lifetime time.Duration) string {
	t.Helper()
	signingKey, kid := keyMgr.SigningKey()
	tokenString, err := token.New(claims, signingKey, kid, lifetime)
	require.NoError(t, err)
	return tokenString
}

func validClaims() token.Claims {
	return token.Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "spiffe://cluster.local/ns/default/sa/my-agent",
	}
}

func TestVerifier_ValidToken(t *testing.T) {
	keyMgr, _, verifier := testVerifierSetup(t)

	tokenString := createTestTxToken(t, keyMgr, validClaims(), 15*time.Second)

	claims, err := verifier.Verify(context.Background(), tokenString)
	require.NoError(t, err)

	assert.Equal(t, "https://tts.example.com", claims.Issuer)
	assert.Equal(t, "trust-domain.example.com", claims.Audience)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, "read:data", claims.Scope)
	assert.Equal(t, "spiffe://cluster.local/ns/default/sa/my-agent", claims.RequestingWorkload)
	assert.NotEmpty(t, claims.TransactionID)
}

func TestVerifier_ExpiredToken(t *testing.T) {
	keyMgr, _, verifier := testVerifierSetup(t)

	// Create a token that's already expired (negative lifetime hack: create then wait)
	// Instead, create with a very short lifetime and sleep
	tokenString := createTestTxToken(t, keyMgr, validClaims(), 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	_, err := verifier.Verify(context.Background(), tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestVerifier_WrongAudience(t *testing.T) {
	keyMgr, jwksServer, _ := testVerifierSetup(t)

	// Create verifier expecting a different audience
	verifier := New(jwksServer.URL, "wrong-trust-domain.example.com")

	tokenString := createTestTxToken(t, keyMgr, validClaims(), 15*time.Second)

	_, err := verifier.Verify(context.Background(), tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestVerifier_TamperedToken(t *testing.T) {
	keyMgr, _, verifier := testVerifierSetup(t)

	tokenString := createTestTxToken(t, keyMgr, validClaims(), 15*time.Second)

	// Tamper with the token by changing a character in the signature
	tampered := tokenString[:len(tokenString)-5] + "XXXXX"

	_, err := verifier.Verify(context.Background(), tampered)
	assert.Error(t, err)
}

func TestVerifier_WrongTypHeader(t *testing.T) {
	keyMgr, _, verifier := testVerifierSetup(t)

	// Create a regular JWT (not txntoken+jwt) by signing directly
	signingKey, kid := keyMgr.SigningKey()
	regularJWT := createRegularJWT(t, signingKey, kid, map[string]any{
		"iss":    "https://tts.example.com",
		"aud":    "trust-domain.example.com",
		"sub":    "user@example.com",
		"scope":  "read:data",
		"req_wl": "sa:agent",
		"txn":    "some-txn-id",
		"exp":    time.Now().Add(15 * time.Second).Unix(),
		"iat":    time.Now().Unix(),
	})

	_, err := verifier.Verify(context.Background(), regularJWT)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "typ")
}

func TestVerifier_KeyRotation(t *testing.T) {
	keyMgr, _, verifier := testVerifierSetup(t)

	// Create token with current key
	tokenString := createTestTxToken(t, keyMgr, validClaims(), 15*time.Second)

	// Rotate the key
	err := keyMgr.Rotate()
	require.NoError(t, err)

	// Old token should still verify (JWKS serves both keys)
	claims, err := verifier.Verify(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)

	// New token with rotated key should also verify
	newTokenString := createTestTxToken(t, keyMgr, validClaims(), 15*time.Second)
	claims2, err := verifier.Verify(context.Background(), newTokenString)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims2.Subject)
}

func TestVerifier_AllClaimsExtracted(t *testing.T) {
	keyMgr, _, verifier := testVerifierSetup(t)

	c := validClaims()
	c.TransactionContext = map[string]any{
		"action":         "analyze",
		"datasetId":      "ds-1234",
		"classification": "public",
	}
	c.RequesterContext = map[string]any{
		"req_ip": "10.0.0.42",
		"authn":  "oidc",
	}

	tokenString := createTestTxToken(t, keyMgr, c, 15*time.Second)

	claims, err := verifier.Verify(context.Background(), tokenString)
	require.NoError(t, err)

	// Required claims
	assert.Equal(t, "https://tts.example.com", claims.Issuer)
	assert.Equal(t, "trust-domain.example.com", claims.Audience)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, "read:data", claims.Scope)
	assert.Equal(t, "spiffe://cluster.local/ns/default/sa/my-agent", claims.RequestingWorkload)
	assert.NotEmpty(t, claims.TransactionID)
	assert.NotZero(t, claims.IssuedAt)
	assert.NotZero(t, claims.ExpiresAt)

	// Optional claims
	require.NotNil(t, claims.TransactionContext)
	assert.Equal(t, "analyze", claims.TransactionContext["action"])
	assert.Equal(t, "ds-1234", claims.TransactionContext["datasetId"])
	assert.Equal(t, "public", claims.TransactionContext["classification"])

	require.NotNil(t, claims.RequesterContext)
	assert.Equal(t, "10.0.0.42", claims.RequesterContext["req_ip"])
	assert.Equal(t, "oidc", claims.RequesterContext["authn"])
}

func TestVerifier_EmptyToken(t *testing.T) {
	_, _, verifier := testVerifierSetup(t)

	_, err := verifier.Verify(context.Background(), "")
	assert.Error(t, err)
}

func TestVerifier_MalformedToken(t *testing.T) {
	_, _, verifier := testVerifierSetup(t)

	_, err := verifier.Verify(context.Background(), "not.a.jwt")
	assert.Error(t, err)
}

func TestVerifier_UnknownKid(t *testing.T) {
	keyMgr, _, _ := testVerifierSetup(t)

	// Create a separate key manager (different keys)
	otherKeyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	// Create a verifier pointing at the original JWKS (doesn't have the other key)
	otherJWKS := httptest.NewServer(otherKeyMgr.JWKSHandler())
	t.Cleanup(otherJWKS.Close)

	// Sign with the original key manager
	tokenString := createTestTxToken(t, keyMgr, validClaims(), 15*time.Second)

	// Verify against the other JWKS (should fail — kid not found)
	verifier := New(otherJWKS.URL, "trust-domain.example.com")
	_, err = verifier.Verify(context.Background(), tokenString)
	assert.Error(t, err)
}
