package tts

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
)

const testAudience = "trust-domain.example.com"

func newLocalVerifierFixture(t *testing.T) (*keys.Manager, *localVerifier) {
	t.Helper()
	km, err := keys.NewManager(2048, time.Hour)
	require.NoError(t, err)
	return km, newLocalVerifier(km, testAudience)
}

// signTxToken signs a TxToken using the manager's current key.
func signTxToken(t *testing.T, km *keys.Manager, claims token.Claims, lifetime time.Duration) string {
	t.Helper()
	key, kid := km.SigningKey()
	s, err := token.New(claims, key, kid, lifetime)
	require.NoError(t, err)
	return s
}

func validClaims() token.Claims {
	return token.Claims{
		Issuer:             "https://tts.example.com",
		Audience:           testAudience,
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "system:serviceaccount:team-alpha:agent",
	}
}

func TestLocalVerifier_ValidToken(t *testing.T) {
	km, v := newLocalVerifierFixture(t)
	tok := signTxToken(t, km, validClaims(), 15*time.Second)

	claims, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
	assert.Equal(t, testAudience, claims.Audience)
	assert.Equal(t, "read:data", claims.Scope)
}

func TestLocalVerifier_VerifiesAcrossKeyRotation(t *testing.T) {
	// Sign a token, rotate, then ensure verification still succeeds against
	// the previous key. Replacement requests may arrive briefly after a
	// rotation and must not 500.
	km, v := newLocalVerifierFixture(t)
	tok := signTxToken(t, km, validClaims(), 15*time.Second)

	require.NoError(t, km.Rotate())

	claims, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", claims.Subject)
}

func TestLocalVerifier_RejectsWrongAudience(t *testing.T) {
	km, v := newLocalVerifierFixture(t)
	c := validClaims()
	c.Audience = "some-other-trust-domain"
	tok := signTxToken(t, km, c, 15*time.Second)

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestLocalVerifier_RejectsExpiredToken(t *testing.T) {
	km, v := newLocalVerifierFixture(t)
	// Negative lifetime → exp is in the past.
	tok := signTxToken(t, km, validClaims(), -1*time.Second)

	_, err := v.Verify(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestLocalVerifier_RejectsWrongTypHeader(t *testing.T) {
	// Forge a JWT signed by the same key but with a generic typ header so
	// access tokens cannot be replayed as TxTokens.
	km, v := newLocalVerifierFixture(t)
	signingKey, kid := km.SigningKey()

	now := time.Now()
	mc := jwt.MapClaims{
		"iss": "https://tts.example.com",
		"aud": testAudience,
		"sub": "user@example.com",
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Second).Unix(),
		"txn": "abc-123",
	}
	jt := jwt.NewWithClaims(jwt.SigningMethodRS256, mc)
	jt.Header["kid"] = kid
	jt.Header["typ"] = "JWT" // wrong typ
	tokenString, err := jt.SignedString(signingKey)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), tokenString)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid typ header")
}

func TestLocalVerifier_RejectsUnknownKid(t *testing.T) {
	// Sign with a different key manager's key so the kid won't be in the
	// verifier's key set.
	otherKM, err := keys.NewManager(2048, time.Hour)
	require.NoError(t, err)
	_, v := newLocalVerifierFixture(t)

	tok := signTxToken(t, otherKM, validClaims(), 15*time.Second)

	_, err = v.Verify(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown kid")
}

func TestLocalVerifier_RejectsEmptyToken(t *testing.T) {
	_, v := newLocalVerifierFixture(t)
	_, err := v.Verify(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty token")
}
