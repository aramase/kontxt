package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager_GeneratesValidKey(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	key, kid := m.SigningKey()
	require.NotNil(t, key)
	assert.NotEmpty(t, kid)

	// Key should be usable for signing
	data := []byte("test data")
	_, err = rsa.SignPKCS1v15(rand.Reader, key, 0, data)
	assert.NoError(t, err)
}

func TestNewManager_KidIsDeterministic(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	_, kid1 := m.SigningKey()
	_, kid2 := m.SigningKey()

	// Same key should produce the same kid every time
	assert.Equal(t, kid1, kid2)
}

func TestNewManager_KidDiffersBetweenKeys(t *testing.T) {
	m1, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)
	m2, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	_, kid1 := m1.SigningKey()
	_, kid2 := m2.SigningKey()

	// Different keys should produce different kids
	assert.NotEqual(t, kid1, kid2)
}

func TestManager_Rotate(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	_, kidBefore := m.SigningKey()

	err = m.Rotate()
	require.NoError(t, err)

	_, kidAfter := m.SigningKey()

	// After rotation, signing key should be different
	assert.NotEqual(t, kidBefore, kidAfter)
}

func TestManager_PublicKeys_IncludesCurrentAndPrevious(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	// Before rotation: one key
	keys := m.PublicKeys()
	assert.Len(t, keys, 1)

	_, kidBefore := m.SigningKey()

	// After rotation: both old and new key present
	err = m.Rotate()
	require.NoError(t, err)

	_, kidAfter := m.SigningKey()

	keys = m.PublicKeys()
	assert.Len(t, keys, 2)

	// Both kids should be present
	kids := make(map[string]bool)
	for _, k := range keys {
		kids[k.Kid] = true
	}
	assert.True(t, kids[kidBefore], "previous key should still be present after rotation")
	assert.True(t, kids[kidAfter], "new key should be present after rotation")
}

func TestManager_DoubleRotation_DropsOldest(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	_, kid0 := m.SigningKey()

	err = m.Rotate()
	require.NoError(t, err)
	_, kid1 := m.SigningKey()

	err = m.Rotate()
	require.NoError(t, err)
	_, kid2 := m.SigningKey()

	// After two rotations: only kid1 and kid2 should be present (kid0 dropped)
	keys := m.PublicKeys()
	assert.Len(t, keys, 2)

	kids := make(map[string]bool)
	for _, k := range keys {
		kids[k.Kid] = true
	}
	assert.False(t, kids[kid0], "oldest key should be dropped after two rotations")
	assert.True(t, kids[kid1], "previous key should be present")
	assert.True(t, kids[kid2], "current key should be present")
}

func TestJWKSHandler_ReturnsValidJWKSet(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	handler := m.JWKSHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)

	var jwks JWKSet
	err = json.Unmarshal(body, &jwks)
	require.NoError(t, err)
	assert.Len(t, jwks.Keys, 1)

	key := jwks.Keys[0]
	assert.Equal(t, "RSA", key.Kty)
	assert.Equal(t, "RS256", key.Alg)
	assert.Equal(t, "sig", key.Use)
	assert.NotEmpty(t, key.Kid)
	assert.NotEmpty(t, key.N)
	assert.NotEmpty(t, key.E)
}

func TestJWKSHandler_ReflectsRotation(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	handler := m.JWKSHandler()

	// Before rotation
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))

	var jwks1 JWKSet
	err = json.Unmarshal(rec1.Body.Bytes(), &jwks1)
	require.NoError(t, err)
	assert.Len(t, jwks1.Keys, 1)

	// After rotation
	err = m.Rotate()
	require.NoError(t, err)

	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))

	var jwks2 JWKSet
	err = json.Unmarshal(rec2.Body.Bytes(), &jwks2)
	require.NoError(t, err)
	assert.Len(t, jwks2.Keys, 2)
}

func TestJWKSHandler_MethodNotAllowed(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	handler := m.JWKSHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestJWKSHandler_CacheHeaders(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	handler := m.JWKSHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	// JWKS should have cache control headers to prevent stale caching
	assert.Contains(t, rec.Header().Get("Cache-Control"), "max-age")
}

func TestPublicKey_CanVerifySignature(t *testing.T) {
	m, err := NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	signingKey, kid := m.SigningKey()

	// Find the public key with matching kid
	var pubKey *PublicKey
	for _, k := range m.PublicKeys() {
		if k.Kid == kid {
			pubKey = &k
			break
		}
	}
	require.NotNil(t, pubKey, "public key with matching kid should exist")

	// Convert back to *rsa.PublicKey and verify we can use it
	rsaPub, err := pubKey.RSAPublicKey()
	require.NoError(t, err)

	// Sign with private key, verify with public key
	data := []byte("test message")
	hash := sha256Sum(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, 0, hash)
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(rsaPub, 0, hash, sig)
	assert.NoError(t, err)
}
