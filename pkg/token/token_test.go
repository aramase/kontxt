package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA key")
	return key
}

func TestNewTxToken_RequiredClaims(t *testing.T) {
	key := generateTestKey(t)
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "spiffe://cluster.local/ns/default/sa/my-agent",
	}

	tokenString, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Parse without verification to inspect claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	mapClaims := parsed.Claims.(jwt.MapClaims)

	// All required claims must be present
	assert.Equal(t, "https://tts.example.com", mapClaims["iss"])
	assert.Equal(t, "trust-domain.example.com", mapClaims["aud"])
	assert.Equal(t, "user@example.com", mapClaims["sub"])
	assert.Equal(t, "read:data", mapClaims["scope"])
	assert.Equal(t, "spiffe://cluster.local/ns/default/sa/my-agent", mapClaims["req_wl"])
	assert.NotEmpty(t, mapClaims["txn"])
	assert.NotNil(t, mapClaims["iat"])
	assert.NotNil(t, mapClaims["exp"])
}

func TestNewTxToken_TypeHeader(t *testing.T) {
	key := generateTestKey(t)
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}

	tokenString, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	// typ header must be txntoken+jwt
	assert.Equal(t, TypeHeader, parsed.Header["typ"])
	assert.Equal(t, SigningAlgorithm, parsed.Header["alg"])
	assert.Equal(t, "test-kid", parsed.Header["kid"])
}

func TestNewTxToken_Expiration(t *testing.T) {
	key := generateTestKey(t)
	lifetime := 15 * time.Second
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}

	before := time.Now().Unix()
	tokenString, err := New(claims, key, "test-kid", lifetime)
	after := time.Now().Unix()
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	mapClaims := parsed.Claims.(jwt.MapClaims)
	iat := int64(mapClaims["iat"].(float64))
	exp := int64(mapClaims["exp"].(float64))

	// iat should be between before and after
	assert.GreaterOrEqual(t, iat, before)
	assert.LessOrEqual(t, iat, after)

	// exp should be iat + lifetime
	assert.Equal(t, iat+int64(lifetime.Seconds()), exp)
}

func TestNewTxToken_TransactionID(t *testing.T) {
	key := generateTestKey(t)
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}

	tokenString, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	mapClaims := parsed.Claims.(jwt.MapClaims)
	txn := mapClaims["txn"].(string)

	// txn must be a valid UUID
	_, err = uuid.Parse(txn)
	assert.NoError(t, err, "txn must be a valid UUID")
}

func TestNewTxToken_PreserveTransactionID(t *testing.T) {
	key := generateTestKey(t)
	existingTxn := "550e8400-e29b-41d4-a716-446655440000"
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
		TransactionID:      existingTxn, // pre-set for replacement tokens
	}

	tokenString, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	mapClaims := parsed.Claims.(jwt.MapClaims)

	// When TransactionID is pre-set, it should be preserved (for token replacement)
	assert.Equal(t, existingTxn, mapClaims["txn"])
}

func TestNewTxToken_OptionalClaims(t *testing.T) {
	key := generateTestKey(t)
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
		TransactionContext: map[string]any{
			"action":         "analyze",
			"datasetId":      "ds-1234",
			"classification": "public",
		},
		RequesterContext: map[string]any{
			"req_ip": "10.0.0.42",
			"authn":  "oidc",
		},
	}

	tokenString, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	mapClaims := parsed.Claims.(jwt.MapClaims)

	// tctx should be present with all fields
	tctx, ok := mapClaims["tctx"].(map[string]any)
	require.True(t, ok, "tctx must be a map")
	assert.Equal(t, "analyze", tctx["action"])
	assert.Equal(t, "ds-1234", tctx["datasetId"])
	assert.Equal(t, "public", tctx["classification"])

	// rctx should be present with all fields
	rctx, ok := mapClaims["rctx"].(map[string]any)
	require.True(t, ok, "rctx must be a map")
	assert.Equal(t, "10.0.0.42", rctx["req_ip"])
	assert.Equal(t, "oidc", rctx["authn"])
}

func TestNewTxToken_OptionalClaimsOmittedWhenNil(t *testing.T) {
	key := generateTestKey(t)
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
		// TransactionContext and RequesterContext are nil
	}

	tokenString, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	require.NoError(t, err)

	mapClaims := parsed.Claims.(jwt.MapClaims)

	// tctx and rctx should be omitted when nil
	_, hasTctx := mapClaims["tctx"]
	_, hasRctx := mapClaims["rctx"]
	assert.False(t, hasTctx, "tctx should be omitted when nil")
	assert.False(t, hasRctx, "rctx should be omitted when nil")
}

func TestNewTxToken_SignatureVerification(t *testing.T) {
	key := generateTestKey(t)
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}

	tokenString, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)

	// Verify with the corresponding public key
	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestNewTxToken_RequiredFieldValidation(t *testing.T) {
	key := generateTestKey(t)

	tests := []struct {
		name   string
		claims Claims
	}{
		{
			name: "missing issuer",
			claims: Claims{
				Audience:           "aud",
				Subject:            "sub",
				Scope:              "scope",
				RequestingWorkload: "wl",
			},
		},
		{
			name: "missing audience",
			claims: Claims{
				Issuer:             "iss",
				Subject:            "sub",
				Scope:              "scope",
				RequestingWorkload: "wl",
			},
		},
		{
			name: "missing subject",
			claims: Claims{
				Issuer:             "iss",
				Audience:           "aud",
				Scope:              "scope",
				RequestingWorkload: "wl",
			},
		},
		{
			name: "missing scope",
			claims: Claims{
				Issuer:             "iss",
				Audience:           "aud",
				Subject:            "sub",
				RequestingWorkload: "wl",
			},
		},
		{
			name: "missing requesting workload",
			claims: Claims{
				Issuer:   "iss",
				Audience: "aud",
				Subject:  "sub",
				Scope:    "scope",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.claims, key, "test-kid", 15*time.Second)
			assert.Error(t, err, "should reject claims with missing required field")
		})
	}
}

func TestNewTxToken_UniqueTransactionIDs(t *testing.T) {
	key := generateTestKey(t)
	claims := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}

	// Generate two tokens — they should have different txn values
	token1, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)
	token2, err := New(claims, key, "test-kid", 15*time.Second)
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed1, _, err := parser.ParseUnverified(token1, jwt.MapClaims{})
	require.NoError(t, err)
	parsed2, _, err := parser.ParseUnverified(token2, jwt.MapClaims{})
	require.NoError(t, err)

	txn1 := parsed1.Claims.(jwt.MapClaims)["txn"].(string)
	txn2 := parsed2.Claims.(jwt.MapClaims)["txn"].(string)
	assert.NotEqual(t, txn1, txn2, "each token should have a unique txn")
}

func TestNewTxToken_JSONRoundTrip(t *testing.T) {
	// Test that Claims can be serialized to JSON and back
	original := Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
		TransactionID:      "test-txn-id",
		TransactionContext: map[string]any{"key": "value"},
		RequesterContext:   map[string]any{"ip": "10.0.0.1"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Claims
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Issuer, decoded.Issuer)
	assert.Equal(t, original.Subject, decoded.Subject)
	assert.Equal(t, original.TransactionID, decoded.TransactionID)
	assert.Equal(t, "value", decoded.TransactionContext["key"])
	assert.Equal(t, "10.0.0.1", decoded.RequesterContext["ip"])
}
