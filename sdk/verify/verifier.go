// Package verify provides TxToken JWT verification with JWKS-based key resolution.
package verify

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aramase/kontxt/pkg/token"
)

// Verifier validates TxToken JWTs against a JWKS endpoint.
type Verifier struct {
	jwksURL  string
	audience string

	mu     sync.RWMutex
	keys   map[string]*rsa.PublicKey
	client *http.Client
}

// New creates a new TxToken verifier.
// jwksURL is the URL of the TTS JWKS endpoint (e.g., "https://tts.example.com/.well-known/jwks.json").
// audience is the expected trust domain (the `aud` claim in the TxToken).
func New(jwksURL, audience string) *Verifier {
	return &Verifier{
		jwksURL:  jwksURL,
		audience: audience,
		keys:     make(map[string]*rsa.PublicKey),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Verify validates a TxToken JWT string and returns the extracted claims.
// It checks: typ header, signature (via JWKS), expiration, and audience.
func (v *Verifier) Verify(_ context.Context, tokenString string) (*token.Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Parse and verify the token
	parsed, err := jwt.Parse(tokenString, v.keyFunc, jwt.WithAudience(v.audience))
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Check typ header
	typ, _ := parsed.Header["typ"].(string)
	if typ != token.TypeHeader {
		return nil, fmt.Errorf("invalid typ header: expected %q, got %q", token.TypeHeader, typ)
	}

	// Extract claims
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	claims, err := extractClaims(mapClaims)
	if err != nil {
		return nil, fmt.Errorf("extracting claims: %w", err)
	}

	return claims, nil
}

// keyFunc resolves the signing key for JWT verification via JWKS.
func (v *Verifier) keyFunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}

	kid, ok := t.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("missing kid in token header")
	}

	// Try cached key
	v.mu.RLock()
	key, found := v.keys[kid]
	v.mu.RUnlock()
	if found {
		return key, nil
	}

	// Fetch JWKS and retry
	if err := v.fetchJWKS(); err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	v.mu.RLock()
	key, found = v.keys[kid]
	v.mu.RUnlock()
	if !found {
		return nil, fmt.Errorf("key %q not found in JWKS at %s", kid, v.jwksURL)
	}

	return key, nil
}

// fetchJWKS fetches public keys from the JWKS endpoint and caches them.
func (v *Verifier) fetchJWKS() error {
	resp, err := v.client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("fetching JWKS from %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Replace all cached keys with fresh ones
	v.keys = make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		v.keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}

	return nil
}

// extractClaims converts jwt.MapClaims to our typed Claims struct.
func extractClaims(mc jwt.MapClaims) (*token.Claims, error) {
	claims := &token.Claims{}

	claims.Issuer, _ = mc["iss"].(string)
	claims.Audience, _ = mc["aud"].(string)
	claims.Subject, _ = mc["sub"].(string)
	claims.Scope, _ = mc["scope"].(string)
	claims.RequestingWorkload, _ = mc["req_wl"].(string)
	claims.TransactionID, _ = mc["txn"].(string)

	if iat, ok := mc["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if exp, ok := mc["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}

	if tctx, ok := mc["tctx"].(map[string]any); ok {
		claims.TransactionContext = tctx
	}
	if rctx, ok := mc["rctx"].(map[string]any); ok {
		claims.RequesterContext = rctx
	}

	return claims, nil
}

// createRegularJWT creates a JWT without the txntoken+jwt typ header (for testing).
func createRegularJWT(t interface{ Helper() }, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	tok.Header["kid"] = kid
	// Intentionally NOT setting typ to txntoken+jwt
	tokenString, err := tok.SignedString(key)
	if err != nil {
		panic(fmt.Sprintf("failed to sign test JWT: %v", err))
	}
	return tokenString
}
