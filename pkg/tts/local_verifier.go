package tts

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
)

// localVerifier verifies TxTokens in-process against the live keys.Manager.
// Used for token replacement so the TTS does not need to reach itself over
// HTTP — `cfg.Issuer` is the `iss` claim identifier and is not necessarily a
// reachable URL (and is often https while the Service is plain HTTP).
type localVerifier struct {
	keyManager *keys.Manager
	audience   string
}

// newLocalVerifier returns a TokenVerifier backed by the given key manager.
// It accepts tokens signed by any key currently in the manager (current +
// previous), so verification continues to work across key rotation.
func newLocalVerifier(km *keys.Manager, audience string) *localVerifier {
	return &localVerifier{keyManager: km, audience: audience}
}

// Verify parses and validates a TxToken JWT. Checks signature against the
// live key set, exp, aud, and the txntoken+jwt typ header.
func (v *localVerifier) Verify(_ context.Context, tokenString string) (*token.Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	parsed, err := jwt.Parse(tokenString, v.keyFunc, jwt.WithAudience(v.audience))
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	typ, _ := parsed.Header["typ"].(string)
	if typ != token.TypeHeader {
		return nil, fmt.Errorf("invalid typ header: expected %q, got %q", token.TypeHeader, typ)
	}

	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	return extractClaims(mc), nil
}

// keyFunc resolves the signing key for a JWT against the live key set.
func (v *localVerifier) keyFunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}

	kid, ok := t.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("missing kid in token header")
	}

	for _, pk := range v.keyManager.PublicKeys() {
		if pk.Kid != kid {
			continue
		}
		rsaKey, err := pk.RSAPublicKey()
		if err != nil {
			return nil, fmt.Errorf("decoding key %q: %w", kid, err)
		}
		return rsaKey, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

// extractClaims converts jwt.MapClaims to the typed Claims struct. Mirrors
// sdk/verify.extractClaims but kept local to avoid exporting it from the SDK
// purely for in-process use.
func extractClaims(mc jwt.MapClaims) *token.Claims {
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

	return claims
}

// Compile-time check that localVerifier satisfies the TokenVerifier interface.
var _ TokenVerifier = (*localVerifier)(nil)
