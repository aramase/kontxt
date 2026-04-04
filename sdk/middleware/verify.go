// Package middleware provides HTTP middleware for TxToken verification and propagation.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aramase/kontxt/pkg/token"
	"github.com/aramase/kontxt/sdk/verify"
)

type contextKey string

const (
	claimsContextKey contextKey = "kontxt-claims"
	tokenContextKey  contextKey = "kontxt-token"
)

// VerifyTxToken returns HTTP middleware that verifies the Txn-Token header
// on incoming requests. If valid, the claims are stored in the request context
// and the next handler is called. If invalid or missing, a 401 response is returned.
func VerifyTxToken(verifier *verify.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := r.Header.Get(token.HeaderName)
			if tokenString == "" {
				writeVerifyError(w, "missing Txn-Token header")
				return
			}

			claims, err := verifier.Verify(r.Context(), tokenString)
			if err != nil {
				writeVerifyError(w, err.Error())
				return
			}

			// Store claims and raw token in context for downstream use
			ctx := withClaims(r.Context(), claims)
			ctx = withToken(ctx, tokenString)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext extracts the verified TxToken claims from the request context.
// Returns nil if no claims are present (request was not verified).
func ClaimsFromContext(ctx context.Context) *token.Claims {
	if ctx == nil {
		return nil
	}
	claims, _ := ctx.Value(claimsContextKey).(*token.Claims)
	return claims
}

// TokenFromContext extracts the raw TxToken string from the request context.
// Returns an empty string if no token is present.
func TokenFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	t, _ := ctx.Value(tokenContextKey).(string)
	return t
}

// withClaims stores claims in a context.
func withClaims(ctx context.Context, claims *token.Claims) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, claimsContextKey, claims)
}

// withToken stores the raw token string in a context.
func withToken(ctx context.Context, tokenString string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, tokenContextKey, tokenString)
}

// writeVerifyError writes a 401 JSON error response.
func writeVerifyError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   "invalid_token",
		"message": message,
	})
}
