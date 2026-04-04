package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Router routes incoming tokens to the correct authenticator based on the issuer claim.
// Authenticators are tried in order; the first matching one handles the token.
type Router struct {
	authenticators []Authenticator
}

// NewRouter creates a router from an ordered list of authenticators.
func NewRouter(authenticators []Authenticator) *Router {
	return &Router{authenticators: authenticators}
}

// Authenticate decodes the issuer from the token (without verification),
// routes to the matching authenticator, and performs full validation.
func (r *Router) Authenticate(ctx context.Context, token string) (*SubjectInfo, error) {
	issuer, err := extractIssuer(token)
	if err != nil {
		return nil, fmt.Errorf("extracting issuer from token: %w", err)
	}

	for _, auth := range r.authenticators {
		if auth.Matches(issuer) {
			return auth.Authenticate(ctx, token)
		}
	}

	return nil, fmt.Errorf("no authenticator found for issuer %q", issuer)
}

// extractIssuer decodes the JWT payload without verification to read the `iss` claim.
// This is safe because actual token verification happens in the authenticator.
func extractIssuer(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (part 1)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsing JWT payload: %w", err)
	}

	if claims.Issuer == "" {
		return "", fmt.Errorf("token has no iss claim")
	}

	return claims.Issuer, nil
}
