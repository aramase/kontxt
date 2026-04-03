package token

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// New creates a signed TxToken JWT from the given claims.
// If claims.TransactionID is empty, a new UUID is generated.
// The token is signed with the provided RSA private key using RS256.
func New(claims Claims, key *rsa.PrivateKey, kid string, lifetime time.Duration) (string, error) {
	if err := validateRequired(claims); err != nil {
		return "", err
	}

	now := time.Now()
	txn := claims.TransactionID
	if txn == "" {
		txn = uuid.New().String()
	}

	// Build JWT claims as a map to control field names exactly.
	jwtClaims := jwt.MapClaims{
		"iss":    claims.Issuer,
		"iat":    now.Unix(),
		"exp":    now.Add(lifetime).Unix(),
		"aud":    claims.Audience,
		"txn":    txn,
		"sub":    claims.Subject,
		"scope":  claims.Scope,
		"req_wl": claims.RequestingWorkload,
	}

	if claims.TransactionContext != nil {
		jwtClaims["tctx"] = claims.TransactionContext
	}
	if claims.RequesterContext != nil {
		jwtClaims["rctx"] = claims.RequesterContext
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["typ"] = TypeHeader
	token.Header["kid"] = kid

	return token.SignedString(key)
}

// validateRequired checks that all required TxToken claims are present.
func validateRequired(claims Claims) error {
	if claims.Issuer == "" {
		return errors.New("issuer (iss) is required")
	}
	if claims.Audience == "" {
		return errors.New("audience (aud) is required")
	}
	if claims.Subject == "" {
		return errors.New("subject (sub) is required")
	}
	if claims.Scope == "" {
		return errors.New("scope is required")
	}
	if claims.RequestingWorkload == "" {
		return errors.New("requesting workload (req_wl) is required")
	}
	return nil
}
