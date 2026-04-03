// Package token provides types and utilities for creating and working with
// Transaction Tokens (TxTokens) as defined in draft-ietf-oauth-transaction-tokens-08.
package token

// RFC 8693 and TxToken constants.
const (
	// HeaderName is the HTTP header used to propagate TxTokens through call chains.
	HeaderName = "Txn-Token"

	// TypeHeader is the JWT typ header value for TxTokens.
	TypeHeader = "txntoken+jwt"

	// SigningAlgorithm is the default signing algorithm for TxTokens.
	SigningAlgorithm = "RS256"

	// GrantType is the OAuth 2.0 grant type for token exchange (RFC 8693).
	GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	// RequestedTokenType is the requested token type for TxTokens.
	RequestedTokenType = "urn:ietf:params:oauth:token-type:txn_token"

	// SubjectTokenTypeAccessToken is the subject token type for OAuth access tokens.
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// SubjectTokenTypeIDToken is the subject token type for OIDC ID tokens.
	SubjectTokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// SubjectTokenTypeTxnToken is the subject token type for TxToken replacement.
	SubjectTokenTypeTxnToken = "urn:ietf:params:oauth:token-type:txn_token"
)

// Claims represents the claims in a Transaction Token JWT.
type Claims struct {
	// Required claims per draft-ietf-oauth-transaction-tokens-08.

	// Issuer is the TTS issuer URI.
	Issuer string `json:"iss"`
	// IssuedAt is the time the token was issued (Unix timestamp).
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is the expiration time (Unix timestamp).
	ExpiresAt int64 `json:"exp"`
	// Audience is the trust domain identifier.
	Audience string `json:"aud"`
	// TransactionID is a unique identifier for the transaction, preserved across replacements.
	TransactionID string `json:"txn"`
	// Subject is the principal (user or workload) from the subject token.
	Subject string `json:"sub"`
	// Scope is the authorized scope (space-delimited), must be ≤ subject token scope.
	Scope string `json:"scope"`
	// RequestingWorkload is the identity of the workload requesting the token.
	RequestingWorkload string `json:"req_wl"`

	// Optional claims.

	// TransactionContext contains immutable authorization details for the transaction.
	// Populated from request_details + TTS computation/enrichment.
	TransactionContext map[string]any `json:"tctx,omitempty"`
	// RequesterContext contains environmental metadata about how the request arrived.
	// Populated from request_context.
	RequesterContext map[string]any `json:"rctx,omitempty"`
}
