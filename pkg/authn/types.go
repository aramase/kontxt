// Package authn provides pluggable JWT authentication for the Transaction Token Service.
// Inspired by KEP-3331 (Structured Authentication Configuration), it supports an ordered
// list of JWT authenticators with OIDC discovery, CEL-based claim validation, and claim mapping.
package authn

import (
	"context"
)

// Authenticator validates a subject token and returns the authenticated subject information.
type Authenticator interface {
	// Matches returns true if this authenticator handles tokens from the given issuer.
	Matches(issuer string) bool
	// Authenticate validates the token and returns the subject info.
	Authenticate(ctx context.Context, token string) (*SubjectInfo, error)
}

// SubjectInfo contains the authenticated identity extracted from a subject token.
type SubjectInfo struct {
	// Subject is the principal identifier (becomes the TxToken `sub` claim).
	Subject string
	// Extra contains additional identity attributes from claim mappings.
	Extra map[string]string
}

// IssuerConfig defines the OIDC issuer configuration for a JWT authenticator.
type IssuerConfig struct {
	// URL is the issuer identifier. Must match the `iss` claim in incoming tokens.
	URL string `json:"url" yaml:"url"`
	// DiscoveryURL overrides where to fetch OIDC discovery metadata.
	// If empty, defaults to {URL}/.well-known/openid-configuration.
	DiscoveryURL string `json:"discoveryURL,omitempty" yaml:"discoveryURL,omitempty"`
	// Audiences is the list of acceptable audience values.
	Audiences []string `json:"audiences" yaml:"audiences"`
	// AudienceMatchPolicy determines how audiences are matched.
	// "MatchAny" means the token's aud must contain at least one configured audience.
	AudienceMatchPolicy string `json:"audienceMatchPolicy,omitempty" yaml:"audienceMatchPolicy,omitempty"`
}

// ClaimValidationRule is a CEL expression evaluated against raw JWT claims.
// If the expression returns false, the token is rejected.
type ClaimValidationRule struct {
	// Expression is a CEL expression that must evaluate to true.
	// The variable `claims` is available as a map[string]any.
	Expression string `json:"expression" yaml:"expression"`
	// Message is the error message when the expression returns false.
	Message string `json:"message" yaml:"message"`
}

// ClaimMappings defines how JWT claims are mapped to SubjectInfo fields.
type ClaimMappings struct {
	// Subject determines which claim becomes the TxToken's `sub`.
	Subject ClaimOrExpression `json:"subject" yaml:"subject"`
	// Extra carries additional identity attributes from the IdP token.
	Extra []ExtraMapping `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// ClaimOrExpression specifies either a simple claim name or a CEL expression.
// Exactly one of Claim or Expression must be set.
type ClaimOrExpression struct {
	// Claim is a simple JWT claim name (e.g., "email", "sub", "oid").
	Claim string `json:"claim,omitempty" yaml:"claim,omitempty"`
	// Expression is a CEL expression evaluated against the `claims` map.
	Expression string `json:"expression,omitempty" yaml:"expression,omitempty"`
}

// ExtraMapping maps a JWT claim to an extra key-value pair on SubjectInfo.
type ExtraMapping struct {
	// Key is the extra attribute key (e.g., "tenant", "name").
	Key string `json:"key" yaml:"key"`
	// ValueExpression is a CEL expression producing the value.
	ValueExpression string `json:"valueExpression" yaml:"valueExpression"`
}

// AuthenticatorConfig is the full configuration for a single JWT authenticator.
type AuthenticatorConfig struct {
	Issuer               IssuerConfig          `json:"issuer" yaml:"issuer"`
	ClaimValidationRules []ClaimValidationRule  `json:"claimValidationRules,omitempty" yaml:"claimValidationRules,omitempty"`
	ClaimMappings        ClaimMappings          `json:"claimMappings" yaml:"claimMappings"`
}
