package authn

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	celgo "github.com/google/cel-go/cel"
)

// OIDCAuthenticator validates JWT tokens against an OIDC provider.
// It handles OIDC discovery, JWKS fetching, signature verification,
// audience validation, CEL claim validation, and claim mapping.
type OIDCAuthenticator struct {
	config          AuthenticatorConfig
	issuerURL       string
	discoveryURL    string
	audiences       map[string]bool
	matchAny        bool
	validationRules []compiledRule
	subjectProgram  celgo.Program
	extraMappings   []compiledMapping

	jwksURL string
	keys    map[string]*rsa.PublicKey
	keysMu  sync.RWMutex
	client  *http.Client
}

// oidcDiscovery represents the relevant fields from an OIDC discovery document.
type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// jwksResponse represents a JSON Web Key Set response.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewOIDCAuthenticator creates a new OIDC authenticator from configuration.
// It compiles CEL expressions and optionally fetches OIDC discovery.
func NewOIDCAuthenticator(config AuthenticatorConfig) (*OIDCAuthenticator, error) {
	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	validationRules, err := compileValidationRules(env, config.ClaimValidationRules)
	if err != nil {
		return nil, fmt.Errorf("compiling validation rules: %w", err)
	}

	subjectProgram, err := compileSubjectMapping(env, config.ClaimMappings.Subject)
	if err != nil {
		return nil, fmt.Errorf("compiling subject mapping: %w", err)
	}

	extraMappings, err := compileExtraMappings(env, config.ClaimMappings.Extra)
	if err != nil {
		return nil, fmt.Errorf("compiling extra mappings: %w", err)
	}

	audiences := make(map[string]bool, len(config.Issuer.Audiences))
	for _, aud := range config.Issuer.Audiences {
		audiences[aud] = true
	}

	discoveryURL := config.Issuer.DiscoveryURL
	if discoveryURL == "" {
		discoveryURL = strings.TrimSuffix(config.Issuer.URL, "/") + "/.well-known/openid-configuration"
	}

	a := &OIDCAuthenticator{
		config:          config,
		issuerURL:       config.Issuer.URL,
		discoveryURL:    discoveryURL,
		audiences:       audiences,
		matchAny:        config.Issuer.AudienceMatchPolicy == "MatchAny" || len(config.Issuer.Audiences) == 1,
		validationRules: validationRules,
		subjectProgram:  subjectProgram,
		extraMappings:   extraMappings,
		keys:            make(map[string]*rsa.PublicKey),
		client:          &http.Client{Timeout: 10 * time.Second},
	}

	return a, nil
}

// Matches returns true if this authenticator handles the given issuer.
func (a *OIDCAuthenticator) Matches(issuer string) bool {
	return issuer == a.issuerURL
}

// Authenticate validates the token and returns subject info.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, tokenString string) (*SubjectInfo, error) {
	// Parse and verify the token
	token, err := jwt.Parse(tokenString, a.keyFunc, jwt.WithIssuer(a.issuerURL))
	if err != nil {
		return nil, fmt.Errorf("parsing/verifying token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	// Validate audience
	if err := a.validateAudience(claims); err != nil {
		return nil, err
	}

	// Convert to map[string]any for CEL evaluation
	claimsMap := map[string]any(claims)

	// Evaluate CEL claim validation rules
	if err := evaluateValidationRules(a.validationRules, claimsMap); err != nil {
		return nil, err
	}

	// Extract subject via claim mapping
	subject, err := evaluateSubjectMapping(a.config.ClaimMappings.Subject, a.subjectProgram, claimsMap)
	if err != nil {
		return nil, fmt.Errorf("extracting subject: %w", err)
	}

	// Extract extra mappings
	extra, err := evaluateExtraMappings(a.extraMappings, claimsMap)
	if err != nil {
		return nil, fmt.Errorf("extracting extra mappings: %w", err)
	}

	return &SubjectInfo{
		Subject: subject,
		Extra:   extra,
	}, nil
}

// validateAudience checks that the token's audience matches the configured audiences.
func (a *OIDCAuthenticator) validateAudience(claims jwt.MapClaims) error {
	aud, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("getting audience: %w", err)
	}

	for _, tokenAud := range aud {
		if a.audiences[tokenAud] {
			return nil
		}
	}

	return fmt.Errorf("token audience %v does not match any configured audience", aud)
}

// keyFunc is the jwt.Keyfunc that provides signing keys for token verification.
func (a *OIDCAuthenticator) keyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	// Try cached key first
	a.keysMu.RLock()
	key, found := a.keys[kid]
	a.keysMu.RUnlock()
	if found {
		return key, nil
	}

	// Fetch JWKS and retry
	if err := a.fetchJWKS(); err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	a.keysMu.RLock()
	key, found = a.keys[kid]
	a.keysMu.RUnlock()
	if !found {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}

	return key, nil
}

// fetchJWKS fetches the JWKS from the provider and caches the keys.
func (a *OIDCAuthenticator) fetchJWKS() error {
	jwksURL := a.jwksURL
	if jwksURL == "" {
		// Discover JWKS URL from OIDC discovery
		url, err := a.discoverJWKSURL()
		if err != nil {
			return err
		}
		jwksURL = url
		a.jwksURL = url
	}

	resp, err := a.client.Get(jwksURL)
	if err != nil {
		return fmt.Errorf("fetching JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	a.keysMu.Lock()
	defer a.keysMu.Unlock()

	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(k)
		if err != nil {
			continue // skip invalid keys
		}
		a.keys[k.Kid] = pubKey
	}

	return nil
}

// discoverJWKSURL fetches the OIDC discovery document and extracts the jwks_uri.
func (a *OIDCAuthenticator) discoverJWKSURL() (string, error) {
	resp, err := a.client.Get(a.discoveryURL)
	if err != nil {
		return "", fmt.Errorf("fetching OIDC discovery from %s: %w", a.discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery endpoint returned status %d", resp.StatusCode)
	}

	var disco oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil {
		return "", fmt.Errorf("decoding OIDC discovery: %w", err)
	}

	if disco.Issuer != a.issuerURL {
		return "", fmt.Errorf("OIDC discovery issuer %q does not match configured issuer %q", disco.Issuer, a.issuerURL)
	}

	if disco.JWKSURI == "" {
		return "", fmt.Errorf("OIDC discovery document has no jwks_uri")
	}

	return disco.JWKSURI, nil
}

// SetJWKSURL allows directly setting the JWKS URL, bypassing OIDC discovery.
// Useful for testing and for issuers that don't support OIDC discovery.
func (a *OIDCAuthenticator) SetJWKSURL(url string) {
	a.jwksURL = url
}

// jwkToRSAPublicKey converts a JWK to an *rsa.PublicKey.
func jwkToRSAPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}
