package tts

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aramase/kontxt/pkg/authn"
)

// Config is the TTS server configuration, matching the TxTokenConfig CRD spec.
type Config struct {
	// TrustDomain is the trust domain identifier, used as the `aud` claim in TxTokens.
	TrustDomain string `yaml:"trustDomain"`
	// Issuer is the TTS issuer URI, used as the `iss` claim in TxTokens.
	Issuer string `yaml:"issuer"`
	// SubjectTokens is an ordered list of JWT authenticators for subject token validation.
	SubjectTokens []authn.AuthenticatorConfig `yaml:"subjectTokens"`
	// Defaults contains default token settings.
	Defaults TokenDefaults `yaml:"defaults"`
}

// TokenDefaults contains default token configuration.
type TokenDefaults struct {
	// TokenLifetime is the default TxToken lifetime (e.g., "15s").
	TokenLifetime string `yaml:"tokenLifetime"`
	// KeySize is the RSA key size in bits (e.g., 2048).
	KeySize int `yaml:"keySize"`
}

// DefaultTokenLifetime returns the parsed token lifetime, defaulting to 15s.
func (c *Config) DefaultTokenLifetime() time.Duration {
	if c.Defaults.TokenLifetime == "" {
		return 15 * time.Second
	}
	d, err := time.ParseDuration(c.Defaults.TokenLifetime)
	if err != nil {
		return 15 * time.Second
	}
	return d
}

// DefaultKeySize returns the RSA key size, defaulting to 2048.
func (c *Config) DefaultKeySize() int {
	if c.Defaults.KeySize == 0 {
		return 2048
	}
	return c.Defaults.KeySize
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.TrustDomain == "" {
		return fmt.Errorf("trustDomain is required")
	}
	if c.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	// SubjectTokens can be empty — the TTS will reject all token exchange
	// requests until authenticators are configured (useful for initial deploy).
	return nil
}

// LoadConfig reads and parses a TTS configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
