// Package keys provides RSA key management for the Transaction Token Service.
// It handles key generation, rotation, and serving public keys via a JWKS endpoint.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Manager handles RSA key lifecycle: generation, rotation, and public key serving.
// It maintains a current signing key and optionally a previous key for graceful rotation.
type Manager struct {
	mu       sync.RWMutex
	current  *keyEntry
	previous *keyEntry
	keySize  int
	lifetime time.Duration
}

type keyEntry struct {
	privateKey *rsa.PrivateKey
	kid        string
}

// NewManager creates a new key manager with an initial RSA key pair.
func NewManager(keySize int, rotationInterval time.Duration) (*Manager, error) {
	m := &Manager{
		keySize:  keySize,
		lifetime: rotationInterval,
	}

	entry, err := m.generateKey()
	if err != nil {
		return nil, fmt.Errorf("generating initial key: %w", err)
	}
	m.current = entry

	return m, nil
}

// SigningKey returns the current RSA private key and its key ID.
func (m *Manager) SigningKey() (*rsa.PrivateKey, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current.privateKey, m.current.kid
}

// Rotate generates a new key pair, making the current key the previous one.
// The previous key is kept for one rotation cycle to allow in-flight token verification.
func (m *Manager) Rotate() error {
	entry, err := m.generateKey()
	if err != nil {
		return fmt.Errorf("generating new key: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.previous = m.current
	m.current = entry
	return nil
}

// PublicKeys returns the public keys (current + previous if present) for JWKS serving.
func (m *Manager) PublicKeys() []PublicKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := []PublicKey{newPublicKey(m.current)}
	if m.previous != nil {
		keys = append(keys, newPublicKey(m.previous))
	}
	return keys
}

// JWKSHandler returns an HTTP handler that serves the JWKS endpoint.
func (m *Manager) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		jwks := JWKSet{
			Keys: m.PublicKeys(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")

		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
		}
	})
}

// generateKey creates a new RSA key pair with a deterministic key ID.
func (m *Manager) generateKey() (*keyEntry, error) {
	key, err := rsa.GenerateKey(rand.Reader, m.keySize)
	if err != nil {
		return nil, err
	}

	kid := computeKid(&key.PublicKey)
	return &keyEntry{privateKey: key, kid: kid}, nil
}

// computeKid generates a deterministic key ID from the public key material.
// Uses a SHA-256 hash of the modulus, truncated to 16 hex characters.
func computeKid(pub *rsa.PublicKey) string {
	h := sha256.Sum256(pub.N.Bytes())
	return fmt.Sprintf("%x", h[:8])
}

// sha256Sum computes a SHA-256 hash of the data.
func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// JWKSet is a JSON Web Key Set (RFC 7517).
type JWKSet struct {
	Keys []PublicKey `json:"keys"`
}

// PublicKey represents an RSA public key in JWK format (RFC 7517).
type PublicKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// newPublicKey creates a JWK representation of an RSA public key.
func newPublicKey(entry *keyEntry) PublicKey {
	pub := &entry.privateKey.PublicKey
	return PublicKey{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: entry.kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// RSAPublicKey converts the JWK PublicKey back to an *rsa.PublicKey.
func (pk *PublicKey) RSAPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(pk.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(pk.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
