package extauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveFromPrincipal_Valid(t *testing.T) {
	resolver := NewIdentityResolver()

	identity, err := resolver.ResolveFromPrincipal("spiffe://cluster.local/ns/team-alpha/sa/nightly-sales-agent")
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:team-alpha:nightly-sales-agent", identity.Subject)
	assert.Equal(t, "team-alpha", identity.Namespace)
	assert.Equal(t, "nightly-sales-agent", identity.ServiceAccount)
}

func TestResolveFromPrincipal_DifferentTrustDomain(t *testing.T) {
	resolver := NewIdentityResolver()

	identity, err := resolver.ResolveFromPrincipal("spiffe://my-cluster.example.com/ns/production/sa/web-server")
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:production:web-server", identity.Subject)
	assert.Equal(t, "production", identity.Namespace)
	assert.Equal(t, "web-server", identity.ServiceAccount)
}

func TestResolveFromPrincipal_Empty(t *testing.T) {
	resolver := NewIdentityResolver()

	_, err := resolver.ResolveFromPrincipal("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestResolveFromPrincipal_NotSPIFFE(t *testing.T) {
	resolver := NewIdentityResolver()

	_, err := resolver.ResolveFromPrincipal("https://not-a-spiffe-uri")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a SPIFFE URI")
}

func TestResolveFromPrincipal_InvalidFormat(t *testing.T) {
	resolver := NewIdentityResolver()

	// Missing /sa/ part
	_, err := resolver.ResolveFromPrincipal("spiffe://cluster.local/ns/team-alpha")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SPIFFE URI")
}

func TestResolve_UsesPrincipal(t *testing.T) {
	resolver := NewIdentityResolver()

	identity, err := resolver.Resolve("spiffe://cluster.local/ns/team-alpha/sa/correct-agent")
	require.NoError(t, err)
	assert.Equal(t, "team-alpha", identity.Namespace)
	assert.Equal(t, "correct-agent", identity.ServiceAccount)
}

func TestResolve_FailsClosedWithoutPrincipal(t *testing.T) {
	resolver := NewIdentityResolver()

	_, err := resolver.Resolve("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SPIFFE principal")
	assert.Contains(t, err.Error(), "ambient mesh required")
}
