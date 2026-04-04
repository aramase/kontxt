package extauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func TestResolveFromPodIP_Valid(t *testing.T) {
	resolver := NewIdentityResolver()

	// Add a pod to the cache
	resolver.UpdatePod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-agent-pod-abc123",
			Namespace: "team-alpha",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "nightly-sales-agent",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.42",
		},
	})

	identity, err := resolver.ResolveFromPodIP("10.0.0.42")
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:team-alpha:nightly-sales-agent", identity.Subject)
	assert.Equal(t, "team-alpha", identity.Namespace)
	assert.Equal(t, "nightly-sales-agent", identity.ServiceAccount)
}

func TestResolveFromPodIP_WithPort(t *testing.T) {
	resolver := NewIdentityResolver()

	resolver.UpdatePod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "my-sa",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.42",
		},
	})

	// Resolve with IP:port format
	identity, err := resolver.ResolveFromPodIP("10.0.0.42:8080")
	require.NoError(t, err)
	assert.Equal(t, "system:serviceaccount:default:my-sa", identity.Subject)
}

func TestResolveFromPodIP_NotFound(t *testing.T) {
	resolver := NewIdentityResolver()

	_, err := resolver.ResolveFromPodIP("10.99.99.99")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestResolveFromPodIP_Empty(t *testing.T) {
	resolver := NewIdentityResolver()

	_, err := resolver.ResolveFromPodIP("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestDeletePod(t *testing.T) {
	resolver := NewIdentityResolver()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "my-sa",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.42",
		},
	}

	resolver.UpdatePod(pod)

	// Should resolve
	_, err := resolver.ResolveFromPodIP("10.0.0.42")
	require.NoError(t, err)

	// Delete the pod
	resolver.DeletePod(pod)

	// Should no longer resolve
	_, err = resolver.ResolveFromPodIP("10.0.0.42")
	assert.Error(t, err)
}

func TestResolve_PrefersPrincipal(t *testing.T) {
	resolver := NewIdentityResolver()

	// Add a pod with a different identity
	resolver.UpdatePod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "different-pod",
			Namespace: "other-ns",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "other-sa",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.42",
		},
	})

	// When both principal and IP are available, principal wins
	identity, err := resolver.Resolve(
		"spiffe://cluster.local/ns/team-alpha/sa/correct-agent",
		"10.0.0.42",
	)
	require.NoError(t, err)
	assert.Equal(t, "team-alpha", identity.Namespace)
	assert.Equal(t, "correct-agent", identity.ServiceAccount)
}

func TestResolve_FallsBackToIP(t *testing.T) {
	resolver := NewIdentityResolver()

	resolver.UpdatePod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-pod",
			Namespace: "team-alpha",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "my-agent",
		},
		Status: corev1.PodStatus{
			PodIP: "10.0.0.42",
		},
	})

	// No principal, only IP
	identity, err := resolver.Resolve("", "10.0.0.42")
	require.NoError(t, err)
	assert.Equal(t, "my-agent", identity.ServiceAccount)
}

func TestResolve_BothEmpty(t *testing.T) {
	resolver := NewIdentityResolver()

	_, err := resolver.Resolve("", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no identity information")
}

func TestUpdatePod_IgnoresEmptyIP(t *testing.T) {
	resolver := NewIdentityResolver()

	// Pod with no IP should be ignored
	resolver.UpdatePod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "my-sa",
		},
		Status: corev1.PodStatus{
			PodIP: "", // no IP yet
		},
	})

	// Cache should be empty
	_, err := resolver.ResolveFromPodIP("10.0.0.42")
	assert.Error(t, err)
}
