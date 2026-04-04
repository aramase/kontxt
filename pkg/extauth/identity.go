package extauth

import (
	"fmt"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// IdentityResolver resolves the source workload identity from the ext_authz CheckRequest.
// In Istio ambient mode, it parses the SPIFFE principal from source.principal.
// In standalone mode, it resolves the source pod IP to a service account via an informer cache.
type IdentityResolver struct {
	mu   sync.RWMutex
	pods map[string]*podInfo // pod IP → pod info
}

type podInfo struct {
	Name           string
	Namespace      string
	ServiceAccount string
}

// WorkloadIdentity represents a resolved workload identity.
type WorkloadIdentity struct {
	// Subject is the workload identifier (e.g., "system:serviceaccount:team-alpha:my-agent").
	Subject string
	// Namespace is the workload's Kubernetes namespace.
	Namespace string
	// ServiceAccount is the workload's Kubernetes service account name.
	ServiceAccount string
}

// NewIdentityResolver creates a new identity resolver.
func NewIdentityResolver() *IdentityResolver {
	return &IdentityResolver{
		pods: make(map[string]*podInfo),
	}
}

// ResolveFromPrincipal extracts the workload identity from a SPIFFE principal URI.
// Format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
func (r *IdentityResolver) ResolveFromPrincipal(principal string) (*WorkloadIdentity, error) {
	if principal == "" {
		return nil, fmt.Errorf("empty principal")
	}

	if !strings.HasPrefix(principal, "spiffe://") {
		return nil, fmt.Errorf("principal %q is not a SPIFFE URI", principal)
	}

	// Parse: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
	path := strings.TrimPrefix(principal, "spiffe://")
	// Remove trust domain
	slashIdx := strings.Index(path, "/")
	if slashIdx < 0 {
		return nil, fmt.Errorf("invalid SPIFFE URI %q: no path after trust domain", principal)
	}
	path = path[slashIdx:]

	// Parse /ns/<namespace>/sa/<service-account>
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 4 || parts[0] != "ns" || parts[2] != "sa" {
		return nil, fmt.Errorf("invalid SPIFFE URI %q: expected /ns/<namespace>/sa/<sa>", principal)
	}

	ns := parts[1]
	sa := parts[3]

	return &WorkloadIdentity{
		Subject:        fmt.Sprintf("system:serviceaccount:%s:%s", ns, sa),
		Namespace:      ns,
		ServiceAccount: sa,
	}, nil
}

// ResolveFromPodIP resolves a workload identity from a pod IP address
// using the local informer cache.
func (r *IdentityResolver) ResolveFromPodIP(podIP string) (*WorkloadIdentity, error) {
	if podIP == "" {
		return nil, fmt.Errorf("empty pod IP")
	}

	// Strip port if present (e.g., "10.0.0.42:8080" → "10.0.0.42")
	if idx := strings.LastIndex(podIP, ":"); idx > 0 {
		// Check if it's an IPv6 address
		if !strings.Contains(podIP, "]") {
			podIP = podIP[:idx]
		}
	}

	r.mu.RLock()
	info, found := r.pods[podIP]
	r.mu.RUnlock()

	if !found {
		return nil, fmt.Errorf("pod with IP %s not found in cache", podIP)
	}

	return &WorkloadIdentity{
		Subject:        fmt.Sprintf("system:serviceaccount:%s:%s", info.Namespace, info.ServiceAccount),
		Namespace:      info.Namespace,
		ServiceAccount: info.ServiceAccount,
	}, nil
}

// UpdatePod adds or updates a pod in the informer cache.
func (r *IdentityResolver) UpdatePod(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.pods[pod.Status.PodIP] = &podInfo{
		Name:           pod.Name,
		Namespace:      pod.Namespace,
		ServiceAccount: pod.Spec.ServiceAccountName,
	}
}

// DeletePod removes a pod from the informer cache.
func (r *IdentityResolver) DeletePod(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pods, pod.Status.PodIP)
}

// Resolve attempts to resolve a workload identity using all available information.
// It tries SPIFFE principal first (cryptographically authenticated), then falls back
// to pod IP resolution (network-level identity).
func (r *IdentityResolver) Resolve(principal, sourceIP string) (*WorkloadIdentity, error) {
	// Prefer SPIFFE principal (cryptographically authenticated in ambient mode)
	if principal != "" {
		return r.ResolveFromPrincipal(principal)
	}

	// Fall back to pod IP resolution (standalone mode)
	if sourceIP != "" {
		return r.ResolveFromPodIP(sourceIP)
	}

	return nil, fmt.Errorf("no identity information available: both principal and source IP are empty")
}
