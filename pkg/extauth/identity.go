package extauth

import (
	"fmt"
	"strings"
)

// IdentityResolver resolves the source workload identity from the ext_authz
// CheckRequest. kontxt requires a cryptographically authenticated SPIFFE
// principal on internal traffic (typically supplied by an Istio ambient mesh
// via ztunnel mTLS). There is intentionally no pod-IP fallback: pod IP is
// unauthenticated, spoofable from pods with CAP_NET_RAW or hostNetwork, racy
// across IP recycle, and absent under CNI SNAT or for host-network pods, so
// it is not a sound primitive to gate token issuance on.
type IdentityResolver struct{}

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
	return &IdentityResolver{}
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

// Resolve returns the workload identity for an internal request. A SPIFFE
// principal is required; if it is missing the request is treated as
// unauthenticated so the caller fails closed rather than issuing a TxToken
// against a weak identity primitive.
func (r *IdentityResolver) Resolve(principal string) (*WorkloadIdentity, error) {
	if principal == "" {
		return nil, fmt.Errorf("no SPIFFE principal on internal request (ambient mesh required)")
	}
	return r.ResolveFromPrincipal(principal)
}
