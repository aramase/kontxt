package middleware

import (
	"net/http"

	"github.com/aramase/kontxt/pkg/token"
)

// PropagateTransport is an http.RoundTripper that automatically propagates
// the Txn-Token header from the request context to outbound HTTP requests.
// Wrap your existing transport with NewPropagateTransport to enable propagation.
type PropagateTransport struct {
	base http.RoundTripper
}

// NewPropagateTransport creates a new PropagateTransport wrapping the given base transport.
// If base is nil, http.DefaultTransport is used.
func NewPropagateTransport(base http.RoundTripper) *PropagateTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &PropagateTransport{base: base}
}

// RoundTrip implements http.RoundTripper. It copies the Txn-Token from the
// request's context into the outbound request header, then delegates to the
// base transport. If the header is already set on the request, it is not overwritten.
func (t *PropagateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Don't overwrite if already set
	if req.Header.Get(token.HeaderName) != "" {
		return t.base.RoundTrip(req)
	}

	// Copy from context if available
	if txToken := TokenFromContext(req.Context()); txToken != "" {
		// Clone the request to avoid mutating the original
		req = req.Clone(req.Context())
		req.Header.Set(token.HeaderName, txToken)
	}

	return t.base.RoundTrip(req)
}
