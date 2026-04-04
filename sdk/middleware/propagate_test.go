package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
)

func TestPropagateTransport_CopiesHeader(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	signingKey, kid := keyMgr.SigningKey()
	txToken, err := token.New(token.Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}, signingKey, kid, 15*time.Second)
	require.NoError(t, err)

	// Simulate an incoming request context with TxToken
	ctx := withToken(withClaims(
		nil, // not needed for propagation
		&token.Claims{Subject: "user@example.com"},
	), txToken)

	// Create a test downstream server that captures the received headers
	var receivedHeader string
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get(token.HeaderName)
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	// Create an HTTP client with the propagation transport
	client := &http.Client{
		Transport: NewPropagateTransport(http.DefaultTransport),
	}

	// Make a request using the context that has the TxToken
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downstream.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, txToken, receivedHeader, "Txn-Token header should be propagated to downstream")
}

func TestPropagateTransport_NoTokenInContext(t *testing.T) {
	// Create a test downstream server
	var receivedHeader string
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get(token.HeaderName)
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	// Create client with propagation transport but no TxToken in context
	client := &http.Client{
		Transport: NewPropagateTransport(http.DefaultTransport),
	}

	req, err := http.NewRequest(http.MethodGet, downstream.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, receivedHeader, "no Txn-Token header should be sent when not in context")
}

func TestPropagateTransport_DoesNotOverwriteExisting(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	signingKey, kid := keyMgr.SigningKey()
	txToken, err := token.New(token.Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:data",
		RequestingWorkload: "sa:my-agent",
	}, signingKey, kid, 15*time.Second)
	require.NoError(t, err)

	ctx := withToken(nil, txToken)

	var receivedHeader string
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get(token.HeaderName)
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	client := &http.Client{
		Transport: NewPropagateTransport(http.DefaultTransport),
	}

	// Set a Txn-Token header explicitly on the request — transport should NOT overwrite
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downstream.URL, nil)
	require.NoError(t, err)
	req.Header.Set(token.HeaderName, "already-set-token")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "already-set-token", receivedHeader, "should not overwrite existing Txn-Token header")
}
