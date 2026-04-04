package extauth

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/aramase/kontxt/api/v1alpha1"
	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	"github.com/aramase/kontxt/sdk/verify"
)

func setupExtAuth(t *testing.T) (*Server, *keys.Manager) {
	t.Helper()

	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	jwksServer := httptest.NewServer(keyMgr.JWKSHandler())
	t.Cleanup(jwksServer.Close)

	verifier := verify.New(jwksServer.URL, "trust-domain.example.com")
	server := NewServer(verifier)

	return server, keyMgr
}

func createTestToken(t *testing.T, keyMgr *keys.Manager, claims token.Claims, lifetime time.Duration) string {
	t.Helper()
	signingKey, kid := keyMgr.SigningKey()
	tokenString, err := token.New(claims, signingKey, kid, lifetime)
	require.NoError(t, err)
	return tokenString
}

func checkRequest(path, method string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Path:    path,
					Method:  method,
					Headers: headers,
				},
			},
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "10.0.0.42",
						},
					},
				},
			},
		},
	}
}

func defaultClaims() token.Claims {
	return token.Claims{
		Issuer:             "https://tts.example.com",
		Audience:           "trust-domain.example.com",
		Subject:            "user@example.com",
		Scope:              "read:datasets execute:analysis",
		RequestingWorkload: "sa:my-agent",
		TransactionContext: map[string]any{
			"datasetId":      "ds-1234",
			"classification": "public",
		},
	}
}

func TestServer_ValidTxToken(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
	assert.NotNil(t, resp.GetOkResponse())
}

func TestServer_MissingTxnTokenHeader(t *testing.T) {
	server, _ := setupExtAuth(t)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{}, // no Txn-Token header
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
	assert.Contains(t, resp.GetStatus().GetMessage(), "missing Txn-Token")
}

func TestServer_ExpiredTxToken(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	txToken := createTestToken(t, keyMgr, defaultClaims(), 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
	assert.Contains(t, resp.GetStatus().GetMessage(), "verification failed")
}

func TestServer_TamperedTxToken(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)
	tampered := txToken[:len(txToken)-5] + "XXXXX"

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": tampered},
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
}

func TestServer_RequiredScopeMissing(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name:          "storage-reqs",
			RequiredScope: "write:datasets",
		},
	})

	claims := defaultClaims()
	claims.Scope = "read:datasets" // does NOT contain write:datasets
	txToken := createTestToken(t, keyMgr, claims, 15*time.Second)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
	assert.Contains(t, resp.GetStatus().GetMessage(), "required scope")
}

func TestServer_RequiredScopePresent(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name:          "storage-reqs",
			RequiredScope: "read:datasets",
		},
	})

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
}

func TestServer_RequiredTctxFieldMissing(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name:               "storage-reqs",
			RequiredTctxFields: []string{"datasetId", "missingField"},
		},
	})

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
	assert.Contains(t, resp.GetStatus().GetMessage(), "missingField")
}

func TestServer_RequiredTctxFieldPresent(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name:               "storage-reqs",
			RequiredTctxFields: []string{"datasetId", "classification"},
		},
	})

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
}

func TestServer_ExcludedEndpoint(t *testing.T) {
	server, _ := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name:          "storage-reqs",
			RequiredScope: "read:datasets",
			ExcludedEndpoints: []v1alpha1.EndpointSpec{
				{Path: "/healthz", Method: "GET"},
				{Path: "/readyz", Method: "GET"},
			},
		},
	})

	// Health endpoint should bypass verification (no Txn-Token needed)
	resp, err := server.Check(context.Background(), checkRequest(
		"/healthz", "GET",
		map[string]string{}, // no Txn-Token
	))
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
}

func TestServer_ExcludedEndpoint_OtherPathNotExcluded(t *testing.T) {
	server, _ := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name: "storage-reqs",
			ExcludedEndpoints: []v1alpha1.EndpointSpec{
				{Path: "/healthz", Method: "GET"},
			},
		},
	})

	// Non-excluded path should still require verification
	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/data", "GET",
		map[string]string{}, // no Txn-Token
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
}

func TestServer_MissingHTTPRequest(t *testing.T) {
	server, _ := setupExtAuth(t)

	resp, err := server.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{},
	})
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
}

func TestServer_HeaderCaseInsensitive(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)

	// Envoy normalizes to lowercase
	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/data", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
}

func TestMatchPath(t *testing.T) {
	assert.True(t, matchPath("/healthz", "/healthz"))
	assert.True(t, matchPath("/healthz/ready", "/healthz"))
	assert.False(t, matchPath("/api/healthz", "/healthz"))
	assert.True(t, matchPath("/api/v1?query=1", "/api/v1"))
	assert.False(t, matchPath("/different", "/healthz"))
}

func TestScopeContains(t *testing.T) {
	assert.True(t, scopeContains("read:datasets execute:analysis", "read:datasets"))
	assert.True(t, scopeContains("read:datasets execute:analysis", "execute:analysis"))
	assert.False(t, scopeContains("read:datasets execute:analysis", "write:reports"))
	assert.False(t, scopeContains("", "read:datasets"))
}

func TestGetHeader(t *testing.T) {
	headers := map[string]string{
		"txn-token":     "token-value",
		"authorization": "Bearer xyz",
	}

	assert.Equal(t, "token-value", getHeader(headers, "Txn-Token"))
	assert.Equal(t, "Bearer xyz", getHeader(headers, "Authorization"))
	assert.Empty(t, getHeader(headers, "X-Missing"))

	// Test with original case
	headers2 := map[string]string{
		"Txn-Token": "token-value",
	}
	assert.Equal(t, "token-value", getHeader(headers2, "Txn-Token"))
}

func TestDeniedResponseFormat(t *testing.T) {
	resp := denied(codes.Unauthenticated, "test error")
	assert.NotNil(t, resp.GetDeniedResponse())
	assert.Contains(t, resp.GetDeniedResponse().GetBody(), "test error")
	assert.Contains(t, resp.GetStatus().GetMessage(), "test error")

	resp2 := denied(codes.PermissionDenied, "forbidden")
	body := resp2.GetDeniedResponse().GetBody()
	assert.True(t, strings.Contains(body, "forbidden"))
}
