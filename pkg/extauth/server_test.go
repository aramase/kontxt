package extauth

import (
	"context"
	"encoding/json"
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

func TestServer_CELRule_Allow(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name: "storage-reqs",
			CELRules: []controller.CELRule{
				{
					Name:    "classification-allowed",
					CEL:     `txtoken.tctx.classification in ["public", "internal"]`,
					Message: "classification not allowed",
				},
			},
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

func TestServer_CELRule_Deny(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name: "storage-reqs",
			CELRules: []controller.CELRule{
				{
					Name:    "no-pii",
					CEL:     `txtoken.tctx.classification != "pii"`,
					Message: "PII access blocked by policy",
				},
			},
		},
	})

	claims := defaultClaims()
	claims.TransactionContext["classification"] = "pii"
	txToken := createTestToken(t, keyMgr, claims, 15*time.Second)

	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse())
	assert.Equal(t, int32(codes.PermissionDenied), resp.GetStatus().GetCode())
	assert.Contains(t, resp.GetStatus().GetMessage(), "PII access blocked by policy")
	assert.Contains(t, resp.GetStatus().GetMessage(), "no-pii")
}

func TestServer_CELRule_RequestVariables(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name: "method-reqs",
			CELRules: []controller.CELRule{
				{
					Name:    "reads-only",
					CEL:     `request.method == "GET"`,
					Message: "only GET is allowed for this service",
				},
			},
		},
	})

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)

	// GET passes the CEL rule.
	getResp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), getResp.GetStatus().GetCode())

	// DELETE is denied with the rule's configured message.
	delResp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/datasets/ds-1", "DELETE",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.NotNil(t, delResp.GetDeniedResponse())
	assert.Contains(t, delResp.GetStatus().GetMessage(), "only GET is allowed for this service")
}

func TestServer_CELRule_BadExpressionDropped(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	// First rule has invalid CEL — that expression must be dropped from the
	// active set without blocking the second, valid rule.
	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name: "bad",
			CELRules: []controller.CELRule{
				{Name: "syntax", CEL: `this is not cel ((`, Message: "x"},
			},
		},
		{
			Name:          "good",
			RequiredScope: "read:datasets",
		},
	})

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)
	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/data", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	// Required scope check from the valid "good" rule still applies.
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
}

func TestServer_CELRule_BadCELPreservesNonCELChecks(t *testing.T) {
	// A single rule that mixes an invalid CEL expression with a non-CEL
	// constraint (RequiredScope) must not fail-open: the bad CEL is dropped
	// from the active set, but the rule itself stays so RequiredScope still
	// applies. Prior to the fix, the whole VerificationRule was dropped,
	// silently disabling scope enforcement on CEL compile errors.
	server, keyMgr := setupExtAuth(t)
	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name:          "mixed",
			RequiredScope: "write:datasets",
			CELRules: []controller.CELRule{
				{Name: "syntax", CEL: `this is not cel ((`, Message: "x"},
			},
		},
	})

	// defaultClaims().Scope is "read:datasets" — missing write:datasets.
	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)
	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/data", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.NotNil(t, resp.GetDeniedResponse(), "RequiredScope must still apply when sibling CEL fails to compile")
	assert.Contains(t, resp.GetStatus().GetMessage(), "write:datasets")
}

func TestServer_CELRule_PartialCompileKeepsValidExpressions(t *testing.T) {
	// One rule, two CEL expressions: one valid (allow), one syntactically
	// invalid. The valid expression must still evaluate; the bad one is
	// dropped at compile time. Request that satisfies the valid expression
	// should be allowed.
	server, keyMgr := setupExtAuth(t)
	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name: "partial",
			CELRules: []controller.CELRule{
				{Name: "bad", CEL: `this is not cel ((`, Message: "x"},
				{Name: "ok", CEL: `request.method == "GET"`, Message: "GET only"},
			},
		},
	})

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)
	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/data", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
}

func TestServer_DeniedResponse_JSONBodyEscaped(t *testing.T) {
	server, keyMgr := setupExtAuth(t)

	// Rule message contains double quotes — denied() must JSON-escape them
	// so the resulting Body is valid JSON.
	server.SetVerificationRules([]controller.VerificationRule{
		{
			Name: "quoted-msg",
			CELRules: []controller.CELRule{
				{
					Name:    "deny",
					CEL:     `false`,
					Message: `bad "input" rejected`,
				},
			},
		},
	})

	txToken := createTestToken(t, keyMgr, defaultClaims(), 15*time.Second)
	resp, err := server.Check(context.Background(), checkRequest(
		"/api/v1/data", "GET",
		map[string]string{"txn-token": txToken},
	))
	require.NoError(t, err)
	require.NotNil(t, resp.GetDeniedResponse())

	body := resp.GetDeniedResponse().GetBody()
	var decoded struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &decoded), "denied body must be valid JSON: %s", body)
	assert.Equal(t, "PermissionDenied", decoded.Error)
	assert.Contains(t, decoded.Message, `bad "input" rejected`)
}

func TestServer_VerificationRules_DeterministicOrder(t *testing.T) {
	// Two rules that both fail; the lexicographically-first by Namespace+Name
	// must always win, regardless of caller insertion order. Upstream rule
	// clients build snapshots from map iteration so insertion order is
	// non-deterministic — sorting in SetVerificationRules is what gives users
	// a stable denial message.
	in1 := []controller.VerificationRule{
		{Namespace: "ns-z", Name: "zeta", RequiredScope: "z-scope"},
		{Namespace: "ns-a", Name: "alpha", RequiredScope: "a-scope"},
	}
	in2 := []controller.VerificationRule{
		{Namespace: "ns-a", Name: "alpha", RequiredScope: "a-scope"},
		{Namespace: "ns-z", Name: "zeta", RequiredScope: "z-scope"},
	}

	for _, in := range [][]controller.VerificationRule{in1, in2} {
		server, keyMgr := setupExtAuth(t)
		server.SetVerificationRules(in)

		claims := defaultClaims()
		claims.Scope = "irrelevant" // misses both required scopes
		txToken := createTestToken(t, keyMgr, claims, 15*time.Second)

		resp, err := server.Check(context.Background(), checkRequest(
			"/api/v1/data", "GET",
			map[string]string{"txn-token": txToken},
		))
		require.NoError(t, err)
		assert.NotNil(t, resp.GetDeniedResponse())
		// ns-a / alpha sorts first, so its required scope wins the denial.
		assert.Contains(t, resp.GetStatus().GetMessage(), "a-scope")
		assert.Contains(t, resp.GetStatus().GetMessage(), "alpha")
	}
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
