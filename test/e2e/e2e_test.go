//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/token"
)

func TestMain(m *testing.M) {
	// Only run E2E tests when explicitly requested
	if os.Getenv("KONTXT_E2E") != "1" {
		fmt.Println("Skipping E2E tests (set KONTXT_E2E=1 to run)")
		os.Exit(0)
	}

	// Run tests
	code := m.Run()
	os.Exit(code)
}

// TestE2E_ClusterSetup creates the kind cluster and deploys kontxt.
// This must run first — other tests depend on the cluster being ready.
func TestE2E_ClusterSetup(t *testing.T) {
	// Check if cluster already exists (for iterative development)
	if _, err := runCmdOutput("kind", "get", "clusters"); err == nil {
		out, _ := runCmdOutput("kind", "get", "clusters")
		if strings.Contains(out, clusterName) {
			t.Log("Cluster already exists, skipping setup")
			return
		}
	}

	setupCluster(t)
	t.Cleanup(func() {
		if os.Getenv("KONTXT_E2E_KEEP_CLUSTER") != "1" {
			teardownCluster(t)
		}
	})
}

func TestE2E_TTSHealthCheck(t *testing.T) {
	ensureCluster(t)

	localURL, cancel := portForward(t, namespace, "app.kubernetes.io/name=kontxt-tts", 8080)
	defer cancel()

	// Give port-forward a moment to stabilize
	time.Sleep(1 * time.Second)

	resp, body := httpGet(t, localURL+"/healthz")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", body)
}

func TestE2E_JWKSEndpoint(t *testing.T) {
	ensureCluster(t)

	localURL, cancel := portForward(t, namespace, "app.kubernetes.io/name=kontxt-tts", 8080)
	defer cancel()
	time.Sleep(1 * time.Second)

	resp, body := httpGet(t, localURL+"/.well-known/jwks.json")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse JWKS
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	err := json.Unmarshal([]byte(body), &jwks)
	require.NoError(t, err)
	require.NotEmpty(t, jwks.Keys, "JWKS should have at least one key")

	key := jwks.Keys[0]
	assert.Equal(t, "RSA", key.Kty)
	assert.Equal(t, "RS256", key.Alg)
	assert.Equal(t, "sig", key.Use)
	assert.NotEmpty(t, key.Kid)
}

func TestE2E_CRDsInstalled(t *testing.T) {
	ensureCluster(t)

	// Verify CRDs are installed
	out, err := runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"get", "crd", "txtokenconfigs.kontxt.io", "-o", "name")
	require.NoError(t, err)
	assert.Contains(t, out, "txtokenconfigs.kontxt.io")

	out, err = runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"get", "crd", "transactiontypes.kontxt.io", "-o", "name")
	require.NoError(t, err)
	assert.Contains(t, out, "transactiontypes.kontxt.io")

	out, err = runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"get", "crd", "servicetokenrequirements.kontxt.io", "-o", "name")
	require.NoError(t, err)
	assert.Contains(t, out, "servicetokenrequirements.kontxt.io")

	out, err = runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"get", "crd", "tokenpolicies.kontxt.io", "-o", "name")
	require.NoError(t, err)
	assert.Contains(t, out, "tokenpolicies.kontxt.io")
}

func TestE2E_TokenExchange(t *testing.T) {
	ensureCluster(t)

	localURL, cancel := portForward(t, namespace, "app.kubernetes.io/name=kontxt-tts", 8080)
	defer cancel()
	time.Sleep(1 * time.Second)

	// The TTS is deployed with no subject token authenticators (empty list),
	// so we can't do a real OIDC token exchange. But we can verify the endpoint
	// rejects requests properly.
	params := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":       {"test-token"},
		"subject_token_type":  {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":               {"read:data"},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(localURL+"/token_endpoint", params)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should get 401 since we have no configured authenticators
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"should reject token when no authenticators are configured")

	var errResp struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&errResp)
	assert.NotEmpty(t, errResp.Error)
}

func TestE2E_TokenFormat(t *testing.T) {
	ensureCluster(t)

	localURL, cancel := portForward(t, namespace, "app.kubernetes.io/name=kontxt-tts", 8080)
	defer cancel()
	time.Sleep(1 * time.Second)

	// Verify the JWKS keys can be fetched and parsed for token verification
	resp, body := httpGet(t, localURL+"/.well-known/jwks.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &jwks))
	require.NotEmpty(t, jwks.Keys)

	// Verify each key is valid JSON with required fields
	for _, keyJSON := range jwks.Keys {
		var key map[string]any
		require.NoError(t, json.Unmarshal(keyJSON, &key))
		assert.Contains(t, key, "kty")
		assert.Contains(t, key, "kid")
		assert.Contains(t, key, "n")
		assert.Contains(t, key, "e")
	}
}

func TestE2E_CRDCanBeCreated(t *testing.T) {
	ensureCluster(t)

	// Create a TransactionType CRD instance
	tt := `
apiVersion: kontxt.io/v1alpha1
kind: TransactionType
metadata:
  name: e2e-test-transaction
  namespace: kontxt-system
spec:
  endpoint:
    path: "/api/v1/test"
    method: "POST"
  purpose: "e2e-test"
  scope: "read:data"
  tokenLifetime: "15s"
`
	cmd := fmt.Sprintf("echo '%s' | kubectl --context kind-%s apply -f -", tt, clusterName)
	out, err := runCmdOutput("bash", "-c", cmd)
	require.NoError(t, err, "failed to create TransactionType: %s", out)

	// Verify it was created
	out, err = runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"-n", namespace, "get", "transactiontype", "e2e-test-transaction", "-o", "jsonpath={.spec.purpose}")
	require.NoError(t, err)
	assert.Equal(t, "e2e-test", strings.TrimSpace(out))

	// Cleanup
	runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"-n", namespace, "delete", "transactiontype", "e2e-test-transaction")
}

func TestE2E_ServiceTokenRequirementCanBeCreated(t *testing.T) {
	ensureCluster(t)

	str := `
apiVersion: kontxt.io/v1alpha1
kind: ServiceTokenRequirement
metadata:
  name: e2e-test-str
  namespace: kontxt-system
spec:
  serviceRef:
    name: test-service
  verification:
    requiredScope: "read:data"
    requiredTctxFields:
      - "datasetId"
  excludedEndpoints:
    - path: "/healthz"
      method: "GET"
`
	cmd := fmt.Sprintf("echo '%s' | kubectl --context kind-%s apply -f -", str, clusterName)
	out, err := runCmdOutput("bash", "-c", cmd)
	require.NoError(t, err, "failed to create ServiceTokenRequirement: %s", out)

	out, err = runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"-n", namespace, "get", "servicetokenrequirement", "e2e-test-str",
		"-o", "jsonpath={.spec.serviceRef.name}")
	require.NoError(t, err)
	assert.Equal(t, "test-service", strings.TrimSpace(out))

	// Cleanup
	runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"-n", namespace, "delete", "servicetokenrequirement", "e2e-test-str")
}

func TestE2E_TokenPolicyCanBeCreated(t *testing.T) {
	ensureCluster(t)

	tp := `
apiVersion: kontxt.io/v1alpha1
kind: TokenPolicy
metadata:
  name: e2e-test-policy
spec:
  constraints:
    maxTokenLifetime: "60s"
    mandatoryTctxFields:
      - "purpose"
`
	cmd := fmt.Sprintf("echo '%s' | kubectl --context kind-%s apply -f -", tp, clusterName)
	out, err := runCmdOutput("bash", "-c", cmd)
	require.NoError(t, err, "failed to create TokenPolicy: %s", out)

	out, err = runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"get", "tokenpolicy", "e2e-test-policy",
		"-o", "jsonpath={.spec.constraints.maxTokenLifetime}")
	require.NoError(t, err)
	assert.Equal(t, "60s", strings.TrimSpace(out))

	// Cleanup
	runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"delete", "tokenpolicy", "e2e-test-policy")
}

// ensureCluster verifies the kind cluster exists and kontxt is deployed.
func ensureCluster(t *testing.T) {
	t.Helper()
	out, err := runCmdOutput("kind", "get", "clusters")
	if err != nil || !strings.Contains(out, clusterName) {
		t.Skip("kind cluster not available, run TestE2E_ClusterSetup first")
	}
}

// Ensure unused imports are recognized
var _ = jwt.MapClaims{}
