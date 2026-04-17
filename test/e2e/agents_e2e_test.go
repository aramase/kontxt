//go:build agents_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	agentsClusterName = "kontxt-agents-e2e"
	agentsKubeContext = "kind-" + agentsClusterName
	demoNamespace     = "demo"
)

var agentsRepoRoot string

// TestMain for agent E2E tests — uses a separate build tag (agents_e2e)
// so it does not conflict with the core E2E TestMain (build tag: e2e).
func TestMain(m *testing.M) {
	if os.Getenv("KONTXT_AGENTS_E2E") != "1" {
		fmt.Println("Skipping agent E2E tests (set KONTXT_AGENTS_E2E=1 to run)")
		os.Exit(0)
	}

	if err := setupAgentsCluster(); err != nil {
		fmt.Fprintf(os.Stderr, "Agent E2E setup failed: %v\n", err)
		cleanupAgentsCluster()
		os.Exit(1)
	}

	code := m.Run()

	if os.Getenv("KONTXT_E2E_KEEP_CLUSTER") != "1" {
		cleanupAgentsCluster()
	}

	os.Exit(code)
}

func setupAgentsCluster() error {
	root, err := findRepoRootFromCwd()
	if err != nil {
		return fmt.Errorf("finding repo root: %w", err)
	}
	agentsRepoRoot = root

	out, _ := runCmdOutput("kind", "get", "clusters")
	if strings.Contains(out, agentsClusterName) {
		fmt.Println("Kind cluster already exists, reusing")
		return deployAgentsStack()
	}

	fmt.Println("Creating kind cluster...")
	if err := runCmdNoTest("kind", "create", "cluster", "--name", agentsClusterName, "--wait", "60s"); err != nil {
		return fmt.Errorf("creating kind cluster: %w", err)
	}

	images := []struct{ tag, dockerfile string }{
		{"kontxt-tts:latest", "cmd/tts/Dockerfile"},
		{"kontxt-extauth:latest", "cmd/extauth/Dockerfile"},
		{"kontxt-controller:latest", "cmd/controller/Dockerfile"},
		{"kontxt-mock-idp:latest", "examples/agents/mock-idp/Dockerfile"},
		{"kontxt-orchestrator:latest", "examples/agents/orchestrator/Dockerfile"},
		{"kontxt-retriever:latest", "examples/agents/retriever/Dockerfile"},
		{"kontxt-analyzer:latest", "examples/agents/analyzer/Dockerfile"},
	}

	fmt.Println("Building Docker images...")
	for _, img := range images {
		fmt.Printf("  Building %s...\n", img.tag)
		if err := runCmdNoTest("docker", "build", "-t", img.tag, "-f", filepath.Join(agentsRepoRoot, img.dockerfile), agentsRepoRoot); err != nil {
			return fmt.Errorf("building %s: %w", img.tag, err)
		}
	}

	fmt.Println("Loading images into kind...")
	for _, img := range images {
		if err := runCmdNoTest("kind", "load", "docker-image", img.tag, "--name", agentsClusterName); err != nil {
			return fmt.Errorf("loading %s: %w", img.tag, err)
		}
	}

	return deployAgentsStack()
}

func deployAgentsStack() error {
	agentsDir := filepath.Join(agentsRepoRoot, "examples/agents")
	prefix := imagePrefix()

	fmt.Println("Installing Gateway API CRDs...")
	if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "apply", "--server-side", "--force-conflicts",
		"-f", "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml"); err != nil {
		return fmt.Errorf("installing gateway API CRDs: %w", err)
	}

	fmt.Println("Installing AgentGateway...")
	if err := runCmdNoTest("helm", "upgrade", "-i", "agentgateway-crds",
		"oci://cr.agentgateway.dev/charts/agentgateway-crds",
		"--kube-context", agentsKubeContext,
		"--create-namespace", "--namespace", "agentgateway-system",
		"--version", "v1.0.1"); err != nil {
		return fmt.Errorf("installing agentgateway CRDs: %w", err)
	}
	if err := runCmdNoTest("helm", "upgrade", "-i", "agentgateway",
		"oci://cr.agentgateway.dev/charts/agentgateway",
		"--kube-context", agentsKubeContext,
		"--namespace", "agentgateway-system",
		"--version", "v1.0.1", "--wait"); err != nil {
		return fmt.Errorf("installing agentgateway: %w", err)
	}

	fmt.Println("Deploying demo services...")
	if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "apply",
		"-f", filepath.Join(agentsDir, "manifests/namespace.yaml")); err != nil {
		return fmt.Errorf("creating demo namespace: %w", err)
	}
	if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "apply",
		"-f", filepath.Join(agentsDir, "manifests/services.yaml")); err != nil {
		return fmt.Errorf("deploying demo services: %w", err)
	}

	// Patch image refs with runtime-specific prefix (Podman uses localhost/).
	if prefix != "" {
		for _, patch := range []struct{ deploy, container, image string }{
			{"mock-idp", "mock-idp", prefix + "kontxt-mock-idp:latest"},
			{"orchestrator", "orchestrator", prefix + "kontxt-orchestrator:latest"},
			{"retriever", "retriever", prefix + "kontxt-retriever:latest"},
			{"analyzer", "analyzer", prefix + "kontxt-analyzer:latest"},
		} {
			if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "-n", demoNamespace,
				"set", "image", "deployment/"+patch.deploy, patch.container+"="+patch.image); err != nil {
				return fmt.Errorf("patching %s image: %w", patch.deploy, err)
			}
		}
	}

	fmt.Println("Installing kontxt...")
	if err := runCmdNoTest("helm", "upgrade", "-i", "kontxt",
		filepath.Join(agentsRepoRoot, "deploy/helm/kontxt"),
		"--kube-context", agentsKubeContext,
		"--create-namespace", "--namespace", namespace,
		"-f", filepath.Join(agentsDir, "helm-values.yaml"),
		"--set", "tts.config.issuer=https://kontxt-tts.kontxt-system.svc.cluster.local",
		"--set", "tts.image.repository="+prefix+"kontxt-tts",
		"--set", "tts.image.pullPolicy=Never",
		"--set", "extauth.image.repository="+prefix+"kontxt-extauth",
		"--set", "extauth.image.pullPolicy=Never",
		"--set", "controller.image.repository="+prefix+"kontxt-controller",
		"--set", "controller.image.pullPolicy=Never",
		"--wait", "--timeout", "300s", "--debug"); err != nil {
		return fmt.Errorf("installing kontxt: %w", err)
	}

	fmt.Println("Applying kontxt CRD instances...")
	if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "apply",
		"-f", filepath.Join(agentsDir, "manifests/kontxt-platform.yaml")); err != nil {
		return fmt.Errorf("applying CRD instances: %w", err)
	}

	// Wait for the controller to reconcile CRDs before deploying ext-auth-generate.
	fmt.Println("Waiting for controller to reconcile CRDs...")
	time.Sleep(5 * time.Second)

	fmt.Println("Deploying ext auth generate adapter...")
	if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "apply",
		"-f", filepath.Join(agentsDir, "manifests/ext-auth-generate.yaml")); err != nil {
		return fmt.Errorf("deploying ext-auth-generate: %w", err)
	}
	if prefix != "" {
		if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "-n", namespace,
			"set", "image", "deployment/kontxt-extauth-generate", "extauth="+prefix+"kontxt-extauth:latest"); err != nil {
			return fmt.Errorf("patching ext-auth-generate image: %w", err)
		}
	}

	fmt.Println("Applying gateway and routing...")
	if err := runCmdNoTest("kubectl", "--context", agentsKubeContext, "apply",
		"-f", filepath.Join(agentsDir, "manifests/gateway.yaml")); err != nil {
		return fmt.Errorf("applying gateway: %w", err)
	}

	fmt.Println("Waiting for pods to be ready...")
	for _, d := range []string{"kontxt-tts", "kontxt-extauth", "kontxt-controller"} {
		if err := waitForAgentsDeployment(namespace, d, 120*time.Second); err != nil {
			return fmt.Errorf("waiting for %s: %w", d, err)
		}
	}
	for _, d := range []string{"mock-idp", "orchestrator", "retriever", "analyzer"} {
		if err := waitForAgentsDeployment(demoNamespace, d, 120*time.Second); err != nil {
			return fmt.Errorf("waiting for %s: %w", d, err)
		}
	}

	// Wait for ext-auth-generate — rules are streamed via gRPC on connect.
	if err := waitForAgentsDeployment(namespace, "kontxt-extauth-generate", 120*time.Second); err != nil {
		return fmt.Errorf("waiting for kontxt-extauth-generate: %w", err)
	}

	// Wait for gateway pod
	if err := waitForAgentsPod(demoNamespace, "gateway.networking.k8s.io/gateway-name=demo-gateway", 120*time.Second); err != nil {
		return fmt.Errorf("waiting for gateway pod: %w", err)
	}

	fmt.Println("Agent E2E setup complete")
	return nil
}

func cleanupAgentsCluster() {
	fmt.Println("Deleting agent E2E kind cluster...")
	runCmdNoTest("kind", "delete", "cluster", "--name", agentsClusterName)
}

func waitForAgentsDeployment(ns, name string, timeout time.Duration) error {
	return runCmdNoTest("kubectl", "--context", agentsKubeContext,
		"rollout", "status", "deployment/"+name, "-n", ns,
		"--timeout", fmt.Sprintf("%ds", int(timeout.Seconds())))
}

func waitForAgentsPod(ns, labelSelector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := runCmdOutput("kubectl", "--context", agentsKubeContext,
			"-n", ns, "get", "pods", "-l", labelSelector,
			"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
		if err == nil && strings.TrimSpace(out) == "True" {
			fmt.Printf("Pod with label %s is Ready\n", labelSelector)
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for pod with label %s", labelSelector)
}

// agentsPortForward starts a port-forward to a service and returns the local URL + cancel func.
func agentsPortForward(t *testing.T, ns, svcName string, remotePort int) (string, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "--context", agentsKubeContext,
		"-n", ns, "port-forward", "svc/"+svcName, fmt.Sprintf("0:%d", remotePort))

	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start port-forward to svc/%s: %v", svcName, err)
	}

	deadline := time.Now().Add(15 * time.Second)
	var localPort string
	for time.Now().Before(deadline) {
		output := outBuf.String()
		if idx := strings.Index(output, "127.0.0.1:"); idx >= 0 {
			rest := output[idx+len("127.0.0.1:"):]
			if spaceIdx := strings.IndexAny(rest, " \n\t->"); spaceIdx > 0 {
				localPort = rest[:spaceIdx]
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	if localPort == "" {
		cancel()
		t.Fatalf("failed to determine local port from port-forward output: %s", outBuf.String())
	}

	localURL := fmt.Sprintf("http://127.0.0.1:%s", localPort)
	t.Logf("Port-forward established: %s → svc/%s:%d", localURL, svcName, remotePort)
	return localURL, cancel
}

func agentsHTTPPost(t *testing.T, url, contentType, body string) (*http.Response, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, contentType, strings.NewReader(body))
	if err != nil {
		t.Fatalf("HTTP POST %s failed: %v", url, err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(respBody)
}

func agentsHTTPPostWithHeaders(t *testing.T, url, contentType, body string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP POST %s failed: %v", url, err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(respBody)
}

// === Tests ===

func TestAgentsE2E_PodsReady(t *testing.T) {
	out, err := runCmdOutput("kubectl", "--context", agentsKubeContext,
		"get", "pods", "-n", namespace, "-o", "jsonpath={range .items[*]}{.metadata.name} {.status.phase}\n{end}")
	if err != nil {
		t.Fatalf("failed to get kontxt-system pods: %v", err)
	}
	t.Logf("kontxt-system pods:\n%s", out)

	out, err = runCmdOutput("kubectl", "--context", agentsKubeContext,
		"get", "pods", "-n", demoNamespace, "-o", "jsonpath={range .items[*]}{.metadata.name} {.status.phase}\n{end}")
	if err != nil {
		t.Fatalf("failed to get demo pods: %v", err)
	}
	t.Logf("demo pods:\n%s", out)
}

func TestAgentsE2E_RulesStreamed(t *testing.T) {
	// Verify the controller has reconciled CRDs by checking TransactionType status.
	out, err := runCmdOutput("kubectl", "--context", agentsKubeContext,
		"get", "transactiontype", "earnings-research", "-n", "demo",
		"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
	if err != nil {
		t.Fatalf("failed to get TransactionType status: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Fatalf("TransactionType earnings-research not Ready, got: %s", out)
	}
	t.Log("TransactionType earnings-research is Ready")

	// Verify ServiceTokenRequirements are reconciled.
	for _, name := range []string{"retriever", "analyzer"} {
		out, err := runCmdOutput("kubectl", "--context", agentsKubeContext,
			"get", "servicetokenrequirement", name, "-n", "demo",
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		if err != nil {
			t.Fatalf("failed to get STR %s status: %v", name, err)
		}
		if strings.TrimSpace(out) != "True" {
			t.Fatalf("STR %s not Ready, got: %s", name, out)
		}
		t.Logf("ServiceTokenRequirement %s is Ready", name)
	}
}

func TestAgentsE2E_IdPToken(t *testing.T) {
	gwURL, cancel := agentsPortForward(t, demoNamespace, "demo-gateway", 80)
	defer cancel()

	resp, body := agentsHTTPPost(t, gwURL+"/idp/token",
		"application/json",
		`{"email":"alice@example.com","scope":"read:docs analyze:data"}`)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal([]byte(body), &tokenResp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if _, ok := tokenResp["access_token"]; !ok {
		t.Fatal("response missing access_token field")
	}
	t.Logf("Got access token (length %d)", len(tokenResp["access_token"].(string)))
}

func TestAgentsE2E_ResearchFlow(t *testing.T) {
	gwURL, cancel := agentsPortForward(t, demoNamespace, "demo-gateway", 80)
	defer cancel()

	accessToken := getAccessToken(t, gwURL)

	resp, body := agentsHTTPPostWithHeaders(t, gwURL+"/api/research",
		"application/json",
		`{"company":"ACME","period":"Q3-2024","question":"Summarize earnings"}`,
		map[string]string{"Authorization": "Bearer " + accessToken})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if result["company"] != "ACME" {
		t.Errorf("expected company=ACME, got %v", result["company"])
	}
	if result["period"] != "Q3-2024" {
		t.Errorf("expected period=Q3-2024, got %v", result["period"])
	}
	docs, ok := result["documents"].([]interface{})
	if !ok || len(docs) == 0 {
		t.Error("expected non-empty documents array")
	}
	if _, ok := result["analysis"]; !ok {
		t.Error("expected analysis field in response")
	}
	t.Logf("Research flow succeeded: %d documents, analysis present", len(docs))
}

func TestAgentsE2E_NoAuthToken(t *testing.T) {
	gwURL, cancel := agentsPortForward(t, demoNamespace, "demo-gateway", 80)
	defer cancel()

	resp, _ := agentsHTTPPostWithHeaders(t, gwURL+"/api/research",
		"application/json",
		`{"company":"ACME","period":"Q3-2024","question":"test"}`,
		nil)

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 401 or 403 without auth token, got %d", resp.StatusCode)
	}
}

func TestAgentsE2E_InvalidToken(t *testing.T) {
	gwURL, cancel := agentsPortForward(t, demoNamespace, "demo-gateway", 80)
	defer cancel()

	resp, _ := agentsHTTPPostWithHeaders(t, gwURL+"/api/research",
		"application/json",
		`{"company":"ACME","period":"Q3-2024","question":"test"}`,
		map[string]string{"Authorization": "Bearer invalidtoken"})

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 401 or 403 with invalid token, got %d", resp.StatusCode)
	}
}

func TestAgentsE2E_TxTokenCorrelation(t *testing.T) {
	gwURL, cancel := agentsPortForward(t, demoNamespace, "demo-gateway", 80)
	defer cancel()

	accessToken := getAccessToken(t, gwURL)

	resp, _ := agentsHTTPPostWithHeaders(t, gwURL+"/api/research",
		"application/json",
		`{"company":"ACME","period":"Q3-2024","question":"Correlation test"}`,
		map[string]string{"Authorization": "Bearer " + accessToken})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("research request failed with status %d", resp.StatusCode)
	}

	// Give logs a moment to flush
	time.Sleep(2 * time.Second)

	retrieverLogs, err := runCmdOutput("kubectl", "--context", agentsKubeContext,
		"logs", "-n", demoNamespace, "-l", "app=retriever", "--tail=5")
	if err != nil {
		t.Fatalf("failed to get retriever logs: %v", err)
	}

	analyzerLogs, err := runCmdOutput("kubectl", "--context", agentsKubeContext,
		"logs", "-n", demoNamespace, "-l", "app=analyzer", "--tail=5")
	if err != nil {
		t.Fatalf("failed to get analyzer logs: %v", err)
	}

	retrieverTxn := extractField(retrieverLogs, "txn=")
	analyzerTxn := extractField(analyzerLogs, "txn=")

	if retrieverTxn == "" {
		t.Fatal("no txn= found in retriever logs")
	}
	if analyzerTxn == "" {
		t.Fatal("no txn= found in analyzer logs")
	}
	if retrieverTxn != analyzerTxn {
		t.Errorf("txn mismatch: retriever=%s analyzer=%s", retrieverTxn, analyzerTxn)
	}
	t.Logf("TxToken correlation verified: txn=%s", retrieverTxn)

	if !strings.Contains(retrieverLogs, "sub=alice@example.com") {
		t.Error("retriever logs missing sub=alice@example.com")
	}
	if !strings.Contains(analyzerLogs, "sub=alice@example.com") {
		t.Error("analyzer logs missing sub=alice@example.com")
	}
}

// getAccessToken gets a mock IdP access token via the gateway.
func getAccessToken(t *testing.T, gwURL string) string {
	t.Helper()
	_, body := agentsHTTPPost(t, gwURL+"/idp/token",
		"application/json",
		`{"email":"alice@example.com","scope":"read:docs analyze:data"}`)
	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("failed to parse token response: %v", err)
	}
	token, ok := resp["access_token"].(string)
	if !ok || token == "" {
		t.Fatal("access_token missing from IdP response")
	}
	return token
}

// extractField extracts the value of a "key=value" field from log lines.
func extractField(logs, prefix string) string {
	for _, line := range strings.Split(logs, "\n") {
		if idx := strings.Index(line, prefix); idx >= 0 {
			rest := line[idx+len(prefix):]
			if spaceIdx := strings.IndexByte(rest, ' '); spaceIdx > 0 {
				return rest[:spaceIdx]
			}
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
