//go:build agents_istio_e2e

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
	istioClusterName = "kontxt-istio-e2e"
	istioKubeContext = "kind-" + istioClusterName
	istioDemoNS      = "demo"
	istioSystemNS    = "istio-system"
	istioGatewaySvc  = "demo-gateway"
)

var istioRepoRoot string

// TestMain for Istio agent E2E tests — uses build tag agents_istio_e2e.
func TestMain(m *testing.M) {
	if os.Getenv("KONTXT_ISTIO_E2E") != "1" {
		fmt.Println("Skipping Istio agent E2E tests (set KONTXT_ISTIO_E2E=1 to run)")
		os.Exit(0)
	}

	if err := setupIstioCluster(); err != nil {
		fmt.Fprintf(os.Stderr, "Istio E2E setup failed: %v\n", err)
		cleanupIstioCluster()
		os.Exit(1)
	}

	code := m.Run()

	if os.Getenv("KONTXT_E2E_KEEP_CLUSTER") != "1" {
		cleanupIstioCluster()
	}

	os.Exit(code)
}

func setupIstioCluster() error {
	root, err := findIstioRepoRoot()
	if err != nil {
		return fmt.Errorf("finding repo root: %w", err)
	}
	istioRepoRoot = root

	out, _ := runIstioCmd("kind", "get", "clusters")
	if strings.Contains(out, istioClusterName) {
		fmt.Println("Kind cluster already exists, reusing")
		return deployIstioStack()
	}

	fmt.Println("Creating kind cluster...")
	kindConfig := filepath.Join(istioRepoRoot, "examples/agents-istio/kind-config.yaml")
	if err := runIstioCmdNoOutput("kind", "create", "cluster", "--name", istioClusterName, "--config", kindConfig, "--wait", "120s"); err != nil {
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
		if err := runIstioCmdNoOutput("docker", "build", "-t", img.tag, "-f", filepath.Join(istioRepoRoot, img.dockerfile), istioRepoRoot); err != nil {
			return fmt.Errorf("building %s: %w", img.tag, err)
		}
	}

	fmt.Println("Loading images into kind...")
	for _, img := range images {
		if err := runIstioCmdNoOutput("kind", "load", "docker-image", img.tag, "--name", istioClusterName); err != nil {
			return fmt.Errorf("loading %s: %w", img.tag, err)
		}
	}

	return deployIstioStack()
}

func deployIstioStack() error {
	istioDir := filepath.Join(istioRepoRoot, "examples/agents-istio")
	prefix := istioImagePrefix()

	// Install Gateway API experimental CRDs (required for ExternalAuth filter).
	gatewayAPIVersion := os.Getenv("GATEWAY_API_VERSION")
	if gatewayAPIVersion == "" {
		gatewayAPIVersion = "v1.5.0"
	}
	fmt.Printf("Installing Gateway API experimental CRDs (%s)...\n", gatewayAPIVersion)
	if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "apply", "--server-side", "--force-conflicts",
		"-f", fmt.Sprintf("https://github.com/kubernetes-sigs/gateway-api/releases/download/%s/experimental-install.yaml", gatewayAPIVersion)); err != nil {
		return fmt.Errorf("installing gateway API experimental CRDs: %w", err)
	}

	// Install Istio with AGENTGATEWAY feature flag.
	fmt.Println("Installing Istio with AGENTGATEWAY feature flag...")
	if err := installIstioForTest(); err != nil {
		return fmt.Errorf("installing Istio: %w", err)
	}

	// Wait for istiod.
	fmt.Println("Waiting for istiod...")
	if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext,
		"rollout", "status", "deployment/istiod", "-n", istioSystemNS, "--timeout=120s"); err != nil {
		return fmt.Errorf("waiting for istiod: %w", err)
	}

	// Wait for ztunnel (ambient mode daemonset).
	fmt.Println("Waiting for ztunnel...")
	if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext,
		"rollout", "status", "daemonset/ztunnel", "-n", istioSystemNS, "--timeout=120s"); err != nil {
		return fmt.Errorf("waiting for ztunnel: %w", err)
	}

	fmt.Println("Deploying demo services...")
	if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "apply",
		"-f", filepath.Join(istioDir, "manifests/namespace.yaml")); err != nil {
		return fmt.Errorf("creating demo namespace: %w", err)
	}
	if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "apply",
		"-f", filepath.Join(istioDir, "manifests/services.yaml")); err != nil {
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
			if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", istioDemoNS,
				"set", "image", "deployment/"+patch.deploy, patch.container+"="+patch.image); err != nil {
				return fmt.Errorf("patching %s image: %w", patch.deploy, err)
			}
		}
	}

	fmt.Println("Installing kontxt with istio.enabled=true...")
	if err := runIstioCmdNoOutput("helm", "upgrade", "-i", "kontxt",
		filepath.Join(istioRepoRoot, "deploy/helm/kontxt"),
		"--kube-context", istioKubeContext,
		"--create-namespace", "--namespace", namespace,
		"-f", filepath.Join(istioDir, "helm-values.yaml"),
		"--set", "tts.config.issuer=https://kontxt-tts.kontxt-system.svc.cluster.local",
		"--set", "tts.image.repository="+prefix+"kontxt-tts",
		"--set", "tts.image.tag=latest",
		"--set", "tts.image.pullPolicy=Never",
		"--set", "extauth.image.repository="+prefix+"kontxt-extauth",
		"--set", "extauth.image.tag=latest",
		"--set", "extauth.image.pullPolicy=Never",
		"--set", "controller.image.repository="+prefix+"kontxt-controller",
		"--set", "controller.image.tag=latest",
		"--set", "controller.image.pullPolicy=Never",
		"--set", "istio.enabled=true",
		"--wait", "--timeout", "300s", "--debug"); err != nil {
		// Dump diagnostic info for debugging.
		fmt.Println("=== kontxt helm install failed, dumping diagnostics ===")
		fmt.Println("--- Pods in", namespace, "---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", namespace, "get", "pods", "-o", "wide")
		fmt.Println("--- Describe pods in", namespace, "---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", namespace, "describe", "pods")
		fmt.Println("--- Events in", namespace, "---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", namespace, "get", "events", "--sort-by=.lastTimestamp")
		fmt.Println("--- Pod logs in", namespace, "---")
		for _, d := range []string{"kontxt-controller", "kontxt-extauth", "kontxt-tts"} {
			fmt.Printf("--- Logs for %s ---\n", d)
			runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", namespace, "logs", "-l", "app.kubernetes.io/name="+d, "--all-containers", "--tail=50")
		}
		fmt.Println("=== end diagnostics ===")
		return fmt.Errorf("installing kontxt: %w", err)
	}

	fmt.Println("Applying kontxt CRD instances...")
	if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "apply",
		"-f", filepath.Join(istioDir, "manifests/kontxt-platform.yaml")); err != nil {
		return fmt.Errorf("applying CRD instances: %w", err)
	}

	// Wait for the controller to reconcile CRDs.
	fmt.Println("Waiting for controller to reconcile CRDs...")
	for _, res := range []struct{ kind, name string }{
		{"transactiontype", "earnings-research"},
		{"servicetokenrequirement", "retriever"},
		{"servicetokenrequirement", "analyzer"},
	} {
		if err := waitForIstioCondition(istioDemoNS, res.kind, res.name, "Ready", 60*time.Second); err != nil {
			return fmt.Errorf("waiting for %s/%s to be Ready: %w", res.kind, res.name, err)
		}
	}

	fmt.Println("Applying gateway and ExternalAuth routes...")
	if err := runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "apply",
		"-f", filepath.Join(istioDir, "manifests/gateway.yaml")); err != nil {
		return fmt.Errorf("applying gateway: %w", err)
	}

	fmt.Println("Waiting for pods to be ready...")
	for _, d := range []string{"kontxt-tts", "kontxt-extauth", "kontxt-controller"} {
		if err := waitForIstioDeployment(namespace, d, 120*time.Second); err != nil {
			return fmt.Errorf("waiting for %s: %w", d, err)
		}
	}
	for _, d := range []string{"mock-idp", "orchestrator", "retriever", "analyzer"} {
		if err := waitForIstioDeployment(istioDemoNS, d, 120*time.Second); err != nil {
			return fmt.Errorf("waiting for %s: %w", d, err)
		}
	}

	if err := waitForIstioDeployment(namespace, "kontxt-extauth-generate", 120*time.Second); err != nil {
		return fmt.Errorf("waiting for kontxt-extauth-generate: %w", err)
	}

	// Wait for gateway pod.
	if err := waitForIstioPod(istioDemoNS, "gateway.networking.k8s.io/gateway-name=demo-gateway", 120*time.Second); err != nil {
		fmt.Println("=== gateway pod wait failed, dumping diagnostics ===")
		fmt.Println("--- Gateway status ---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", istioDemoNS, "get", "gateway", "demo-gateway", "-o", "yaml")
		fmt.Println("--- GatewayClass ---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "get", "gatewayclass", "-o", "wide")
		fmt.Println("--- Pods in", istioDemoNS, "---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", istioDemoNS, "get", "pods", "-o", "wide")
		fmt.Println("--- Events in", istioDemoNS, "---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", istioDemoNS, "get", "events", "--sort-by=.lastTimestamp")
		fmt.Println("--- istiod logs (last 50) ---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", istioSystemNS, "logs", "-l", "app=istiod", "--tail=50")
		fmt.Println("=== end gateway diagnostics ===")
		return fmt.Errorf("waiting for gateway pod: %w", err)
	}

	// Wait for the gateway listener to be programmed by istiod.
	fmt.Println("Waiting for gateway listener to be programmed...")
	if err := waitForGatewayListenerProgrammed(istioDemoNS, "demo-gateway", 120*time.Second); err != nil {
		fmt.Println("=== gateway listener not programmed, dumping diagnostics ===")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", istioDemoNS, "get", "gateway", "demo-gateway", "-o", "yaml")
		fmt.Println("--- istiod logs (last 50) ---")
		runIstioCmdNoOutput("kubectl", "--context", istioKubeContext, "-n", istioSystemNS, "logs", "-l", "app=istiod", "--tail=50")
		fmt.Println("=== end diagnostics ===")
		return fmt.Errorf("waiting for gateway listener to be programmed: %w", err)
	}

	fmt.Println("Istio agent E2E setup complete")
	return nil
}

func installIstioForTest() error {
	if _, err := exec.LookPath("istioctl"); err != nil {
		return fmt.Errorf("istioctl not found. Install istioctl 1.30+ from https://istio.io/latest/docs/setup/getting-started/#download")
	}

	args := []string{"install", "--context", istioKubeContext, "-y",
		"--set", "profile=ambient",
		"--set", "values.pilot.env.PILOT_ENABLE_AGENTGATEWAY=true",
		"--set", "meshConfig.accessLogFile=/dev/stdout",
	}
	// Allow overriding the image hub (e.g. for alternate registries).
	hub := os.Getenv("ISTIO_HUB")
	if hub != "" {
		args = append(args, "--set", "hub="+hub)
	}
	return runIstioCmdNoOutput("istioctl", args...)
}

func cleanupIstioCluster() {
	fmt.Println("Deleting Istio E2E kind cluster...")
	runIstioCmdNoOutput("kind", "delete", "cluster", "--name", istioClusterName)
}

func waitForIstioDeployment(ns, name string, timeout time.Duration) error {
	return runIstioCmdNoOutput("kubectl", "--context", istioKubeContext,
		"rollout", "status", "deployment/"+name, "-n", ns,
		"--timeout", fmt.Sprintf("%ds", int(timeout.Seconds())))
}

func waitForIstioPod(ns, labelSelector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := runIstioCmd("kubectl", "--context", istioKubeContext,
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

func waitForIstioCondition(ns, kind, name, conditionType string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := runIstioCmd("kubectl", "--context", istioKubeContext,
			"-n", ns, "get", kind, name,
			"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", conditionType))
		if err == nil && strings.TrimSpace(out) == "True" {
			fmt.Printf("%s/%s is %s\n", kind, name, conditionType)
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %s/%s condition %s", kind, name, conditionType)
}

func waitForGatewayListenerProgrammed(ns, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := runIstioCmd("kubectl", "--context", istioKubeContext,
			"-n", ns, "get", "gateway", name,
			"-o", "jsonpath={.status.listeners[0].conditions[?(@.type=='Programmed')].status}")
		if err == nil && strings.TrimSpace(out) == "True" {
			fmt.Printf("Gateway %s listener is Programmed\n", name)
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for gateway %s listener to be Programmed", name)
}

// istioPortForward starts a port-forward to a service and returns the local URL + cancel func.
func istioPortForward(t *testing.T, ns, svcName string, remotePort int) (string, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "--context", istioKubeContext,
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

func istioHTTPPost(t *testing.T, url, contentType, body string) (*http.Response, string) {
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

func istioHTTPPostWithHeaders(t *testing.T, url, contentType, body string, headers map[string]string) (*http.Response, string) {
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

func TestIstioE2E_PodsReady(t *testing.T) {
	// Verify istiod is running.
	out, err := runIstioCmd("kubectl", "--context", istioKubeContext,
		"get", "pods", "-n", istioSystemNS, "-o", "jsonpath={range .items[*]}{.metadata.name} {.status.phase}\n{end}")
	if err != nil {
		t.Fatalf("failed to get istio-system pods: %v", err)
	}
	t.Logf("istio-system pods:\n%s", out)

	out, err = runIstioCmd("kubectl", "--context", istioKubeContext,
		"get", "pods", "-n", namespace, "-o", "jsonpath={range .items[*]}{.metadata.name} {.status.phase}\n{end}")
	if err != nil {
		t.Fatalf("failed to get kontxt-system pods: %v", err)
	}
	t.Logf("kontxt-system pods:\n%s", out)

	out, err = runIstioCmd("kubectl", "--context", istioKubeContext,
		"get", "pods", "-n", istioDemoNS, "-o", "jsonpath={range .items[*]}{.metadata.name} {.status.phase}\n{end}")
	if err != nil {
		t.Fatalf("failed to get demo pods: %v", err)
	}
	t.Logf("demo pods:\n%s", out)
}

func TestIstioE2E_GatewayReady(t *testing.T) {
	// Verify the Gateway resource is accepted and programmed.
	out, err := runIstioCmd("kubectl", "--context", istioKubeContext,
		"get", "gateway", "demo-gateway", "-n", istioDemoNS,
		"-o", "jsonpath={.status.conditions[?(@.type=='Accepted')].status}")
	if err != nil {
		t.Fatalf("failed to get gateway status: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Fatalf("Gateway not Accepted, got: %s", out)
	}
	t.Log("Gateway demo-gateway is Accepted")

	out, err = runIstioCmd("kubectl", "--context", istioKubeContext,
		"get", "gateway", "demo-gateway", "-n", istioDemoNS,
		"-o", "jsonpath={.status.listeners[0].conditions[?(@.type=='Programmed')].status}")
	if err != nil {
		t.Fatalf("failed to get gateway programmed status: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Fatalf("Gateway listener not Programmed, got: %s", out)
	}
	t.Log("Gateway demo-gateway listener is Programmed by istiod")
}

func TestIstioE2E_RulesStreamed(t *testing.T) {
	out, err := runIstioCmd("kubectl", "--context", istioKubeContext,
		"get", "transactiontype", "earnings-research", "-n", istioDemoNS,
		"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
	if err != nil {
		t.Fatalf("failed to get TransactionType status: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Fatalf("TransactionType earnings-research not Ready, got: %s", out)
	}
	t.Log("TransactionType earnings-research is Ready")

	for _, name := range []string{"retriever", "analyzer"} {
		out, err := runIstioCmd("kubectl", "--context", istioKubeContext,
			"get", "servicetokenrequirement", name, "-n", istioDemoNS,
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

func TestIstioE2E_IdPToken(t *testing.T) {
	gwURL, cancel := istioPortForward(t, istioDemoNS, istioGatewaySvc, 80)
	defer cancel()

	resp, body := istioHTTPPost(t, gwURL+"/idp/token",
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

func TestIstioE2E_ResearchFlow(t *testing.T) {
	gwURL, cancel := istioPortForward(t, istioDemoNS, istioGatewaySvc, 80)
	defer cancel()

	accessToken := istioGetAccessToken(t, gwURL)

	resp, body := istioHTTPPostWithHeaders(t, gwURL+"/api/research",
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

func TestIstioE2E_NoAuthToken(t *testing.T) {
	gwURL, cancel := istioPortForward(t, istioDemoNS, istioGatewaySvc, 80)
	defer cancel()

	resp, _ := istioHTTPPostWithHeaders(t, gwURL+"/api/research",
		"application/json",
		`{"company":"ACME","period":"Q3-2024","question":"test"}`,
		nil)

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 401 or 403 without auth token, got %d", resp.StatusCode)
	}
}

func TestIstioE2E_InvalidToken(t *testing.T) {
	gwURL, cancel := istioPortForward(t, istioDemoNS, istioGatewaySvc, 80)
	defer cancel()

	resp, _ := istioHTTPPostWithHeaders(t, gwURL+"/api/research",
		"application/json",
		`{"company":"ACME","period":"Q3-2024","question":"test"}`,
		map[string]string{"Authorization": "Bearer invalidtoken"})

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 401 or 403 with invalid token, got %d", resp.StatusCode)
	}
}

func TestIstioE2E_TxTokenCorrelation(t *testing.T) {
	gwURL, cancel := istioPortForward(t, istioDemoNS, istioGatewaySvc, 80)
	defer cancel()

	accessToken := istioGetAccessToken(t, gwURL)

	resp, _ := istioHTTPPostWithHeaders(t, gwURL+"/api/research",
		"application/json",
		`{"company":"ACME","period":"Q3-2024","question":"Correlation test"}`,
		map[string]string{"Authorization": "Bearer " + accessToken})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("research request failed with status %d", resp.StatusCode)
	}

	// Give logs a moment to flush.
	time.Sleep(2 * time.Second)

	retrieverLogs, err := runIstioCmd("kubectl", "--context", istioKubeContext,
		"logs", "-n", istioDemoNS, "-l", "app=retriever", "--tail=5")
	if err != nil {
		t.Fatalf("failed to get retriever logs: %v", err)
	}

	analyzerLogs, err := runIstioCmd("kubectl", "--context", istioKubeContext,
		"logs", "-n", istioDemoNS, "-l", "app=analyzer", "--tail=5")
	if err != nil {
		t.Fatalf("failed to get analyzer logs: %v", err)
	}

	retrieverTxn := istioExtractField(retrieverLogs, "txn=")
	analyzerTxn := istioExtractField(analyzerLogs, "txn=")

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

// === Helpers ===

func istioGetAccessToken(t *testing.T, gwURL string) string {
	t.Helper()
	_, body := istioHTTPPost(t, gwURL+"/idp/token",
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

func istioExtractField(logs, prefix string) string {
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

func istioImagePrefix() string {
	out, err := runIstioCmd("docker", "version")
	if err == nil && strings.Contains(strings.ToLower(out), "podman") {
		return "localhost/"
	}
	return ""
}

func findIstioRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repo root (go.mod)")
		}
		dir = parent
	}
}

func runIstioCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func runIstioCmdNoOutput(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
