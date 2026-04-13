//go:build e2e || agents_e2e || agents_istio_e2e

package e2e

import (
	"bytes"
	"context"
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
	clusterName = "kontxt-e2e"
	namespace   = "kontxt-system"
)

var (
	repoRoot string
	ttsURL   string // set after port-forward
)

// imagePrefix returns "localhost/" when the container runtime is Podman,
// empty string for Docker. Podman stores locally-built images with a
// localhost/ prefix inside kind nodes; Docker does not.
func imagePrefix() string {
	out, err := runCmdOutput("docker", "version")
	if err == nil && strings.Contains(strings.ToLower(out), "podman") {
		return "localhost/"
	}
	return ""
}

// setupClusterForTestMain creates the kind cluster for TestMain (no *testing.T).
func setupClusterForTestMain() error {
	root, err := findRepoRootFromCwd()
	if err != nil {
		return fmt.Errorf("finding repo root: %w", err)
	}
	repoRoot = root

	// Check if cluster already exists
	out, _ := runCmdOutput("kind", "get", "clusters")
	if strings.Contains(out, clusterName) {
		fmt.Println("Kind cluster already exists, reusing")
		return nil
	}

	fmt.Println("Creating kind cluster...")
	if err := runCmdNoTest("kind", "create", "cluster", "--name", clusterName, "--wait", "60s"); err != nil {
		return fmt.Errorf("creating kind cluster: %w", err)
	}

	fmt.Println("Building Docker images...")
	if err := runCmdNoTest("docker", "build", "-t", "kontxt-tts:e2e", "-f", filepath.Join(repoRoot, "cmd/tts/Dockerfile"), repoRoot); err != nil {
		return fmt.Errorf("building TTS image: %w", err)
	}
	if err := runCmdNoTest("docker", "build", "-t", "kontxt-extauth:e2e", "-f", filepath.Join(repoRoot, "cmd/extauth/Dockerfile"), repoRoot); err != nil {
		return fmt.Errorf("building extauth image: %w", err)
	}
	if err := runCmdNoTest("docker", "build", "-t", "kontxt-controller:e2e", "-f", filepath.Join(repoRoot, "cmd/controller/Dockerfile"), repoRoot); err != nil {
		return fmt.Errorf("building controller image: %w", err)
	}

	fmt.Println("Loading images into kind...")
	for _, img := range []string{"kontxt-tts:e2e", "kontxt-extauth:e2e", "kontxt-controller:e2e"} {
		if err := runCmdNoTest("kind", "load", "docker-image", img, "--name", clusterName); err != nil {
			return fmt.Errorf("loading image %s: %w", img, err)
		}
	}

	fmt.Println("Creating namespace...")
	if err := runCmdNoTest("kubectl", "--context", "kind-"+clusterName, "create", "namespace", namespace); err != nil {
		return fmt.Errorf("creating namespace: %w", err)
	}

	fmt.Println("Applying CRDs...")
	if err := applyCRDsNoTest(); err != nil {
		return fmt.Errorf("applying CRDs: %w", err)
	}

	fmt.Println("Deploying TTS...")
	if err := runCmdNoTest("kubectl", "--context", "kind-"+clusterName, "apply", "-f", filepath.Join(repoRoot, "test/e2e/testdata/tts-deployment.yaml")); err != nil {
		return fmt.Errorf("deploying TTS: %w", err)
	}

	// Patch image with runtime-specific prefix (Podman uses localhost/).
	prefix := imagePrefix()
	if prefix != "" {
		if err := runCmdNoTest("kubectl", "--context", "kind-"+clusterName, "-n", namespace,
			"set", "image", "deployment/kontxt-tts", "tts="+prefix+"kontxt-tts:e2e"); err != nil {
			return fmt.Errorf("patching TTS image prefix: %w", err)
		}
	}

	fmt.Println("Waiting for TTS to be ready...")
	if err := waitForPodNoTest(namespace, "app.kubernetes.io/name=kontxt-tts", 120*time.Second); err != nil {
		return fmt.Errorf("waiting for TTS: %w", err)
	}

	fmt.Println("E2E setup complete")
	return nil
}

// cleanupCluster deletes the kind cluster (best-effort).
func cleanupCluster() {
	fmt.Println("Deleting kind cluster...")
	cmd := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

// applyCRDsNoTest applies CRDs without requiring *testing.T.
func applyCRDsNoTest() error {
	crdDir := filepath.Join(repoRoot, "test/e2e/testdata")
	entries, err := os.ReadDir(crdDir)
	if err != nil {
		return fmt.Errorf("reading CRD dir: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "kontxt.io_") && strings.HasSuffix(entry.Name(), ".yaml") {
			if err := runCmdNoTest("kubectl", "--context", "kind-"+clusterName, "apply", "-f", filepath.Join(crdDir, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// waitForPodNoTest waits for a pod to be Ready without *testing.T.
func waitForPodNoTest(ns, labelSelector string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := runCmdOutput("kubectl", "--context", "kind-"+clusterName,
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

// runCmdNoTest runs a command without *testing.T, returning an error on failure.
func runCmdNoTest(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// findRepoRootFromCwd finds the repo root without *testing.T.
func findRepoRootFromCwd() (string, error) {
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

// setupCluster creates a kind cluster — kept for backward compatibility but delegates to setupClusterForTestMain.
func setupCluster(t *testing.T) {
	t.Helper()
	if err := setupClusterForTestMain(); err != nil {
		t.Fatal(err)
	}
}

// applyCRDs applies the kontxt CRD definitions (requires *testing.T).
func applyCRDs(t *testing.T) {
	t.Helper()
	crdDir := filepath.Join(repoRoot, "test/e2e/testdata")
	// Apply all generated CRD YAML files
	entries, err := os.ReadDir(crdDir)
	if err != nil {
		t.Fatalf("failed to read CRD dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "kontxt.io_") && strings.HasSuffix(entry.Name(), ".yaml") {
			runCmd(t, "kubectl", "--context", "kind-"+clusterName, "apply", "-f", filepath.Join(crdDir, entry.Name()))
		}
	}
}

// deployTTS deploys the TTS as a simple pod+service (no Helm for simplicity in E2E).
func deployTTS(t *testing.T) {
	t.Helper()
	manifest := filepath.Join(repoRoot, "test/e2e/testdata/tts-deployment.yaml")
	runCmd(t, "kubectl", "--context", "kind-"+clusterName, "apply", "-f", manifest)
}

// waitForPod waits for a pod matching the label selector to be Ready.
func waitForPod(t *testing.T, ns, labelSelector string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := runCmdOutput("kubectl", "--context", "kind-"+clusterName,
			"-n", ns, "get", "pods", "-l", labelSelector,
			"-o", "jsonpath={.items[0].status.conditions[?(@.type=='Ready')].status}")
		if err == nil && strings.TrimSpace(out) == "True" {
			t.Logf("Pod with label %s is Ready", labelSelector)
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("Timed out waiting for pod with label %s to be Ready", labelSelector)
}

// portForward starts a port-forward to the TTS pod and returns the local URL.
func portForward(t *testing.T, ns, labelSelector string, remotePort int) (string, context.CancelFunc) {
	t.Helper()

	// Get the pod name
	podName, err := runCmdOutput("kubectl", "--context", "kind-"+clusterName,
		"-n", ns, "get", "pods", "-l", labelSelector,
		"-o", "jsonpath={.items[0].metadata.name}")
	if err != nil {
		t.Fatalf("Failed to get pod name: %v", err)
	}
	podName = strings.TrimSpace(podName)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "kubectl", "--context", "kind-"+clusterName,
		"-n", ns, "port-forward", podName, fmt.Sprintf("0:%d", remotePort))

	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("Failed to start port-forward: %v", err)
	}

	// Wait for port-forward to be ready (parse the local port from output)
	deadline := time.Now().Add(15 * time.Second)
	var localPort string
	for time.Now().Before(deadline) {
		output := outBuf.String()
		// kubectl outputs: "Forwarding from 127.0.0.1:XXXXX -> 8080"
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
		t.Fatalf("Failed to determine local port from port-forward output: %s", outBuf.String())
	}

	localURL := fmt.Sprintf("http://127.0.0.1:%s", localPort)
	t.Logf("Port-forward established: %s → %s:%d", localURL, podName, remotePort)

	return localURL, cancel
}

// httpGet sends a GET request and returns the response.
func httpGet(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("HTTP GET %s failed: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// runCmd runs a command and fails the test on error.
func runCmd(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("Command failed: %s %s: %v", name, strings.Join(args, " "), err)
	}
}

// runCmdOutput runs a command and returns stdout.
func runCmdOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}
	err := cmd.Run()
	return out.String(), err
}

// findRepoRoot walks up from CWD to find go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}
