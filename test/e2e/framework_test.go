//go:build e2e

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
	repoRoot  string
	ttsURL    string // set after port-forward
)

// setupCluster creates a kind cluster, builds images, and deploys kontxt.
func setupCluster(t *testing.T) {
	t.Helper()

	repoRoot = findRepoRoot(t)

	t.Log("Creating kind cluster...")
	runCmd(t, "kind", "create", "cluster", "--name", clusterName, "--wait", "60s")

	t.Log("Building Docker images...")
	runCmd(t, "docker", "build", "-t", "kontxt-tts:e2e", "-f", filepath.Join(repoRoot, "cmd/tts/Dockerfile"), repoRoot)
	runCmd(t, "docker", "build", "-t", "kontxt-extauth:e2e", "-f", filepath.Join(repoRoot, "cmd/extauth/Dockerfile"), repoRoot)
	runCmd(t, "docker", "build", "-t", "kontxt-controller:e2e", "-f", filepath.Join(repoRoot, "cmd/controller/Dockerfile"), repoRoot)

	t.Log("Loading images into kind...")
	runCmd(t, "kind", "load", "docker-image", "kontxt-tts:e2e", "--name", clusterName)
	runCmd(t, "kind", "load", "docker-image", "kontxt-extauth:e2e", "--name", clusterName)
	runCmd(t, "kind", "load", "docker-image", "kontxt-controller:e2e", "--name", clusterName)

	t.Log("Creating namespace...")
	runCmd(t, "kubectl", "--context", "kind-"+clusterName, "create", "namespace", namespace)

	t.Log("Applying CRDs...")
	applyCRDs(t)

	t.Log("Deploying TTS...")
	deployTTS(t)

	t.Log("Waiting for TTS to be ready...")
	waitForPod(t, namespace, "app.kubernetes.io/name=kontxt-tts", 120*time.Second)
}

// teardownCluster deletes the kind cluster.
func teardownCluster(t *testing.T) {
	t.Helper()
	t.Log("Deleting kind cluster...")
	cmd := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run() // best-effort, don't fail on cleanup
}

// applyCRDs applies the kontxt CRD definitions.
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
