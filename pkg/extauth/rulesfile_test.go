package extauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/api/v1alpha1"
	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/sdk/verify"
)

func TestRulesLoader_LoadOnce_GenerationRules(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.json")

	rules := []controller.GenerationRule{
		{
			Namespace: "default",
			Name:      "test-transaction",
			Endpoint:  v1alpha1.EndpointSpec{Path: "/api/test", Method: "POST"},
			Purpose:   "test-purpose",
			Scope:     "read:data",
		},
	}
	writeRulesJSON(t, rulesFile, rules)

	loader := NewRulesLoader(rulesFile, "generate")
	genServer := NewGenerationServer(nil, nil)
	loader.SetGenerationServer(genServer)

	err := loader.LoadOnce()
	require.NoError(t, err)

	assert.Len(t, genServer.generationRules, 1)
	assert.Equal(t, "test-purpose", genServer.generationRules[0].Purpose)
	assert.Equal(t, "/api/test", genServer.generationRules[0].Endpoint.Path)
}

func TestRulesLoader_LoadOnce_VerificationRules(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.json")

	rules := []controller.VerificationRule{
		{
			Namespace:          "default",
			Name:               "test-str",
			ServiceName:        "my-service",
			RequiredScope:      "read:data",
			RequiredTctxFields: []string{"datasetId"},
			ExcludedEndpoints: []v1alpha1.EndpointSpec{
				{Path: "/healthz", Method: "GET"},
			},
		},
	}
	writeRulesJSON(t, rulesFile, rules)

	loader := NewRulesLoader(rulesFile, "verify")
	verifier := verify.New("http://localhost:8080/.well-known/jwks.json", "test.example.com")
	verifyServer := NewServer(verifier)
	loader.SetVerifyServer(verifyServer)

	err := loader.LoadOnce()
	require.NoError(t, err)

	assert.Len(t, verifyServer.verificationRules, 1)
	assert.Equal(t, "read:data", verifyServer.verificationRules[0].RequiredScope)
	assert.Equal(t, []string{"datasetId"}, verifyServer.verificationRules[0].RequiredTctxFields)
}

func TestRulesLoader_LoadOnce_FileNotExist(t *testing.T) {
	loader := NewRulesLoader("/nonexistent/rules.json", "verify")

	err := loader.LoadOnce()
	require.NoError(t, err, "missing file should not be an error")
}

func TestRulesLoader_LoadOnce_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.json")
	require.NoError(t, os.WriteFile(rulesFile, []byte("not json"), 0644))

	loader := NewRulesLoader(rulesFile, "verify")
	verifier := verify.New("http://localhost:8080/.well-known/jwks.json", "test.example.com")
	loader.SetVerifyServer(NewServer(verifier))

	err := loader.LoadOnce()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing verification rules")
}

func TestRulesLoader_LoadOnce_UnknownMode(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.json")
	require.NoError(t, os.WriteFile(rulesFile, []byte("[]"), 0644))

	loader := NewRulesLoader(rulesFile, "bogus")
	err := loader.LoadOnce()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown mode")
}

func TestRulesLoader_WatchAndReload(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.json")

	// Start with one rule
	rules := []controller.VerificationRule{
		{
			Namespace:   "default",
			Name:        "rule-1",
			ServiceName: "svc-1",
		},
	}
	writeRulesJSON(t, rulesFile, rules)

	loader := NewRulesLoader(rulesFile, "verify")
	verifier := verify.New("http://localhost:8080/.well-known/jwks.json", "test.example.com")
	verifyServer := NewServer(verifier)
	loader.SetVerifyServer(verifyServer)

	require.NoError(t, loader.LoadOnce())
	assert.Len(t, verifyServer.verificationRules, 1)

	// Set up a reload signal
	var reloadWg sync.WaitGroup
	reloadWg.Add(1)
	loader.onReloadForTest = func() {
		reloadWg.Done()
	}

	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- loader.WatchAndReload(done)
	}()

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	// Update the file with two rules
	rules = []controller.VerificationRule{
		{Namespace: "default", Name: "rule-1", ServiceName: "svc-1"},
		{Namespace: "default", Name: "rule-2", ServiceName: "svc-2"},
	}
	writeRulesJSON(t, rulesFile, rules)

	// Wait for reload with timeout
	waitDone := make(chan struct{})
	go func() {
		reloadWg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for rules reload")
	}

	assert.Len(t, verifyServer.verificationRules, 2)

	close(done)
	require.NoError(t, <-errCh)
}

func writeRulesJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0644))
}
