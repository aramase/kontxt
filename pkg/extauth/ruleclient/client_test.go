package ruleclient

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aramase/kontxt/api/v1alpha1"
	rulesv1 "github.com/aramase/kontxt/gen/kontxt/rules/v1"
	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/internal/controller/ruleserver"
)

// fakeGenSetter records generation rules calls for testing.
type fakeGenSetter struct {
	mu    sync.Mutex
	calls [][]controller.GenerationRule
	ch    chan struct{} // signaled after each call
}

func newFakeGenSetter() *fakeGenSetter {
	return &fakeGenSetter{ch: make(chan struct{}, 64)}
}

func (f *fakeGenSetter) SetGenerationRules(rules []controller.GenerationRule) {
	f.mu.Lock()
	f.calls = append(f.calls, rules)
	f.mu.Unlock()
	f.ch <- struct{}{}
}

func (f *fakeGenSetter) waitCall(t *testing.T, timeout time.Duration) []controller.GenerationRule {
	t.Helper()
	select {
	case <-f.ch:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for SetGenerationRules call")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// fakeVerSetter records verification rules calls for testing.
type fakeVerSetter struct {
	mu    sync.Mutex
	calls [][]controller.VerificationRule
	ch    chan struct{}
}

func newFakeVerSetter() *fakeVerSetter {
	return &fakeVerSetter{ch: make(chan struct{}, 64)}
}

func (f *fakeVerSetter) SetVerificationRules(rules []controller.VerificationRule) {
	f.mu.Lock()
	f.calls = append(f.calls, rules)
	f.mu.Unlock()
	f.ch <- struct{}{}
}

func (f *fakeVerSetter) waitCall(t *testing.T, timeout time.Duration) []controller.VerificationRule {
	t.Helper()
	select {
	case <-f.ch:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for SetVerificationRules call")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// startRuleServer creates a ruleserver.RuleServer, registers it with a gRPC server
// on a random port, and returns the server, address, and a cleanup function.
func startRuleServer(t *testing.T) (*ruleserver.RuleServer, string, func()) {
	t.Helper()
	rs := ruleserver.NewRuleServer()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gs := grpc.NewServer()
	rulesv1.RegisterRuleDiscoveryServiceServer(gs, rs)
	go gs.Serve(lis)

	cleanup := func() {
		gs.Stop()
	}
	return rs, lis.Addr().String(), cleanup
}

func TestConnect_ReceivesSnapshot(t *testing.T) {
	rs, addr, cleanup := startRuleServer(t)
	defer cleanup()

	// Seed rules before client connects.
	rs.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "ns1", Name: "rule1", Purpose: "test", Scope: "read"},
	})

	genSetter := newFakeGenSetter()
	verSetter := newFakeVerSetter()

	client := NewRuleClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	client.SetGenerationSetter(genSetter)
	client.SetVerificationSetter(verSetter)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go client.Run(ctx)

	// Should receive the generation snapshot.
	rules := genSetter.waitCall(t, 3*time.Second)
	require.Len(t, rules, 1)
	assert.Equal(t, "ns1", rules[0].Namespace)
	assert.Equal(t, "rule1", rules[0].Name)
	assert.Equal(t, "test", rules[0].Purpose)
	assert.Equal(t, "read", rules[0].Scope)

	// Also expect initial empty verification snapshot.
	verRules := verSetter.waitCall(t, 3*time.Second)
	assert.Empty(t, verRules)
}

func TestApplyGenerationRules_FullFields(t *testing.T) {
	rs, addr, cleanup := startRuleServer(t)
	defer cleanup()

	rs.UpdateGenerationRules([]controller.GenerationRule{
		{
			Namespace: "team-alpha",
			Name:      "analyze-dataset",
			Endpoint: v1alpha1.EndpointSpec{
				Path:   "/api/v1/datasets/{datasetId}/analyze",
				Method: "POST",
			},
			Purpose: "dataset-analysis",
			Scope:   "read:datasets execute:analysis",
			TctxMapping: map[string]v1alpha1.TctxFieldMapping{
				"datasetId": {Source: "path", Field: "datasetId", Required: true},
			},
			TctxEnrichments: []v1alpha1.TctxEnrichment{
				{Field: "classification", Enricher: "dataset-classifier"},
			},
			RctxFields:    []string{"req_ip", "authn"},
			TokenLifetime: "30s",
		},
	})

	genSetter := newFakeGenSetter()
	client := NewRuleClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	client.SetGenerationSetter(genSetter)
	client.SetVerificationSetter(newFakeVerSetter())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go client.Run(ctx)

	rules := genSetter.waitCall(t, 3*time.Second)
	require.Len(t, rules, 1)
	r := rules[0]
	assert.Equal(t, "team-alpha", r.Namespace)
	assert.Equal(t, "/api/v1/datasets/{datasetId}/analyze", r.Endpoint.Path)
	assert.Equal(t, "POST", r.Endpoint.Method)
	assert.Equal(t, "dataset-analysis", r.Purpose)
	assert.Equal(t, "read:datasets execute:analysis", r.Scope)

	require.Contains(t, r.TctxMapping, "datasetId")
	assert.Equal(t, "path", r.TctxMapping["datasetId"].Source)
	assert.True(t, r.TctxMapping["datasetId"].Required)

	require.Len(t, r.TctxEnrichments, 1)
	assert.Equal(t, "classification", r.TctxEnrichments[0].Field)
	assert.Equal(t, "dataset-classifier", r.TctxEnrichments[0].Enricher)

	assert.Equal(t, []string{"req_ip", "authn"}, r.RctxFields)
	assert.Equal(t, "30s", r.TokenLifetime)
}

func TestApplyVerificationRules(t *testing.T) {
	rs, addr, cleanup := startRuleServer(t)
	defer cleanup()

	rs.UpdateVerificationRules([]controller.VerificationRule{
		{
			Namespace:          "ns1",
			Name:               "ver-rule1",
			ServiceName:        "my-svc",
			RequiredScope:      "read:data",
			RequiredTctxFields: []string{"datasetId"},
			CELRules: []controller.CELRule{
				{Name: "check1", CEL: "txtoken.tctx.datasetId != ''", Message: "datasetId required"},
			},
			ExcludedEndpoints: []v1alpha1.EndpointSpec{
				{Path: "/healthz", Method: "GET"},
			},
			AutoNarrow: true,
		},
	})

	verSetter := newFakeVerSetter()
	client := NewRuleClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	client.SetGenerationSetter(newFakeGenSetter())
	client.SetVerificationSetter(verSetter)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go client.Run(ctx)

	rules := verSetter.waitCall(t, 3*time.Second)
	require.Len(t, rules, 1)
	r := rules[0]
	assert.Equal(t, "ns1", r.Namespace)
	assert.Equal(t, "ver-rule1", r.Name)
	assert.Equal(t, "my-svc", r.ServiceName)
	assert.Equal(t, "read:data", r.RequiredScope)
	assert.Equal(t, []string{"datasetId"}, r.RequiredTctxFields)
	require.Len(t, r.CELRules, 1)
	assert.Equal(t, "check1", r.CELRules[0].Name)
	require.Len(t, r.ExcludedEndpoints, 1)
	assert.Equal(t, "/healthz", r.ExcludedEndpoints[0].Path)
	assert.True(t, r.AutoNarrow)
}

func TestDelta_UpsertAndRemove(t *testing.T) {
	rs, addr, cleanup := startRuleServer(t)
	defer cleanup()

	genSetter := newFakeGenSetter()
	client := NewRuleClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	client.SetGenerationSetter(genSetter)
	client.SetVerificationSetter(newFakeVerSetter())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go client.Run(ctx)

	// Initial empty snapshot.
	rules := genSetter.waitCall(t, 3*time.Second)
	assert.Empty(t, rules)

	// Upsert a rule via delta.
	rs.UpsertGenerationRule(controller.GenerationRule{
		Namespace: "ns1", Name: "rule1", Purpose: "delta-test",
	})

	rules = genSetter.waitCall(t, 3*time.Second)
	require.Len(t, rules, 1)
	assert.Equal(t, "delta-test", rules[0].Purpose)

	// Upsert another rule.
	rs.UpsertGenerationRule(controller.GenerationRule{
		Namespace: "ns1", Name: "rule2", Purpose: "delta-test-2",
	})

	rules = genSetter.waitCall(t, 3*time.Second)
	require.Len(t, rules, 2)

	// Remove first rule.
	rs.RemoveGenerationRule("ns1", "rule1")

	rules = genSetter.waitCall(t, 3*time.Second)
	require.Len(t, rules, 1)
	assert.Equal(t, "rule2", rules[0].Name)
}

func TestReconnect_OnServerRestart(t *testing.T) {
	rs, addr, cleanup := startRuleServer(t)

	genSetter := newFakeGenSetter()
	client := NewRuleClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	client.SetGenerationSetter(genSetter)
	client.SetVerificationSetter(newFakeVerSetter())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go client.Run(ctx)

	// Get initial empty snapshot.
	genSetter.waitCall(t, 3*time.Second)

	// Stop the server.
	cleanup()

	// Start a new server on the same address.
	lis, err := net.Listen("tcp", addr)
	require.NoError(t, err)

	rs2 := ruleserver.NewRuleServer()
	rs2.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "new", Name: "after-restart"},
	})
	_ = rs

	gs2 := grpc.NewServer()
	rulesv1.RegisterRuleDiscoveryServiceServer(gs2, rs2)
	go gs2.Serve(lis)
	defer gs2.Stop()

	// Client should reconnect and receive the new snapshot.
	rules := genSetter.waitCall(t, 10*time.Second)
	require.Len(t, rules, 1)
	assert.Equal(t, "after-restart", rules[0].Name)
}

func TestContext_Cancellation(t *testing.T) {
	_, addr, cleanup := startRuleServer(t)
	defer cleanup()

	client := NewRuleClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	client.SetGenerationSetter(newFakeGenSetter())
	client.SetVerificationSetter(newFakeVerSetter())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx)
	}()

	// Let client connect.
	time.Sleep(500 * time.Millisecond)

	// Cancel context -- Run should return.
	cancel()

	select {
	case err := <-done:
		// context.Canceled is expected.
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("client.Run did not return after context cancellation")
	}
}

func TestConcurrentUpdates(t *testing.T) {
	rs, addr, cleanup := startRuleServer(t)
	defer cleanup()

	genSetter := newFakeGenSetter()
	client := NewRuleClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	client.SetGenerationSetter(genSetter)
	client.SetVerificationSetter(newFakeVerSetter())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go client.Run(ctx)

	// Drain initial empty snapshot.
	genSetter.waitCall(t, 3*time.Second)

	// Fire concurrent updates.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rs.UpdateGenerationRules([]controller.GenerationRule{
				{Namespace: "ns", Name: fmt.Sprintf("rule-%d", idx)},
			})
		}(i)
	}
	wg.Wait()

	// Drain -- client should receive at least one update without panicking.
	var lastRules []controller.GenerationRule
	for {
		select {
		case <-genSetter.ch:
			genSetter.mu.Lock()
			lastRules = genSetter.calls[len(genSetter.calls)-1]
			genSetter.mu.Unlock()
		case <-time.After(2 * time.Second):
			require.Len(t, lastRules, 1)
			return
		}
	}
}
