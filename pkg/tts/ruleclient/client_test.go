package ruleclient

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	rulesv1 "github.com/aramase/kontxt/gen/kontxt/rules/v1"
	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/internal/controller/ruleserver"
)

// fakeSetter records SetIssuanceRules calls and signals on a channel.
type fakeSetter struct {
	mu      sync.Mutex
	calls   [][]controller.IssuanceRule
	failNth int // if > 0, return error on the Nth call (1-indexed)
	ch      chan struct{}
}

func newFakeSetter() *fakeSetter {
	return &fakeSetter{ch: make(chan struct{}, 64)}
}

func (f *fakeSetter) SetIssuanceRules(rules []controller.IssuanceRule) error {
	f.mu.Lock()
	f.calls = append(f.calls, rules)
	n := len(f.calls)
	f.mu.Unlock()
	f.ch <- struct{}{}
	if f.failNth > 0 && n == f.failNth {
		return assert.AnError
	}
	return nil
}

func (f *fakeSetter) waitCall(t *testing.T, timeout time.Duration) []controller.IssuanceRule {
	t.Helper()
	select {
	case <-f.ch:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for SetIssuanceRules call")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

// startTestServer starts a ruleserver on a random port and returns it plus a
// shutdown helper.
func startTestServer(t *testing.T) (*ruleserver.RuleServer, string, func()) {
	t.Helper()
	rs := ruleserver.NewRuleServer()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gs := grpc.NewServer()
	rulesv1.RegisterRuleDiscoveryServiceServer(gs, rs)
	go gs.Serve(lis)

	cleanup := func() { gs.Stop() }
	return rs, lis.Addr().String(), cleanup
}

func TestRuleClient_InitialSnapshotApplied(t *testing.T) {
	rs, addr, cleanup := startTestServer(t)
	defer cleanup()

	rs.UpdateIssuanceRules([]controller.IssuanceRule{
		{PolicyName: "p1", RuleName: "r1", CEL: "true", Message: "ok",
			TargetNamespaces: []string{"team-alpha"}},
	})

	setter := newFakeSetter()
	c := NewRuleClient(addr, setter, grpc.WithTransportCredentials(insecure.NewCredentials()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	got := setter.waitCall(t, 3*time.Second)
	require.Len(t, got, 1)
	assert.Equal(t, "p1", got[0].PolicyName)
	assert.Equal(t, "r1", got[0].RuleName)
	assert.Equal(t, []string{"team-alpha"}, got[0].TargetNamespaces)
	// Ready() flips to true strictly after SetIssuanceRules returns, so the
	// waitCall channel can fire before c.synced has been stored. Poll briefly.
	assert.Eventually(t, c.Ready, time.Second, 5*time.Millisecond)
}

func TestRuleClient_DeltaUpsertAndRemove(t *testing.T) {
	rs, addr, cleanup := startTestServer(t)
	defer cleanup()

	setter := newFakeSetter()
	c := NewRuleClient(addr, setter, grpc.WithTransportCredentials(insecure.NewCredentials()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// Initial empty snapshot.
	got := setter.waitCall(t, 3*time.Second)
	assert.Empty(t, got)

	rs.UpsertIssuanceRule(controller.IssuanceRule{PolicyName: "p1", RuleName: "r1", CEL: "true", Message: "m"})
	got = setter.waitCall(t, 3*time.Second)
	require.Len(t, got, 1)
	assert.Equal(t, "r1", got[0].RuleName)

	rs.UpsertIssuanceRule(controller.IssuanceRule{PolicyName: "p1", RuleName: "r2", CEL: "true", Message: "m"})
	got = setter.waitCall(t, 3*time.Second)
	require.Len(t, got, 2)

	// RemoveIssuanceRule drops every rule sourced from policy p1, so both rules disappear.
	rs.RemoveIssuanceRule("", "p1")
	got = setter.waitCall(t, 3*time.Second)
	assert.Empty(t, got)
}

func TestRuleClient_SetterErrorKeepsSyncedFalseOnFirstCall(t *testing.T) {
	rs, addr, cleanup := startTestServer(t)
	defer cleanup()

	rs.UpdateIssuanceRules([]controller.IssuanceRule{
		{PolicyName: "p1", RuleName: "r1", CEL: "true", Message: "m"},
	})

	setter := newFakeSetter()
	setter.failNth = 1
	c := NewRuleClient(addr, setter, grpc.WithTransportCredentials(insecure.NewCredentials()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	_ = setter.waitCall(t, 3*time.Second)
	// First call failed -> still not ready, previous rules preserved.
	assert.False(t, c.Ready())

	// Push an update; the second SetIssuanceRules call succeeds and the client becomes ready.
	rs.UpsertIssuanceRule(controller.IssuanceRule{PolicyName: "p1", RuleName: "r2", CEL: "true", Message: "m2"})
	_ = setter.waitCall(t, 3*time.Second)
	assert.Eventually(t, c.Ready, time.Second, 5*time.Millisecond)
}

// TestRuleClient_DeterministicRuleOrder asserts that the slice handed to the
// setter is sorted by (PolicyNamespace, PolicyName, RuleName) regardless of
// the order in which the controller streams upserts. EvaluateIssuanceRules
// returns the first denial, so non-deterministic ordering would make the
// `policy_denied` error message flap across equivalent rule sets.
func TestRuleClient_DeterministicRuleOrder(t *testing.T) {
	rs, addr, cleanup := startTestServer(t)
	defer cleanup()

	setter := newFakeSetter()
	c := NewRuleClient(addr, setter, grpc.WithTransportCredentials(insecure.NewCredentials()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// Empty initial snapshot.
	_ = setter.waitCall(t, 3*time.Second)

	// Push rules in deliberately scrambled order spanning multiple policies.
	upserts := []controller.IssuanceRule{
		{PolicyName: "policy-b", RuleName: "rule-2", CEL: "true", Message: "m"},
		{PolicyName: "policy-a", RuleName: "rule-2", CEL: "true", Message: "m"},
		{PolicyName: "policy-b", RuleName: "rule-1", CEL: "true", Message: "m"},
		{PolicyName: "policy-a", RuleName: "rule-1", CEL: "true", Message: "m"},
	}
	var final []controller.IssuanceRule
	for _, r := range upserts {
		rs.UpsertIssuanceRule(r)
		final = setter.waitCall(t, 3*time.Second)
	}
	require.Len(t, final, 4)

	want := []string{"policy-a/rule-1", "policy-a/rule-2", "policy-b/rule-1", "policy-b/rule-2"}
	got := make([]string, len(final))
	for i, r := range final {
		got[i] = r.PolicyName + "/" + r.RuleName
	}
	assert.Equal(t, want, got, "ruleclient must hand rules to the setter in deterministic sort order")
}
