package ruleserver

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
)

// startTestServer creates a RuleServer, registers it with a gRPC server on a
// random port, and returns the server, client connection, and a cleanup function.
func startTestServer(t *testing.T) (*RuleServer, *grpc.ClientConn, func()) {
	t.Helper()

	rs := NewRuleServer()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	gs := grpc.NewServer()
	rulesv1.RegisterRuleDiscoveryServiceServer(gs, rs)

	go gs.Serve(lis)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	cleanup := func() {
		conn.Close()
		gs.Stop()
	}

	return rs, conn, cleanup
}

// recvGenResponse reads a single generation response with a timeout.
func recvGenResponse(t *testing.T, stream rulesv1.RuleDiscoveryService_StreamGenerationRulesClient, timeout time.Duration) *rulesv1.StreamGenerationRulesResponse {
	t.Helper()
	type result struct {
		resp *rulesv1.StreamGenerationRulesResponse
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := stream.Recv()
		ch <- result{resp, err}
	}()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.resp
	case <-time.After(timeout):
		t.Fatal("timed out waiting for generation rules response")
		return nil
	}
}

// recvVerResponse reads a single verification response with a timeout.
func recvVerResponse(t *testing.T, stream rulesv1.RuleDiscoveryService_StreamVerificationRulesClient, timeout time.Duration) *rulesv1.StreamVerificationRulesResponse {
	t.Helper()
	type result struct {
		resp *rulesv1.StreamVerificationRulesResponse
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := stream.Recv()
		ch <- result{resp, err}
	}()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.resp
	case <-time.After(timeout):
		t.Fatal("timed out waiting for verification rules response")
		return nil
	}
}

func TestNewServer(t *testing.T) {
	rs := NewRuleServer()
	require.NotNil(t, rs)
}

func TestStreamGenerationRules_InitialSnapshot(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	// Seed with rules before connecting.
	rs.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "ns1", Name: "rule1", Purpose: "test", Scope: "read"},
	})

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)

	// Send initial request.
	require.NoError(t, stream.Send(&rulesv1.StreamGenerationRulesRequest{}))

	resp := recvGenResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetSnapshot())
	require.Len(t, resp.GetSnapshot().GetRules(), 1)
	assert.Equal(t, "ns1", resp.GetSnapshot().GetRules()[0].GetNamespace())
	assert.Equal(t, "rule1", resp.GetSnapshot().GetRules()[0].GetName())
	assert.Equal(t, "test", resp.GetSnapshot().GetRules()[0].GetPurpose())
	assert.NotEmpty(t, resp.GetVersionInfo())
}

func TestStreamGenerationRules_EmptyInitialSnapshot(t *testing.T) {
	_, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamGenerationRulesRequest{}))

	resp := recvGenResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetSnapshot())
	assert.Empty(t, resp.GetSnapshot().GetRules())
}

func TestStreamGenerationRules_UpdateTriggersSnapshot(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamGenerationRulesRequest{}))

	// Consume initial empty snapshot.
	_ = recvGenResponse(t, stream, 3*time.Second)

	// Push an update.
	rs.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "ns2", Name: "rule2", Purpose: "updated"},
	})

	resp := recvGenResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetSnapshot())
	require.Len(t, resp.GetSnapshot().GetRules(), 1)
	assert.Equal(t, "rule2", resp.GetSnapshot().GetRules()[0].GetName())
}

func TestStreamGenerationRules_Delta(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamGenerationRulesRequest{}))

	// Consume initial empty snapshot.
	_ = recvGenResponse(t, stream, 3*time.Second)

	// Upsert a rule.
	rs.UpsertGenerationRule(controller.GenerationRule{
		Namespace: "ns1", Name: "rule1", Purpose: "delta-test",
	})

	resp := recvGenResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetDelta())
	require.Len(t, resp.GetDelta().GetUpserted(), 1)
	assert.Equal(t, "delta-test", resp.GetDelta().GetUpserted()[0].GetPurpose())
	assert.Empty(t, resp.GetDelta().GetRemoved())

	// Remove the rule.
	rs.RemoveGenerationRule("ns1", "rule1")

	resp = recvGenResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetDelta())
	assert.Empty(t, resp.GetDelta().GetUpserted())
	require.Len(t, resp.GetDelta().GetRemoved(), 1)
	assert.Equal(t, "ns1", resp.GetDelta().GetRemoved()[0].GetNamespace())
	assert.Equal(t, "rule1", resp.GetDelta().GetRemoved()[0].GetName())
}

func TestStreamGenerationRules_MultipleClients(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect two clients.
	stream1, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream1.Send(&rulesv1.StreamGenerationRulesRequest{}))

	stream2, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream2.Send(&rulesv1.StreamGenerationRulesRequest{}))

	// Consume initial snapshots.
	_ = recvGenResponse(t, stream1, 3*time.Second)
	_ = recvGenResponse(t, stream2, 3*time.Second)

	// Push an update — both clients should receive it.
	rs.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "shared", Name: "broadcast"},
	})

	resp1 := recvGenResponse(t, stream1, 3*time.Second)
	resp2 := recvGenResponse(t, stream2, 3*time.Second)

	require.Len(t, resp1.GetSnapshot().GetRules(), 1)
	require.Len(t, resp2.GetSnapshot().GetRules(), 1)
	assert.Equal(t, "broadcast", resp1.GetSnapshot().GetRules()[0].GetName())
	assert.Equal(t, "broadcast", resp2.GetSnapshot().GetRules()[0].GetName())
}

func TestStreamGenerationRules_ClientDisconnect(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)

	// Client 1 connects then disconnects.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	stream1, err := client.StreamGenerationRules(ctx1)
	require.NoError(t, err)
	require.NoError(t, stream1.Send(&rulesv1.StreamGenerationRulesRequest{}))
	_ = recvGenResponse(t, stream1, 3*time.Second)
	cancel1() // disconnect client 1

	// Client 2 remains connected.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	stream2, err := client.StreamGenerationRules(ctx2)
	require.NoError(t, err)
	require.NoError(t, stream2.Send(&rulesv1.StreamGenerationRulesRequest{}))
	_ = recvGenResponse(t, stream2, 3*time.Second)

	// Small delay for server to process disconnect.
	time.Sleep(100 * time.Millisecond)

	// Server should not panic — push an update.
	rs.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "still-alive", Name: "ok"},
	})

	// Client 2 should receive the update.
	resp := recvGenResponse(t, stream2, 3*time.Second)
	require.Len(t, resp.GetSnapshot().GetRules(), 1)
	assert.Equal(t, "ok", resp.GetSnapshot().GetRules()[0].GetName())
}

func TestStreamGenerationRules_Reconnect(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)

	// First connection.
	ctx1, cancel1 := context.WithCancel(context.Background())
	stream1, err := client.StreamGenerationRules(ctx1)
	require.NoError(t, err)
	require.NoError(t, stream1.Send(&rulesv1.StreamGenerationRulesRequest{}))
	_ = recvGenResponse(t, stream1, 3*time.Second)
	cancel1()

	// Update rules while disconnected.
	rs.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "reconnect", Name: "new-data"},
	})

	// Reconnect — should get a fresh snapshot.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	stream2, err := client.StreamGenerationRules(ctx2)
	require.NoError(t, err)
	require.NoError(t, stream2.Send(&rulesv1.StreamGenerationRulesRequest{}))

	resp := recvGenResponse(t, stream2, 3*time.Second)
	require.NotNil(t, resp.GetSnapshot())
	require.Len(t, resp.GetSnapshot().GetRules(), 1)
	assert.Equal(t, "new-data", resp.GetSnapshot().GetRules()[0].GetName())
}

func TestStreamVerificationRules_InitialSnapshot(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
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
			AutoNarrow: true,
		},
	})

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamVerificationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamVerificationRulesRequest{}))

	resp := recvVerResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetSnapshot())
	require.Len(t, resp.GetSnapshot().GetRules(), 1)

	rule := resp.GetSnapshot().GetRules()[0]
	assert.Equal(t, "ns1", rule.GetNamespace())
	assert.Equal(t, "ver-rule1", rule.GetName())
	assert.Equal(t, "my-svc", rule.GetServiceName())
	assert.Equal(t, "read:data", rule.GetRequiredScope())
	assert.Equal(t, []string{"datasetId"}, rule.GetRequiredTctxFields())
	require.Len(t, rule.GetCelRules(), 1)
	assert.Equal(t, "check1", rule.GetCelRules()[0].GetName())
	assert.True(t, rule.GetAutoNarrow())
}

func TestStreamVerificationRules_Delta(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamVerificationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamVerificationRulesRequest{}))
	_ = recvVerResponse(t, stream, 3*time.Second) // initial empty

	// Upsert.
	rs.UpsertVerificationRule(controller.VerificationRule{
		Namespace: "ns1", Name: "ver1", ServiceName: "svc1",
	})

	resp := recvVerResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetDelta())
	require.Len(t, resp.GetDelta().GetUpserted(), 1)
	assert.Equal(t, "svc1", resp.GetDelta().GetUpserted()[0].GetServiceName())

	// Remove.
	rs.RemoveVerificationRule("ns1", "ver1")

	resp = recvVerResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetDelta())
	require.Len(t, resp.GetDelta().GetRemoved(), 1)
	assert.Equal(t, "ver1", resp.GetDelta().GetRemoved()[0].GetName())
}

func TestVersionTracking(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamGenerationRulesRequest{}))

	resp1 := recvGenResponse(t, stream, 3*time.Second)
	v1 := resp1.GetVersionInfo()
	require.NotEmpty(t, v1)

	rs.UpdateGenerationRules([]controller.GenerationRule{
		{Namespace: "ns1", Name: "r1"},
	})

	resp2 := recvGenResponse(t, stream, 3*time.Second)
	v2 := resp2.GetVersionInfo()
	require.NotEmpty(t, v2)
	assert.NotEqual(t, v1, v2, "version should increment on update")
}

func TestStreamGenerationRules_FullRoundTrip(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	// Seed with a complex rule to verify all field conversions.
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

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamGenerationRulesRequest{}))

	resp := recvGenResponse(t, stream, 3*time.Second)
	require.Len(t, resp.GetSnapshot().GetRules(), 1)

	rule := resp.GetSnapshot().GetRules()[0]
	assert.Equal(t, "team-alpha", rule.GetNamespace())
	assert.Equal(t, "analyze-dataset", rule.GetName())
	assert.Equal(t, "/api/v1/datasets/{datasetId}/analyze", rule.GetEndpoint().GetPath())
	assert.Equal(t, "POST", rule.GetEndpoint().GetMethod())
	assert.Equal(t, "dataset-analysis", rule.GetPurpose())
	assert.Equal(t, "read:datasets execute:analysis", rule.GetScope())

	mapping := rule.GetTctxMapping()
	require.Contains(t, mapping, "datasetId")
	assert.Equal(t, "path", mapping["datasetId"].GetSource())
	assert.Equal(t, "datasetId", mapping["datasetId"].GetField())
	assert.True(t, mapping["datasetId"].GetRequired())

	require.Len(t, rule.GetTctxEnrichments(), 1)
	assert.Equal(t, "classification", rule.GetTctxEnrichments()[0].GetField())
	assert.Equal(t, "dataset-classifier", rule.GetTctxEnrichments()[0].GetEnricher())

	assert.Equal(t, []string{"req_ip", "authn"}, rule.GetRctxFields())
	assert.Equal(t, "30s", rule.GetTokenLifetime())
}

func TestStreamGenerationRules_ConcurrentUpdates(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.StreamGenerationRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamGenerationRulesRequest{}))
	_ = recvGenResponse(t, stream, 3*time.Second) // initial

	// Fire 10 concurrent updates.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rs.UpdateGenerationRules([]controller.GenerationRule{
				{Namespace: "ns", Name: fmt.Sprintf("rule-%d", idx)},
			})
		}(i)
	}
	wg.Wait()

	// Drain all responses — we should get at least 1, up to 10.
	var received int
	for {
		type result struct {
			resp *rulesv1.StreamGenerationRulesResponse
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			resp, err := stream.Recv()
			ch <- result{resp, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("unexpected error: %v", r.err)
			}
			received++
			if received >= 10 {
				return
			}
		case <-time.After(2 * time.Second):
			// No more messages; that's fine as long as we got at least 1.
			require.GreaterOrEqual(t, received, 1)
			return
		}
	}
}

// recvIssResponse reads a single issuance response with a timeout.
func recvIssResponse(t *testing.T, stream rulesv1.RuleDiscoveryService_StreamIssuanceRulesClient, timeout time.Duration) *rulesv1.StreamIssuanceRulesResponse {
	t.Helper()
	type result struct {
		resp *rulesv1.StreamIssuanceRulesResponse
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := stream.Recv()
		ch <- result{resp, err}
	}()
	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.resp
	case <-time.After(timeout):
		t.Fatal("timed out waiting for issuance rules response")
		return nil
	}
}

func TestStreamIssuanceRules_InitialSnapshot(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	rs.UpdateIssuanceRules([]controller.IssuanceRule{
		{
			PolicyName:       "default",
			RuleName:         "no-admin-all",
			CEL:              "!('admin:all' in scope.split(' '))",
			Message:          "admin:all scope is forbidden",
			TargetNamespaces: []string{"team-alpha"},
		},
	})

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamIssuanceRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamIssuanceRulesRequest{}))

	resp := recvIssResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetSnapshot())
	require.Len(t, resp.GetSnapshot().GetRules(), 1)
	rule := resp.GetSnapshot().GetRules()[0]
	assert.Equal(t, "default", rule.GetPolicyName())
	assert.Equal(t, "no-admin-all", rule.GetRuleName())
	assert.Equal(t, "admin:all scope is forbidden", rule.GetMessage())
	assert.Equal(t, []string{"team-alpha"}, rule.GetTargetNamespaces())
	assert.NotEmpty(t, resp.GetVersionInfo())
}

func TestStreamIssuanceRules_EmptyInitialSnapshot(t *testing.T) {
	_, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamIssuanceRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamIssuanceRulesRequest{}))

	resp := recvIssResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetSnapshot())
	assert.Empty(t, resp.GetSnapshot().GetRules())
}

func TestStreamIssuanceRules_UpsertAndRemove(t *testing.T) {
	rs, conn, cleanup := startTestServer(t)
	defer cleanup()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamIssuanceRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&rulesv1.StreamIssuanceRulesRequest{}))
	_ = recvIssResponse(t, stream, 3*time.Second)

	rs.UpsertIssuanceRule(controller.IssuanceRule{
		PolicyName: "p1", RuleName: "r1", CEL: "true", Message: "msg",
	})
	resp := recvIssResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetDelta())
	require.Len(t, resp.GetDelta().GetUpserted(), 1)
	assert.Equal(t, "r1", resp.GetDelta().GetUpserted()[0].GetRuleName())

	// Upsert again with same key replaces, not appends.
	rs.UpsertIssuanceRule(controller.IssuanceRule{
		PolicyName: "p1", RuleName: "r1", CEL: "true", Message: "msg-v2",
	})
	resp = recvIssResponse(t, stream, 3*time.Second)
	require.Len(t, resp.GetDelta().GetUpserted(), 1)
	assert.Equal(t, "msg-v2", resp.GetDelta().GetUpserted()[0].GetMessage())

	// RemoveIssuanceRule drops all rules sourced from the given policy.
	rs.UpsertIssuanceRule(controller.IssuanceRule{
		PolicyName: "p1", RuleName: "r2", CEL: "true", Message: "msg2",
	})
	_ = recvIssResponse(t, stream, 3*time.Second)

	rs.RemoveIssuanceRule("", "p1")
	resp = recvIssResponse(t, stream, 3*time.Second)
	require.NotNil(t, resp.GetDelta())
	require.Len(t, resp.GetDelta().GetRemoved(), 1)
	assert.Equal(t, "p1", resp.GetDelta().GetRemoved()[0].GetName())

	// After removal, full snapshot to a fresh client should be empty.
	stream2, err := client.StreamIssuanceRules(ctx)
	require.NoError(t, err)
	require.NoError(t, stream2.Send(&rulesv1.StreamIssuanceRulesRequest{}))
	resp = recvIssResponse(t, stream2, 3*time.Second)
	assert.Empty(t, resp.GetSnapshot().GetRules())
}
