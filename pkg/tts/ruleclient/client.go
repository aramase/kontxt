// Package ruleclient implements a gRPC streaming client that receives
// issuance rules from the kontxt controller's RuleDiscoveryService and applies
// them to a TTS Handler. Mirrors pkg/extauth/ruleclient.
package ruleclient

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	rulesv1 "github.com/aramase/kontxt/gen/kontxt/rules/v1"
	"github.com/aramase/kontxt/internal/controller"
)

// IssuanceSetter receives the latest issuance rule set. The setter is
// responsible for compiling CEL and replacing the handler's rule set
// atomically.
type IssuanceSetter interface {
	SetIssuanceRules(rules []controller.IssuanceRule) error
}

// ruleKey identifies a unique issuance rule across all TokenPolicies.
type ruleKey struct {
	PolicyNamespace string
	PolicyName      string
	RuleName        string
}

// RuleClient connects to the controller's RuleDiscoveryService and streams
// issuance rules into the configured IssuanceSetter.
type RuleClient struct {
	addr   string
	opts   []grpc.DialOption
	setter IssuanceSetter

	// synced is set after the first snapshot has been received and applied.
	synced atomic.Bool
}

// NewRuleClient creates a RuleClient targeting the given controller gRPC address.
func NewRuleClient(addr string, setter IssuanceSetter, opts ...grpc.DialOption) *RuleClient {
	return &RuleClient{
		addr:   addr,
		opts:   opts,
		setter: setter,
	}
}

// Ready reports whether the client has received and applied at least one snapshot.
func (c *RuleClient) Ready() bool {
	return c.synced.Load()
}

// Run connects to the controller and streams rules. It reconnects on error
// with exponential backoff and blocks until ctx is canceled.
func (c *RuleClient) Run(ctx context.Context) error {
	backoff := 500 * time.Millisecond
	maxBackoff := 30 * time.Second

	for {
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("tts rule client disconnected: %v, reconnecting...", err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (c *RuleClient) connect(ctx context.Context) error {
	conn, err := grpc.NewClient(c.addr, c.opts...)
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer conn.Close()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)
	return c.streamIssuance(ctx, client)
}

func (c *RuleClient) streamIssuance(ctx context.Context, client rulesv1.RuleDiscoveryServiceClient) error {
	stream, err := client.StreamIssuanceRules(ctx)
	if err != nil {
		return fmt.Errorf("open issuance stream: %w", err)
	}

	if err := stream.Send(&rulesv1.StreamIssuanceRulesRequest{}); err != nil {
		return fmt.Errorf("send issuance request: %w", err)
	}

	rules := make(map[ruleKey]controller.IssuanceRule)

	for {
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv issuance: %w", err)
		}

		switch u := resp.GetUpdate().(type) {
		case *rulesv1.StreamIssuanceRulesResponse_Snapshot:
			rules = make(map[ruleKey]controller.IssuanceRule)
			for _, pr := range u.Snapshot.GetRules() {
				r := protoToIssuanceRule(pr)
				rules[keyFor(r)] = r
			}
		case *rulesv1.StreamIssuanceRulesResponse_Delta:
			for _, pr := range u.Delta.GetUpserted() {
				r := protoToIssuanceRule(pr)
				rules[keyFor(r)] = r
			}
			// Removed RuleRef carries (PolicyNamespace, PolicyName). The
			// controller drops all rules from a removed policy in a single
			// delta, mirroring how the reconciler re-pushes on update.
			for _, ref := range u.Delta.GetRemoved() {
				for k := range rules {
					if k.PolicyNamespace == ref.GetNamespace() && k.PolicyName == ref.GetName() {
						delete(rules, k)
					}
				}
			}
		}

		flat := make([]controller.IssuanceRule, 0, len(rules))
		for _, r := range rules {
			flat = append(flat, r)
		}
		// Sort by (PolicyNamespace, PolicyName, RuleName) so the rule
		// evaluation order is deterministic across updates. Without this,
		// map iteration order would make `policy_denied` error messages
		// vary across equivalent rule sets, since EvaluateIssuanceRules
		// returns the first failure it sees.
		sort.Slice(flat, func(i, j int) bool {
			if flat[i].PolicyNamespace != flat[j].PolicyNamespace {
				return flat[i].PolicyNamespace < flat[j].PolicyNamespace
			}
			if flat[i].PolicyName != flat[j].PolicyName {
				return flat[i].PolicyName < flat[j].PolicyName
			}
			return flat[i].RuleName < flat[j].RuleName
		})
		if err := c.setter.SetIssuanceRules(flat); err != nil {
			// Compile errors at this point indicate the controller pushed CEL
			// the TTS cannot parse. Log and continue with the previous valid
			// rule set rather than tearing the connection down.
			log.Printf("tts rule client: applying issuance rules failed: %v", err)
		} else {
			c.synced.Store(true)
		}
	}
}

func keyFor(r controller.IssuanceRule) ruleKey {
	return ruleKey{PolicyNamespace: r.PolicyNamespace, PolicyName: r.PolicyName, RuleName: r.RuleName}
}

func protoToIssuanceRule(pr *rulesv1.IssuanceRule) controller.IssuanceRule {
	return controller.IssuanceRule{
		PolicyNamespace:  pr.GetPolicyNamespace(),
		PolicyName:       pr.GetPolicyName(),
		RuleName:         pr.GetRuleName(),
		CEL:              pr.GetCel(),
		Message:          pr.GetMessage(),
		TargetNamespaces: append([]string(nil), pr.GetTargetNamespaces()...),
	}
}
