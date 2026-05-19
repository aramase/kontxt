// Package ruleclient implements a gRPC streaming client that receives
// generation and verification rules from the kontxt controller's RuleDiscoveryService.
// It replaces the ConfigMap/fsnotify-based RulesLoader.
package ruleclient

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"github.com/aramase/kontxt/api/v1alpha1"
	rulesv1 "github.com/aramase/kontxt/gen/kontxt/rules/v1"
	"github.com/aramase/kontxt/internal/controller"
)

// GenerationSetter receives generation rules from the client.
type GenerationSetter interface {
	SetGenerationRules(rules []controller.GenerationRule)
}

// VerificationSetter receives verification rules from the client.
type VerificationSetter interface {
	SetVerificationRules(rules []controller.VerificationRule)
}

type ruleKey struct {
	Namespace string
	Name      string
}

// RuleClient connects to the controller's RuleDiscoveryService and streams
// generation and verification rules to the local ext-auth servers.
type RuleClient struct {
	addr   string
	opts   []grpc.DialOption
	genSet GenerationSetter
	verSet VerificationSetter

	// genSynced is set to 1 after the first generation snapshot has been
	// received and applied. Only meaningful when genSet != nil.
	genSynced atomic.Bool
	// verSynced is set to 1 after the first verification snapshot has been
	// received and applied. Only meaningful when verSet != nil.
	verSynced atomic.Bool
}

// NewRuleClient creates a RuleClient targeting the given controller gRPC address.
func NewRuleClient(addr string, opts ...grpc.DialOption) *RuleClient {
	return &RuleClient{
		addr: addr,
		opts: opts,
	}
}

// SetGenerationSetter sets the target that receives generation rules.
func (c *RuleClient) SetGenerationSetter(s GenerationSetter) {
	c.genSet = s
}

// SetVerificationSetter sets the target that receives verification rules.
func (c *RuleClient) SetVerificationSetter(s VerificationSetter) {
	c.verSet = s
}

// Ready reports whether the client has received and applied the initial
// snapshot for every configured stream (generation and/or verification).
// Returns false until each enabled stream has synced at least once.
func (c *RuleClient) Ready() bool {
	if c.genSet != nil && !c.genSynced.Load() {
		return false
	}
	if c.verSet != nil && !c.verSynced.Load() {
		return false
	}
	return true
}

// Run connects to the controller and streams rules. It reconnects on error
// with exponential backoff. It blocks until ctx is canceled.
func (c *RuleClient) Run(ctx context.Context) error {
	backoff := 500 * time.Millisecond
	maxBackoff := 30 * time.Second

	for {
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("rule client disconnected: %v, reconnecting...", err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (c *RuleClient) connect(ctx context.Context) error {
	conn, err := grpc.NewClient(c.addr, c.opts...)
	if err != nil {
		return fmt.Errorf("dial controller: %w", err)
	}
	defer conn.Close()

	client := rulesv1.NewRuleDiscoveryServiceClient(conn)

	errCh := make(chan error, 2)

	if c.genSet != nil {
		go func() {
			errCh <- c.streamGeneration(ctx, client)
		}()
	}

	if c.verSet != nil {
		go func() {
			errCh <- c.streamVerification(ctx, client)
		}()
	}

	// Return on the first error -- both streams will be torn down
	// because the conn is closed in defer.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *RuleClient) streamGeneration(ctx context.Context, client rulesv1.RuleDiscoveryServiceClient) error {
	stream, err := client.StreamGenerationRules(ctx)
	if err != nil {
		return fmt.Errorf("open generation stream: %w", err)
	}

	if err := stream.Send(&rulesv1.StreamGenerationRulesRequest{}); err != nil {
		return fmt.Errorf("send generation request: %w", err)
	}

	genRules := make(map[ruleKey]controller.GenerationRule)

	for {
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv generation: %w", err)
		}

		switch u := resp.GetUpdate().(type) {
		case *rulesv1.StreamGenerationRulesResponse_Snapshot:
			genRules = make(map[ruleKey]controller.GenerationRule)
			for _, pr := range u.Snapshot.GetRules() {
				r := protoToGenerationRule(pr)
				genRules[ruleKey{r.Namespace, r.Name}] = r
			}
		case *rulesv1.StreamGenerationRulesResponse_Delta:
			for _, pr := range u.Delta.GetUpserted() {
				r := protoToGenerationRule(pr)
				genRules[ruleKey{r.Namespace, r.Name}] = r
			}
			for _, ref := range u.Delta.GetRemoved() {
				delete(genRules, ruleKey{ref.GetNamespace(), ref.GetName()})
			}
		}

		rules := make([]controller.GenerationRule, 0, len(genRules))
		for _, r := range genRules {
			rules = append(rules, r)
		}
		c.genSet.SetGenerationRules(rules)
		c.genSynced.Store(true)
	}
}

func (c *RuleClient) streamVerification(ctx context.Context, client rulesv1.RuleDiscoveryServiceClient) error {
	stream, err := client.StreamVerificationRules(ctx)
	if err != nil {
		return fmt.Errorf("open verification stream: %w", err)
	}

	if err := stream.Send(&rulesv1.StreamVerificationRulesRequest{}); err != nil {
		return fmt.Errorf("send verification request: %w", err)
	}

	verRules := make(map[ruleKey]controller.VerificationRule)

	for {
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv verification: %w", err)
		}

		switch u := resp.GetUpdate().(type) {
		case *rulesv1.StreamVerificationRulesResponse_Snapshot:
			verRules = make(map[ruleKey]controller.VerificationRule)
			for _, pr := range u.Snapshot.GetRules() {
				r := protoToVerificationRule(pr)
				verRules[ruleKey{r.Namespace, r.Name}] = r
			}
		case *rulesv1.StreamVerificationRulesResponse_Delta:
			for _, pr := range u.Delta.GetUpserted() {
				r := protoToVerificationRule(pr)
				verRules[ruleKey{r.Namespace, r.Name}] = r
			}
			for _, ref := range u.Delta.GetRemoved() {
				delete(verRules, ruleKey{ref.GetNamespace(), ref.GetName()})
			}
		}

		rules := make([]controller.VerificationRule, 0, len(verRules))
		for _, r := range verRules {
			rules = append(rules, r)
		}
		c.verSet.SetVerificationRules(rules)
		c.verSynced.Store(true)
	}
}

// --- Conversion: proto messages to controller types ---

func protoToGenerationRule(pr *rulesv1.GenerationRule) controller.GenerationRule {
	r := controller.GenerationRule{
		Namespace:     pr.GetNamespace(),
		Name:          pr.GetName(),
		Purpose:       pr.GetPurpose(),
		Scope:         pr.GetScope(),
		RctxFields:    pr.GetRctxFields(),
		TokenLifetime: pr.GetTokenLifetime(),
	}
	if ep := pr.GetEndpoint(); ep != nil {
		r.Endpoint = v1alpha1.EndpointSpec{
			Path:   ep.GetPath(),
			Method: ep.GetMethod(),
		}
	}
	if m := pr.GetTctxMapping(); len(m) > 0 {
		r.TctxMapping = make(map[string]v1alpha1.TctxFieldMapping, len(m))
		for k, v := range m {
			r.TctxMapping[k] = v1alpha1.TctxFieldMapping{
				Source:   v.GetSource(),
				Field:    v.GetField(),
				Required: v.GetRequired(),
			}
		}
	}
	if enr := pr.GetTctxEnrichments(); len(enr) > 0 {
		r.TctxEnrichments = make([]v1alpha1.TctxEnrichment, len(enr))
		for i, e := range enr {
			r.TctxEnrichments[i] = v1alpha1.TctxEnrichment{
				Field:    e.GetField(),
				Enricher: e.GetEnricher(),
			}
		}
	}
	return r
}

func protoToVerificationRule(pr *rulesv1.VerificationRule) controller.VerificationRule {
	r := controller.VerificationRule{
		Namespace:          pr.GetNamespace(),
		Name:               pr.GetName(),
		ServiceName:        pr.GetServiceName(),
		RequiredScope:      pr.GetRequiredScope(),
		RequiredTctxFields: pr.GetRequiredTctxFields(),
		AutoNarrow:         pr.GetAutoNarrow(),
	}
	if cel := pr.GetCelRules(); len(cel) > 0 {
		r.CELRules = make([]controller.CELRule, len(cel))
		for i, c := range cel {
			r.CELRules[i] = controller.CELRule{
				Name:    c.GetName(),
				CEL:     c.GetCel(),
				Message: c.GetMessage(),
			}
		}
	}
	if eps := pr.GetExcludedEndpoints(); len(eps) > 0 {
		r.ExcludedEndpoints = make([]v1alpha1.EndpointSpec, len(eps))
		for i, e := range eps {
			r.ExcludedEndpoints[i] = v1alpha1.EndpointSpec{
				Path:   e.GetPath(),
				Method: e.GetMethod(),
			}
		}
	}
	return r
}
