// Package ruleserver implements a gRPC streaming server that distributes
// generation and verification rules from the kontxt controller to ext-auth
// adapter instances. It replaces the ConfigMap-based distribution mechanism.
package ruleserver

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/aramase/kontxt/api/v1alpha1"
	rulesv1 "github.com/aramase/kontxt/gen/kontxt/rules/v1"
	"github.com/aramase/kontxt/internal/controller"
)

// RuleServer implements the RuleDiscoveryService gRPC service.
// It holds the current rule state and broadcasts updates to all connected
// ext-auth clients via per-client channels.
type RuleServer struct {
	rulesv1.UnimplementedRuleDiscoveryServiceServer

	mu                sync.RWMutex
	generationRules   []controller.GenerationRule
	verificationRules []controller.VerificationRule
	issuanceRules     []controller.IssuanceRule

	genVersion atomic.Uint64
	verVersion atomic.Uint64
	issVersion atomic.Uint64

	genSubscribers map[string]chan *rulesv1.StreamGenerationRulesResponse
	verSubscribers map[string]chan *rulesv1.StreamVerificationRulesResponse
	issSubscribers map[string]chan *rulesv1.StreamIssuanceRulesResponse

	subIDCounter atomic.Uint64
}

// NewRuleServer creates a new RuleServer.
func NewRuleServer() *RuleServer {
	return &RuleServer{
		genSubscribers: make(map[string]chan *rulesv1.StreamGenerationRulesResponse),
		verSubscribers: make(map[string]chan *rulesv1.StreamVerificationRulesResponse),
		issSubscribers: make(map[string]chan *rulesv1.StreamIssuanceRulesResponse),
	}
}

// StreamGenerationRules implements the bidirectional streaming RPC. On first
// request it sends a full snapshot; subsequent updates are pushed as they occur.
func (s *RuleServer) StreamGenerationRules(stream rulesv1.RuleDiscoveryService_StreamGenerationRulesServer) error {
	// Wait for the first request from the client.
	if _, err := stream.Recv(); err != nil {
		return err
	}

	// Register subscriber.
	id := fmt.Sprintf("gen-%d", s.subIDCounter.Add(1))
	ch := make(chan *rulesv1.StreamGenerationRulesResponse, 64)

	s.mu.Lock()
	s.genSubscribers[id] = ch
	// Build snapshot under lock.
	snapshot := s.buildGenSnapshot()
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.genSubscribers, id)
		s.mu.Unlock()
	}()

	// Send initial snapshot.
	if err := stream.Send(snapshot); err != nil {
		return err
	}

	// Stream updates.
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case resp, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// StreamVerificationRules implements the bidirectional streaming RPC for verification rules.
func (s *RuleServer) StreamVerificationRules(stream rulesv1.RuleDiscoveryService_StreamVerificationRulesServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}

	id := fmt.Sprintf("ver-%d", s.subIDCounter.Add(1))
	ch := make(chan *rulesv1.StreamVerificationRulesResponse, 64)

	s.mu.Lock()
	s.verSubscribers[id] = ch
	snapshot := s.buildVerSnapshot()
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.verSubscribers, id)
		s.mu.Unlock()
	}()

	if err := stream.Send(snapshot); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case resp, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// StreamIssuanceRules implements the bidirectional streaming RPC for issuance
// rules pushed to the TTS.
func (s *RuleServer) StreamIssuanceRules(stream rulesv1.RuleDiscoveryService_StreamIssuanceRulesServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}

	id := fmt.Sprintf("iss-%d", s.subIDCounter.Add(1))
	ch := make(chan *rulesv1.StreamIssuanceRulesResponse, 64)

	s.mu.Lock()
	s.issSubscribers[id] = ch
	snapshot := s.buildIssSnapshot()
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.issSubscribers, id)
		s.mu.Unlock()
	}()

	if err := stream.Send(snapshot); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case resp, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// UpdateGenerationRules replaces all generation rules and broadcasts a full
// snapshot to all connected clients.
func (s *RuleServer) UpdateGenerationRules(rules []controller.GenerationRule) {
	s.mu.Lock()
	s.generationRules = rules
	v := fmt.Sprintf("%d", s.genVersion.Add(1))
	resp := &rulesv1.StreamGenerationRulesResponse{
		Update: &rulesv1.StreamGenerationRulesResponse_Snapshot{
			Snapshot: &rulesv1.GenerationRulesSnapshot{
				Rules: generationRulesToProto(rules),
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.genSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// UpsertGenerationRule adds or updates a single generation rule and broadcasts
// a delta to all connected clients.
func (s *RuleServer) UpsertGenerationRule(rule controller.GenerationRule) {
	s.mu.Lock()
	found := false
	for i, r := range s.generationRules {
		if r.Namespace == rule.Namespace && r.Name == rule.Name {
			s.generationRules[i] = rule
			found = true
			break
		}
	}
	if !found {
		s.generationRules = append(s.generationRules, rule)
	}

	v := fmt.Sprintf("%d", s.genVersion.Add(1))
	resp := &rulesv1.StreamGenerationRulesResponse{
		Update: &rulesv1.StreamGenerationRulesResponse_Delta{
			Delta: &rulesv1.GenerationRulesDelta{
				Upserted: generationRulesToProto([]controller.GenerationRule{rule}),
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.genSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// RemoveGenerationRule removes a generation rule by namespace/name and broadcasts
// a delta to all connected clients.
func (s *RuleServer) RemoveGenerationRule(namespace, name string) {
	s.mu.Lock()
	for i, r := range s.generationRules {
		if r.Namespace == namespace && r.Name == name {
			s.generationRules = append(s.generationRules[:i], s.generationRules[i+1:]...)
			break
		}
	}

	v := fmt.Sprintf("%d", s.genVersion.Add(1))
	resp := &rulesv1.StreamGenerationRulesResponse{
		Update: &rulesv1.StreamGenerationRulesResponse_Delta{
			Delta: &rulesv1.GenerationRulesDelta{
				Removed: []*rulesv1.RuleRef{{Namespace: namespace, Name: name}},
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.genSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// UpdateVerificationRules replaces all verification rules and broadcasts a full snapshot.
func (s *RuleServer) UpdateVerificationRules(rules []controller.VerificationRule) {
	s.mu.Lock()
	s.verificationRules = rules
	v := fmt.Sprintf("%d", s.verVersion.Add(1))
	resp := &rulesv1.StreamVerificationRulesResponse{
		Update: &rulesv1.StreamVerificationRulesResponse_Snapshot{
			Snapshot: &rulesv1.VerificationRulesSnapshot{
				Rules: verificationRulesToProto(rules),
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.verSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// UpsertVerificationRule adds or updates a single verification rule.
func (s *RuleServer) UpsertVerificationRule(rule controller.VerificationRule) {
	s.mu.Lock()
	found := false
	for i, r := range s.verificationRules {
		if r.Namespace == rule.Namespace && r.Name == rule.Name {
			s.verificationRules[i] = rule
			found = true
			break
		}
	}
	if !found {
		s.verificationRules = append(s.verificationRules, rule)
	}

	v := fmt.Sprintf("%d", s.verVersion.Add(1))
	resp := &rulesv1.StreamVerificationRulesResponse{
		Update: &rulesv1.StreamVerificationRulesResponse_Delta{
			Delta: &rulesv1.VerificationRulesDelta{
				Upserted: verificationRulesToProto([]controller.VerificationRule{rule}),
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.verSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// RemoveVerificationRule removes a verification rule by namespace/name.
func (s *RuleServer) RemoveVerificationRule(namespace, name string) {
	s.mu.Lock()
	for i, r := range s.verificationRules {
		if r.Namespace == namespace && r.Name == name {
			s.verificationRules = append(s.verificationRules[:i], s.verificationRules[i+1:]...)
			break
		}
	}

	v := fmt.Sprintf("%d", s.verVersion.Add(1))
	resp := &rulesv1.StreamVerificationRulesResponse{
		Update: &rulesv1.StreamVerificationRulesResponse_Delta{
			Delta: &rulesv1.VerificationRulesDelta{
				Removed: []*rulesv1.RuleRef{{Namespace: namespace, Name: name}},
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.verSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// UpdateIssuanceRules replaces all issuance rules and broadcasts a full snapshot.
func (s *RuleServer) UpdateIssuanceRules(rules []controller.IssuanceRule) {
	s.mu.Lock()
	s.issuanceRules = rules
	v := fmt.Sprintf("%d", s.issVersion.Add(1))
	resp := &rulesv1.StreamIssuanceRulesResponse{
		Update: &rulesv1.StreamIssuanceRulesResponse_Snapshot{
			Snapshot: &rulesv1.IssuanceRulesSnapshot{
				Rules: issuanceRulesToProto(rules),
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.issSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// UpsertIssuanceRule adds or updates a single issuance rule and broadcasts a delta.
// Rules are keyed by (PolicyNamespace, PolicyName, RuleName).
func (s *RuleServer) UpsertIssuanceRule(rule controller.IssuanceRule) {
	s.mu.Lock()
	found := false
	for i, r := range s.issuanceRules {
		if r.PolicyNamespace == rule.PolicyNamespace &&
			r.PolicyName == rule.PolicyName &&
			r.RuleName == rule.RuleName {
			s.issuanceRules[i] = rule
			found = true
			break
		}
	}
	if !found {
		s.issuanceRules = append(s.issuanceRules, rule)
	}

	v := fmt.Sprintf("%d", s.issVersion.Add(1))
	resp := &rulesv1.StreamIssuanceRulesResponse{
		Update: &rulesv1.StreamIssuanceRulesResponse_Delta{
			Delta: &rulesv1.IssuanceRulesDelta{
				Upserted: issuanceRulesToProto([]controller.IssuanceRule{rule}),
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.issSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// RemoveIssuanceRule removes all issuance rules sourced from the given
// TokenPolicy (identified by namespace + name) and broadcasts a delta. The
// RuleRef.Name carries the policy name; the entire policy's rule set is dropped
// in one delta, mirroring how reconciliation re-pushes the full set on update.
func (s *RuleServer) RemoveIssuanceRule(policyNamespace, policyName string) {
	s.mu.Lock()
	out := s.issuanceRules[:0]
	for _, r := range s.issuanceRules {
		if r.PolicyNamespace == policyNamespace && r.PolicyName == policyName {
			continue
		}
		out = append(out, r)
	}
	s.issuanceRules = out

	v := fmt.Sprintf("%d", s.issVersion.Add(1))
	resp := &rulesv1.StreamIssuanceRulesResponse{
		Update: &rulesv1.StreamIssuanceRulesResponse_Delta{
			Delta: &rulesv1.IssuanceRulesDelta{
				Removed: []*rulesv1.RuleRef{{Namespace: policyNamespace, Name: policyName}},
			},
		},
		VersionInfo: v,
	}
	for _, ch := range s.issSubscribers {
		select {
		case ch <- resp:
		default:
		}
	}
	s.mu.Unlock()
}

// buildGenSnapshot returns a full generation rules snapshot response. Must be called under s.mu.
func (s *RuleServer) buildGenSnapshot() *rulesv1.StreamGenerationRulesResponse {
	return &rulesv1.StreamGenerationRulesResponse{
		Update: &rulesv1.StreamGenerationRulesResponse_Snapshot{
			Snapshot: &rulesv1.GenerationRulesSnapshot{
				Rules: generationRulesToProto(s.generationRules),
			},
		},
		VersionInfo: fmt.Sprintf("%d", s.genVersion.Load()),
	}
}

// buildVerSnapshot returns a full verification rules snapshot response. Must be called under s.mu.
func (s *RuleServer) buildVerSnapshot() *rulesv1.StreamVerificationRulesResponse {
	return &rulesv1.StreamVerificationRulesResponse{
		Update: &rulesv1.StreamVerificationRulesResponse_Snapshot{
			Snapshot: &rulesv1.VerificationRulesSnapshot{
				Rules: verificationRulesToProto(s.verificationRules),
			},
		},
		VersionInfo: fmt.Sprintf("%d", s.verVersion.Load()),
	}
}

// buildIssSnapshot returns a full issuance rules snapshot response. Must be called under s.mu.
func (s *RuleServer) buildIssSnapshot() *rulesv1.StreamIssuanceRulesResponse {
	return &rulesv1.StreamIssuanceRulesResponse{
		Update: &rulesv1.StreamIssuanceRulesResponse_Snapshot{
			Snapshot: &rulesv1.IssuanceRulesSnapshot{
				Rules: issuanceRulesToProto(s.issuanceRules),
			},
		},
		VersionInfo: fmt.Sprintf("%d", s.issVersion.Load()),
	}
}

// --- Conversion functions: controller types to proto messages ---

func generationRulesToProto(rules []controller.GenerationRule) []*rulesv1.GenerationRule {
	out := make([]*rulesv1.GenerationRule, len(rules))
	for i := range rules {
		out[i] = generationRuleToProto(&rules[i])
	}
	return out
}

func generationRuleToProto(r *controller.GenerationRule) *rulesv1.GenerationRule {
	pr := &rulesv1.GenerationRule{
		Namespace:     r.Namespace,
		Name:          r.Name,
		Purpose:       r.Purpose,
		Scope:         r.Scope,
		RctxFields:    r.RctxFields,
		TokenLifetime: r.TokenLifetime,
	}
	if r.Endpoint.Path != "" || r.Endpoint.Method != "" {
		pr.Endpoint = endpointToProto(&r.Endpoint)
	}
	if len(r.TctxMapping) > 0 {
		pr.TctxMapping = make(map[string]*rulesv1.TctxFieldMapping, len(r.TctxMapping))
		for k, v := range r.TctxMapping {
			pr.TctxMapping[k] = &rulesv1.TctxFieldMapping{
				Source:   v.Source,
				Field:    v.Field,
				Required: v.Required,
			}
		}
	}
	if len(r.TctxEnrichments) > 0 {
		pr.TctxEnrichments = make([]*rulesv1.TctxEnrichment, len(r.TctxEnrichments))
		for i, e := range r.TctxEnrichments {
			pr.TctxEnrichments[i] = &rulesv1.TctxEnrichment{
				Field:    e.Field,
				Enricher: e.Enricher,
			}
		}
	}
	return pr
}

func verificationRulesToProto(rules []controller.VerificationRule) []*rulesv1.VerificationRule {
	out := make([]*rulesv1.VerificationRule, len(rules))
	for i := range rules {
		out[i] = verificationRuleToProto(&rules[i])
	}
	return out
}

func verificationRuleToProto(r *controller.VerificationRule) *rulesv1.VerificationRule {
	pr := &rulesv1.VerificationRule{
		Namespace:          r.Namespace,
		Name:               r.Name,
		ServiceName:        r.ServiceName,
		RequiredScope:      r.RequiredScope,
		RequiredTctxFields: r.RequiredTctxFields,
		AutoNarrow:         r.AutoNarrow,
	}
	if len(r.CELRules) > 0 {
		pr.CelRules = make([]*rulesv1.CELRule, len(r.CELRules))
		for i, c := range r.CELRules {
			pr.CelRules[i] = &rulesv1.CELRule{
				Name:    c.Name,
				Cel:     c.CEL,
				Message: c.Message,
			}
		}
	}
	if len(r.ExcludedEndpoints) > 0 {
		pr.ExcludedEndpoints = make([]*rulesv1.EndpointSpec, len(r.ExcludedEndpoints))
		for i := range r.ExcludedEndpoints {
			pr.ExcludedEndpoints[i] = endpointToProto(&r.ExcludedEndpoints[i])
		}
	}
	return pr
}

func endpointToProto(e *v1alpha1.EndpointSpec) *rulesv1.EndpointSpec {
	return &rulesv1.EndpointSpec{
		Path:   e.Path,
		Method: e.Method,
	}
}

func issuanceRulesToProto(rules []controller.IssuanceRule) []*rulesv1.IssuanceRule {
	out := make([]*rulesv1.IssuanceRule, len(rules))
	for i := range rules {
		out[i] = issuanceRuleToProto(&rules[i])
	}
	return out
}

func issuanceRuleToProto(r *controller.IssuanceRule) *rulesv1.IssuanceRule {
	return &rulesv1.IssuanceRule{
		PolicyNamespace:  r.PolicyNamespace,
		PolicyName:       r.PolicyName,
		RuleName:         r.RuleName,
		Cel:              r.CEL,
		Message:          r.Message,
		TargetNamespaces: append([]string(nil), r.TargetNamespaces...),
	}
}
