package controller

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aramase/kontxt/api/v1alpha1"
)

// GenerationRule represents a compiled generation rule pushed to the TTS.
type GenerationRule struct {
	// Namespace is the namespace this rule applies to.
	Namespace string `json:"namespace"`
	// Name is the TransactionType name.
	Name string `json:"name"`
	// Endpoint is the path+method that triggers token generation.
	Endpoint v1alpha1.EndpointSpec `json:"endpoint"`
	// Purpose is the transaction purpose (included in tctx).
	Purpose string `json:"purpose"`
	// Scope is the requested scope for the TxToken.
	Scope string `json:"scope"`
	// TctxMapping defines how to extract tctx fields from the request.
	TctxMapping map[string]v1alpha1.TctxFieldMapping `json:"tctxMapping,omitempty"`
	// TctxEnrichments defines computed tctx fields.
	TctxEnrichments []v1alpha1.TctxEnrichment `json:"tctxEnrichments,omitempty"`
	// RctxFields lists rctx fields to populate.
	RctxFields []string `json:"rctxFields,omitempty"`
	// TokenLifetime is the effective lifetime after policy clamping.
	TokenLifetime string `json:"tokenLifetime"`
}

// VerificationRule represents a compiled verification rule pushed to the ext auth adapter.
type VerificationRule struct {
	// Namespace is the namespace this rule applies to.
	Namespace string `json:"namespace"`
	// Name is the ServiceTokenRequirement name.
	Name string `json:"name"`
	// ServiceName is the Kubernetes service this applies to.
	ServiceName string `json:"serviceName"`
	// RequiredScope is the minimum required scope.
	RequiredScope string `json:"requiredScope,omitempty"`
	// RequiredTctxFields lists required tctx fields.
	RequiredTctxFields []string `json:"requiredTctxFields,omitempty"`
	// CELRules are pre-validated CEL expressions.
	CELRules []CELRule `json:"celRules,omitempty"`
	// ExcludedEndpoints lists endpoints that bypass verification.
	ExcludedEndpoints []v1alpha1.EndpointSpec `json:"excludedEndpoints,omitempty"`
	// AutoNarrow enables automatic scope narrowing.
	AutoNarrow bool `json:"autoNarrow,omitempty"`
}

// CELRule is a named CEL expression for verification.
type CELRule struct {
	Name    string `json:"name"`
	CEL     string `json:"cel"`
	Message string `json:"message"`
}

// MarshalGenerationRules serializes generation rules to JSON for ConfigMap storage.
func MarshalGenerationRules(rules []GenerationRule) (string, error) {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling generation rules: %w", err)
	}
	return string(data), nil
}

// UnmarshalGenerationRules deserializes generation rules from JSON.
func UnmarshalGenerationRules(data string) ([]GenerationRule, error) {
	var rules []GenerationRule
	if err := json.Unmarshal([]byte(data), &rules); err != nil {
		return nil, fmt.Errorf("unmarshaling generation rules: %w", err)
	}
	return rules, nil
}

// MarshalVerificationRules serializes verification rules to JSON for ConfigMap storage.
func MarshalVerificationRules(rules []VerificationRule) (string, error) {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling verification rules: %w", err)
	}
	return string(data), nil
}

// UnmarshalVerificationRules deserializes verification rules from JSON.
func UnmarshalVerificationRules(data string) ([]VerificationRule, error) {
	var rules []VerificationRule
	if err := json.Unmarshal([]byte(data), &rules); err != nil {
		return nil, fmt.Errorf("unmarshaling verification rules: %w", err)
	}
	return rules, nil
}

// ValidateTransactionTypeAgainstPolicy checks a TransactionType against a TokenPolicy.
// Returns a list of violations (empty if compliant).
func ValidateTransactionTypeAgainstPolicy(tt *v1alpha1.TransactionType, policy *v1alpha1.TokenPolicy) []string {
	var violations []string

	if policy == nil {
		return violations
	}

	// Check token lifetime ceiling
	if policy.Spec.Constraints.MaxTokenLifetime != "" && tt.Spec.TokenLifetime != "" {
		maxDuration, err1 := time.ParseDuration(policy.Spec.Constraints.MaxTokenLifetime)
		ttDuration, err2 := time.ParseDuration(tt.Spec.TokenLifetime)
		if err1 == nil && err2 == nil && ttDuration > maxDuration {
			violations = append(violations, fmt.Sprintf(
				"tokenLifetime %s exceeds policy maximum %s",
				tt.Spec.TokenLifetime, policy.Spec.Constraints.MaxTokenLifetime,
			))
		}
	}

	// Check mandatory tctx fields
	for _, required := range policy.Spec.Constraints.MandatoryTctxFields {
		if required == "purpose" {
			// Purpose is always included
			continue
		}
		found := false
		for fieldName := range tt.Spec.TctxMapping {
			if fieldName == required {
				found = true
				break
			}
		}
		if !found {
			for _, enrichment := range tt.Spec.TctxEnrichments {
				if enrichment.Field == required {
					found = true
					break
				}
			}
		}
		if !found {
			violations = append(violations, fmt.Sprintf(
				"mandatory tctx field %q not produced by this TransactionType",
				required,
			))
		}
	}

	// Check disallowed enrichers
	for _, enrichment := range tt.Spec.TctxEnrichments {
		for _, disallowed := range policy.Spec.Constraints.DisallowedEnrichers {
			if enrichment.Enricher == disallowed {
				violations = append(violations, fmt.Sprintf(
					"enricher %q is disallowed by policy",
					enrichment.Enricher,
				))
			}
		}
	}

	return violations
}

// ComputeProducedTctxFields returns all tctx fields a TransactionType produces.
func ComputeProducedTctxFields(tt *v1alpha1.TransactionType) []string {
	fields := []string{"purpose"} // purpose is always included

	for name := range tt.Spec.TctxMapping {
		fields = append(fields, name)
	}
	for _, e := range tt.Spec.TctxEnrichments {
		fields = append(fields, e.Field)
	}

	return fields
}

// ClampTokenLifetime returns the effective lifetime, clamped to the policy ceiling.
func ClampTokenLifetime(requested string, maxLifetime string, defaultLifetime string) string {
	if requested == "" {
		requested = defaultLifetime
	}
	if maxLifetime == "" {
		return requested
	}

	reqDur, err1 := time.ParseDuration(requested)
	maxDur, err2 := time.ParseDuration(maxLifetime)
	if err1 != nil || err2 != nil {
		return requested
	}

	if reqDur > maxDur {
		return maxLifetime
	}
	return requested
}
