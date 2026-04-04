package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aramase/kontxt/api/v1alpha1"
)

func TestValidateTransactionTypeAgainstPolicy_Compliant(t *testing.T) {
	tt := &v1alpha1.TransactionType{
		Spec: v1alpha1.TransactionTypeSpec{
			Purpose:       "analysis",
			Scope:         "read:data",
			TokenLifetime: "15s",
			TctxMapping: map[string]v1alpha1.TctxFieldMapping{
				"datasetId": {Source: "path", Field: "datasetId"},
			},
		},
	}

	policy := &v1alpha1.TokenPolicy{
		Spec: v1alpha1.TokenPolicySpec{
			Constraints: v1alpha1.PolicyConstraints{
				MaxTokenLifetime:    "60s",
				MandatoryTctxFields: []string{"purpose"},
			},
		},
	}

	violations := ValidateTransactionTypeAgainstPolicy(tt, policy)
	assert.Empty(t, violations)
}

func TestValidateTransactionTypeAgainstPolicy_LifetimeExceeded(t *testing.T) {
	tt := &v1alpha1.TransactionType{
		Spec: v1alpha1.TransactionTypeSpec{
			Purpose:       "analysis",
			Scope:         "read:data",
			TokenLifetime: "120s",
		},
	}

	policy := &v1alpha1.TokenPolicy{
		Spec: v1alpha1.TokenPolicySpec{
			Constraints: v1alpha1.PolicyConstraints{
				MaxTokenLifetime: "60s",
			},
		},
	}

	violations := ValidateTransactionTypeAgainstPolicy(tt, policy)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0], "exceeds policy maximum")
}

func TestValidateTransactionTypeAgainstPolicy_MissingMandatoryField(t *testing.T) {
	tt := &v1alpha1.TransactionType{
		Spec: v1alpha1.TransactionTypeSpec{
			Purpose: "analysis",
			Scope:   "read:data",
			// No tctxMapping for "classification"
		},
	}

	policy := &v1alpha1.TokenPolicy{
		Spec: v1alpha1.TokenPolicySpec{
			Constraints: v1alpha1.PolicyConstraints{
				MandatoryTctxFields: []string{"purpose", "classification"},
			},
		},
	}

	violations := ValidateTransactionTypeAgainstPolicy(tt, policy)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0], "classification")
}

func TestValidateTransactionTypeAgainstPolicy_MandatoryFieldViaEnrichment(t *testing.T) {
	tt := &v1alpha1.TransactionType{
		Spec: v1alpha1.TransactionTypeSpec{
			Purpose: "analysis",
			Scope:   "read:data",
			TctxEnrichments: []v1alpha1.TctxEnrichment{
				{Field: "classification", Enricher: "dataset-classifier"},
			},
		},
	}

	policy := &v1alpha1.TokenPolicy{
		Spec: v1alpha1.TokenPolicySpec{
			Constraints: v1alpha1.PolicyConstraints{
				MandatoryTctxFields: []string{"purpose", "classification"},
			},
		},
	}

	violations := ValidateTransactionTypeAgainstPolicy(tt, policy)
	assert.Empty(t, violations, "enrichment-produced fields should satisfy mandatory requirement")
}

func TestValidateTransactionTypeAgainstPolicy_DisallowedEnricher(t *testing.T) {
	tt := &v1alpha1.TransactionType{
		Spec: v1alpha1.TransactionTypeSpec{
			Purpose: "analysis",
			Scope:   "read:data",
			TctxEnrichments: []v1alpha1.TctxEnrichment{
				{Field: "tier", Enricher: "user-tier-lookup"},
			},
		},
	}

	policy := &v1alpha1.TokenPolicy{
		Spec: v1alpha1.TokenPolicySpec{
			Constraints: v1alpha1.PolicyConstraints{
				DisallowedEnrichers: []string{"user-tier-lookup"},
			},
		},
	}

	violations := ValidateTransactionTypeAgainstPolicy(tt, policy)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0], "disallowed")
}

func TestValidateTransactionTypeAgainstPolicy_NilPolicy(t *testing.T) {
	tt := &v1alpha1.TransactionType{
		Spec: v1alpha1.TransactionTypeSpec{
			Purpose:       "analysis",
			Scope:         "read:data",
			TokenLifetime: "999s",
		},
	}

	violations := ValidateTransactionTypeAgainstPolicy(tt, nil)
	assert.Empty(t, violations, "no policy means no violations")
}

func TestComputeProducedTctxFields(t *testing.T) {
	tt := &v1alpha1.TransactionType{
		Spec: v1alpha1.TransactionTypeSpec{
			Purpose: "analysis",
			TctxMapping: map[string]v1alpha1.TctxFieldMapping{
				"datasetId":    {Source: "path", Field: "datasetId"},
				"analysisType": {Source: "body", Field: "type"},
			},
			TctxEnrichments: []v1alpha1.TctxEnrichment{
				{Field: "classification", Enricher: "dataset-classifier"},
			},
		},
	}

	fields := ComputeProducedTctxFields(tt)

	assert.Contains(t, fields, "purpose")
	assert.Contains(t, fields, "datasetId")
	assert.Contains(t, fields, "analysisType")
	assert.Contains(t, fields, "classification")
	assert.Len(t, fields, 4)
}

func TestClampTokenLifetime(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		max       string
		def       string
		want      string
	}{
		{"within ceiling", "15s", "60s", "15s", "15s"},
		{"exceeds ceiling", "120s", "60s", "15s", "60s"},
		{"no ceiling", "120s", "", "15s", "120s"},
		{"empty uses default", "", "60s", "15s", "15s"},
		{"empty no ceiling", "", "", "15s", "15s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClampTokenLifetime(tt.requested, tt.max, tt.def)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMarshalUnmarshalGenerationRules(t *testing.T) {
	rules := []GenerationRule{
		{
			Namespace: "team-alpha",
			Name:      "analyze-dataset",
			Endpoint:  v1alpha1.EndpointSpec{Path: "/api/v1/analyze", Method: "POST"},
			Purpose:   "analysis",
			Scope:     "read:data",
			TctxMapping: map[string]v1alpha1.TctxFieldMapping{
				"datasetId": {Source: "path", Field: "datasetId", Required: true},
			},
			TokenLifetime: "15s",
		},
	}

	data, err := MarshalGenerationRules(rules)
	require.NoError(t, err)
	assert.Contains(t, data, "analyze-dataset")

	decoded, err := UnmarshalGenerationRules(data)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, "team-alpha", decoded[0].Namespace)
	assert.Equal(t, "analysis", decoded[0].Purpose)
	assert.True(t, decoded[0].TctxMapping["datasetId"].Required)
}

func TestMarshalUnmarshalVerificationRules(t *testing.T) {
	rules := []VerificationRule{
		{
			Namespace:          "team-beta",
			Name:               "storage-reqs",
			ServiceName:        "storage-service",
			RequiredScope:      "read:datasets",
			RequiredTctxFields: []string{"datasetId", "classification"},
			CELRules: []CELRule{
				{Name: "public-only", CEL: `txtoken.tctx.classification == "public"`, Message: "public only"},
			},
			ExcludedEndpoints: []v1alpha1.EndpointSpec{
				{Path: "/healthz", Method: "GET"},
			},
			AutoNarrow: true,
		},
	}

	data, err := MarshalVerificationRules(rules)
	require.NoError(t, err)

	decoded, err := UnmarshalVerificationRules(data)
	require.NoError(t, err)
	require.Len(t, decoded, 1)
	assert.Equal(t, "storage-service", decoded[0].ServiceName)
	assert.True(t, decoded[0].AutoNarrow)
	assert.Len(t, decoded[0].CELRules, 1)
	assert.Equal(t, "public-only", decoded[0].CELRules[0].Name)
}

func TestSetCondition_Add(t *testing.T) {
	var conditions []metav1.Condition

	setCondition(&conditions, "Ready", metav1.ConditionTrue, "Reconciled", "all good")

	require.Len(t, conditions, 1)
	assert.Equal(t, "Ready", conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, conditions[0].Status)
	assert.Equal(t, "Reconciled", conditions[0].Reason)
}

func TestSetCondition_Update(t *testing.T) {
	conditions := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionFalse, Reason: "Pending", Message: "not yet"},
	}

	setCondition(&conditions, "Ready", metav1.ConditionTrue, "Reconciled", "done")

	require.Len(t, conditions, 1) // should update, not add
	assert.Equal(t, metav1.ConditionTrue, conditions[0].Status)
	assert.Equal(t, "Reconciled", conditions[0].Reason)
	assert.Equal(t, "done", conditions[0].Message)
}

func TestValidateCELRules_Valid(t *testing.T) {
	rules := []v1alpha1.VerificationRule{
		{Name: "test", CEL: `txtoken.tctx.classification == "public"`, Message: "msg"},
	}
	errs := validateCELRules(rules)
	assert.Empty(t, errs)
}

func TestValidateCELRules_EmptyExpression(t *testing.T) {
	rules := []v1alpha1.VerificationRule{
		{Name: "bad", CEL: "", Message: "msg"},
	}
	errs := validateCELRules(rules)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0], "empty CEL")
}
