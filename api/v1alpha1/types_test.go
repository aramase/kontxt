package v1alpha1

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	err := AddToScheme(scheme)
	require.NoError(t, err)

	// Verify all types are registered
	gvks, _, err := scheme.ObjectKinds(&TxTokenConfig{})
	require.NoError(t, err)
	assert.Len(t, gvks, 1)
	assert.Equal(t, "TxTokenConfig", gvks[0].Kind)
	assert.Equal(t, "kontxt.io", gvks[0].Group)
	assert.Equal(t, "v1alpha1", gvks[0].Version)

	gvks, _, err = scheme.ObjectKinds(&TransactionType{})
	require.NoError(t, err)
	assert.Equal(t, "TransactionType", gvks[0].Kind)

	gvks, _, err = scheme.ObjectKinds(&ServiceTokenRequirement{})
	require.NoError(t, err)
	assert.Equal(t, "ServiceTokenRequirement", gvks[0].Kind)

	gvks, _, err = scheme.ObjectKinds(&TokenPolicy{})
	require.NoError(t, err)
	assert.Equal(t, "TokenPolicy", gvks[0].Kind)
}

func TestTxTokenConfig_YAMLRoundTrip(t *testing.T) {
	original := &TxTokenConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kontxt.io/v1alpha1",
			Kind:       "TxTokenConfig",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: TxTokenConfigSpec{
			TrustDomain: "aks-cluster-1.contoso.com",
			Issuer:      "https://tts.platform-system.svc.cluster.local",
			SubjectTokens: []SubjectTokenAuthenticator{
				{
					Issuer: IssuerConfig{
						URL:                 "https://login.microsoftonline.com/tenant/v2.0",
						Audiences:           []string{"app-id"},
						AudienceMatchPolicy: "MatchAny",
					},
					ClaimValidationRules: []ClaimValidationRule{
						{
							Expression: `claims.tid == "tenant-id"`,
							Message:    "wrong tenant",
						},
					},
					ClaimMappings: ClaimMappings{
						Subject: ClaimOrExpression{Expression: "claims.oid"},
						Extra: []ExtraMapping{
							{Key: "tenant", ValueExpression: "claims.tid"},
						},
					},
				},
			},
			Defaults: TokenDefaults{
				TokenLifetime:    "15s",
				SigningAlgorithm: "RS256",
			},
		},
	}

	// Serialize to YAML
	yamlBytes, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Deserialize from YAML
	var decoded TxTokenConfig
	err = yaml.Unmarshal(yamlBytes, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Spec.TrustDomain, decoded.Spec.TrustDomain)
	assert.Equal(t, original.Spec.Issuer, decoded.Spec.Issuer)
	assert.Len(t, decoded.Spec.SubjectTokens, 1)
	assert.Equal(t, "https://login.microsoftonline.com/tenant/v2.0", decoded.Spec.SubjectTokens[0].Issuer.URL)
	assert.Equal(t, "claims.oid", decoded.Spec.SubjectTokens[0].ClaimMappings.Subject.Expression)
	assert.Equal(t, "15s", decoded.Spec.Defaults.TokenLifetime)
}

func TestTransactionType_YAMLRoundTrip(t *testing.T) {
	original := &TransactionType{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kontxt.io/v1alpha1",
			Kind:       "TransactionType",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "analyze-dataset",
			Namespace: "team-alpha",
		},
		Spec: TransactionTypeSpec{
			Endpoint: EndpointSpec{
				Path:   "/api/v1/datasets/{datasetId}/analyze",
				Method: "POST",
			},
			Purpose: "dataset-analysis",
			Scope:   "read:datasets execute:analysis",
			TctxMapping: map[string]TctxFieldMapping{
				"datasetId": {Source: "path", Field: "datasetId", Required: true},
				"type":      {Source: "body", Field: "type", Required: true},
			},
			TctxEnrichments: []TctxEnrichment{
				{Field: "classification", Enricher: "dataset-classifier"},
			},
			RctxFields:    []string{"req_ip", "authn"},
			TokenLifetime: "30s",
		},
	}

	yamlBytes, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded TransactionType
	err = yaml.Unmarshal(yamlBytes, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "team-alpha", decoded.Namespace)
	assert.Equal(t, "/api/v1/datasets/{datasetId}/analyze", decoded.Spec.Endpoint.Path)
	assert.Equal(t, "POST", decoded.Spec.Endpoint.Method)
	assert.Equal(t, "dataset-analysis", decoded.Spec.Purpose)
	assert.Equal(t, "read:datasets execute:analysis", decoded.Spec.Scope)
	assert.Len(t, decoded.Spec.TctxMapping, 2)
	assert.True(t, decoded.Spec.TctxMapping["datasetId"].Required)
	assert.Equal(t, "path", decoded.Spec.TctxMapping["datasetId"].Source)
	assert.Len(t, decoded.Spec.TctxEnrichments, 1)
	assert.Equal(t, "30s", decoded.Spec.TokenLifetime)
}

func TestServiceTokenRequirement_YAMLRoundTrip(t *testing.T) {
	original := &ServiceTokenRequirement{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kontxt.io/v1alpha1",
			Kind:       "ServiceTokenRequirement",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "storage-service-reqs",
			Namespace: "team-beta",
		},
		Spec: ServiceTokenRequirementSpec{
			ServiceRef: ServiceReference{Name: "storage-service"},
			Verification: VerificationSpec{
				RequiredScope:      "read:datasets",
				RequiredTctxFields: []string{"datasetId", "classification"},
				Rules: []VerificationRule{
					{
						Name:    "public-or-internal-only",
						CEL:     `txtoken.tctx.classification in ["public", "internal"]`,
						Message: "only public and internal datasets",
					},
				},
			},
			ExcludedEndpoints: []EndpointSpec{
				{Path: "/healthz", Method: "GET"},
				{Path: "/readyz", Method: "GET"},
			},
			AutoNarrow: true,
		},
	}

	yamlBytes, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded ServiceTokenRequirement
	err = yaml.Unmarshal(yamlBytes, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "team-beta", decoded.Namespace)
	assert.Equal(t, "storage-service", decoded.Spec.ServiceRef.Name)
	assert.Equal(t, "read:datasets", decoded.Spec.Verification.RequiredScope)
	assert.Equal(t, []string{"datasetId", "classification"}, decoded.Spec.Verification.RequiredTctxFields)
	assert.Len(t, decoded.Spec.Verification.Rules, 1)
	assert.Equal(t, "public-or-internal-only", decoded.Spec.Verification.Rules[0].Name)
	assert.Len(t, decoded.Spec.ExcludedEndpoints, 2)
	assert.True(t, decoded.Spec.AutoNarrow)
}

func TestTokenPolicy_YAMLRoundTrip(t *testing.T) {
	original := &TokenPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "kontxt.io/v1alpha1",
			Kind:       "TokenPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-policy",
		},
		Spec: TokenPolicySpec{
			AuthorizedTransactionNamespaces: &metav1.LabelSelector{
				MatchLabels: map[string]string{"kontxt.io/entry-allowed": "true"},
			},
			AuthorizedRequesters: []RequesterRule{
				{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kontxt.io/entry-allowed": "true"},
					},
					ServiceAccountNames: []string{"agent-*", "api-gateway"},
				},
			},
			Constraints: PolicyConstraints{
				MaxTokenLifetime:    "60s",
				MandatoryTctxFields: []string{"purpose"},
				MandatoryRctxFields: []string{"req_ip", "authn"},
			},
			IssuanceRules: []IssuanceRule{
				{
					Name:    "block-pii-outside-hours",
					CEL:     `!(tctx.classification == "pii" && timestamp(now).getHours() < 8)`,
					Message: "PII access only during business hours",
				},
			},
			AccessEvaluationWebhook: &WebhookConfig{
				Enabled:       false,
				Endpoint:      "https://policy-engine.svc/v1/evaluate",
				FailurePolicy: "Deny",
			},
		},
	}

	yamlBytes, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded TokenPolicy
	err = yaml.Unmarshal(yamlBytes, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "default-policy", decoded.Name)
	assert.Equal(t, "60s", decoded.Spec.Constraints.MaxTokenLifetime)
	assert.Equal(t, []string{"purpose"}, decoded.Spec.Constraints.MandatoryTctxFields)
	assert.Len(t, decoded.Spec.IssuanceRules, 1)
	assert.Equal(t, "block-pii-outside-hours", decoded.Spec.IssuanceRules[0].Name)
	assert.NotNil(t, decoded.Spec.AccessEvaluationWebhook)
	assert.False(t, decoded.Spec.AccessEvaluationWebhook.Enabled)
}

func TestTokenPolicy_NamespaceOverride(t *testing.T) {
	policy := &TokenPolicy{
		Spec: TokenPolicySpec{
			TargetNamespaces: &NamespaceSelector{
				MatchNames: []string{"team-beta"},
			},
			Constraints: PolicyConstraints{
				MaxTokenLifetime:    "15s",
				DisallowedEnrichers: []string{"user-tier-lookup"},
			},
		},
	}

	data, err := json.Marshal(policy)
	require.NoError(t, err)

	var decoded TokenPolicy
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, []string{"team-beta"}, decoded.Spec.TargetNamespaces.MatchNames)
	assert.Equal(t, "15s", decoded.Spec.Constraints.MaxTokenLifetime)
	assert.Equal(t, []string{"user-tier-lookup"}, decoded.Spec.Constraints.DisallowedEnrichers)
}

func TestClaimOrExpression_MutuallyExclusive(t *testing.T) {
	// Test with claim only
	c1 := ClaimOrExpression{Claim: "email"}
	data, err := json.Marshal(c1)
	require.NoError(t, err)

	var decoded1 ClaimOrExpression
	err = json.Unmarshal(data, &decoded1)
	require.NoError(t, err)
	assert.Equal(t, "email", decoded1.Claim)
	assert.Empty(t, decoded1.Expression)

	// Test with expression only
	c2 := ClaimOrExpression{Expression: "claims.oid"}
	data, err = json.Marshal(c2)
	require.NoError(t, err)

	var decoded2 ClaimOrExpression
	err = json.Unmarshal(data, &decoded2)
	require.NoError(t, err)
	assert.Empty(t, decoded2.Claim)
	assert.Equal(t, "claims.oid", decoded2.Expression)
}
