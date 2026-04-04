package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// CRD 1: TxTokenConfig — Platform Admin, cluster-scoped
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=ttc
// +kubebuilder:subresource:status

// TxTokenConfig is the cluster-scoped configuration for the Transaction Token Service.
// Owned by the platform admin.
type TxTokenConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TxTokenConfigSpec   `json:"spec,omitempty"`
	Status TxTokenConfigStatus `json:"status,omitempty"`
}

// TxTokenConfigSpec defines the TTS infrastructure configuration.
type TxTokenConfigSpec struct {
	// TrustDomain is the trust domain identifier, used as the `aud` claim in TxTokens.
	// +kubebuilder:validation:Required
	TrustDomain string `json:"trustDomain"`

	// Issuer is the TTS issuer URI, used as the `iss` claim in TxTokens.
	// +kubebuilder:validation:Required
	Issuer string `json:"issuer"`

	// SubjectTokens is an ordered list of JWT authenticators for subject token validation.
	// The first authenticator whose issuer URL matches the token's `iss` claim handles it.
	// Inspired by KEP-3331 (Structured Authentication Configuration).
	// +kubebuilder:validation:MinItems=1
	SubjectTokens []SubjectTokenAuthenticator `json:"subjectTokens"`

	// WorkloadAuth configures how the TTS authenticates the requesting workload.
	WorkloadAuth WorkloadAuthConfig `json:"workloadAuth,omitempty"`

	// Defaults contains default token settings.
	Defaults TokenDefaults `json:"defaults,omitempty"`
}

// SubjectTokenAuthenticator configures a single JWT authenticator for subject tokens.
type SubjectTokenAuthenticator struct {
	// Issuer configures the OIDC issuer for this authenticator.
	Issuer IssuerConfig `json:"issuer"`

	// ClaimValidationRules are CEL expressions evaluated against raw JWT claims.
	// Each rule must evaluate to true for the token to be accepted.
	// +optional
	ClaimValidationRules []ClaimValidationRule `json:"claimValidationRules,omitempty"`

	// ClaimMappings defines how JWT claims are mapped to the TxToken subject.
	ClaimMappings ClaimMappings `json:"claimMappings"`
}

// IssuerConfig defines the OIDC issuer configuration.
type IssuerConfig struct {
	// URL is the issuer identifier. Must match the `iss` claim in incoming tokens.
	// +kubebuilder:validation:Required
	URL string `json:"url"`

	// DiscoveryURL overrides where to fetch OIDC discovery metadata.
	// If empty, defaults to {URL}/.well-known/openid-configuration.
	// +optional
	DiscoveryURL string `json:"discoveryURL,omitempty"`

	// Audiences is the list of acceptable audience values.
	// +kubebuilder:validation:MinItems=1
	Audiences []string `json:"audiences"`

	// AudienceMatchPolicy determines how audiences are matched.
	// "MatchAny" means the token's aud must contain at least one configured audience.
	// +kubebuilder:validation:Enum=MatchAny
	// +optional
	AudienceMatchPolicy string `json:"audienceMatchPolicy,omitempty"`
}

// ClaimValidationRule is a CEL expression evaluated against raw JWT claims.
type ClaimValidationRule struct {
	// Expression is a CEL expression that must evaluate to true.
	// The variable `claims` is available as a map[string]any.
	// +kubebuilder:validation:Required
	Expression string `json:"expression"`

	// Message is the error message returned when the expression evaluates to false.
	// +kubebuilder:validation:Required
	Message string `json:"message"`
}

// ClaimMappings defines how JWT claims are mapped to SubjectInfo fields.
type ClaimMappings struct {
	// Subject determines which claim becomes the TxToken's `sub`.
	// Exactly one of Claim or Expression must be set.
	Subject ClaimOrExpression `json:"subject"`

	// Extra carries additional identity attributes from the IdP token.
	// +optional
	Extra []ExtraMapping `json:"extra,omitempty"`
}

// ClaimOrExpression specifies either a simple claim name or a CEL expression.
type ClaimOrExpression struct {
	// Claim is a simple JWT claim name (e.g., "email", "sub", "oid").
	// +optional
	Claim string `json:"claim,omitempty"`

	// Expression is a CEL expression evaluated against the `claims` map.
	// +optional
	Expression string `json:"expression,omitempty"`
}

// ExtraMapping maps a JWT claim to an extra key-value pair.
type ExtraMapping struct {
	// Key is the extra attribute key (e.g., "tenant", "name").
	// +kubebuilder:validation:Required
	Key string `json:"key"`

	// ValueExpression is a CEL expression producing the value.
	// +kubebuilder:validation:Required
	ValueExpression string `json:"valueExpression"`
}

// WorkloadAuthConfig configures workload authentication to the TTS.
type WorkloadAuthConfig struct {
	// Type is the workload authentication mechanism.
	// +kubebuilder:validation:Enum=kubernetes-sa;spiffe
	// +kubebuilder:default=kubernetes-sa
	Type string `json:"type,omitempty"`
}

// TokenDefaults contains default token configuration.
type TokenDefaults struct {
	// TokenLifetime is the default TxToken lifetime (e.g., "15s").
	// +kubebuilder:default="15s"
	TokenLifetime string `json:"tokenLifetime,omitempty"`

	// SigningAlgorithm is the JWT signing algorithm.
	// +kubebuilder:default="RS256"
	SigningAlgorithm string `json:"signingAlgorithm,omitempty"`
}

// TxTokenConfigStatus defines the observed state of TxTokenConfig.
type TxTokenConfigStatus struct {
	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// TxTokenConfigList contains a list of TxTokenConfig.
type TxTokenConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TxTokenConfig `json:"items"`
}

// ============================================================================
// CRD 2: TransactionType — Transaction Owner, namespace-scoped
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=tt
// +kubebuilder:subresource:status

// TransactionType defines what TxToken to generate for a specific API endpoint.
// Owned by the transaction owner (agent developer) in their namespace.
type TransactionType struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TransactionTypeSpec   `json:"spec,omitempty"`
	Status TransactionTypeStatus `json:"status,omitempty"`
}

// TransactionTypeSpec defines the generation rules for a transaction.
type TransactionTypeSpec struct {
	// Endpoint specifies which inbound API endpoint triggers this transaction.
	Endpoint EndpointSpec `json:"endpoint"`

	// Purpose describes the intent of this transaction (becomes a field in tctx).
	// +kubebuilder:validation:Required
	Purpose string `json:"purpose"`

	// Scope is the requested scope for the TxToken (space-delimited).
	// Must be ≤ subject token scope and ≤ TokenPolicy ceiling.
	// +kubebuilder:validation:Required
	Scope string `json:"scope"`

	// TctxMapping defines how to build the `tctx` claim from the inbound request.
	// +optional
	TctxMapping map[string]TctxFieldMapping `json:"tctxMapping,omitempty"`

	// TctxEnrichments define values computed by the TTS (not in the original request).
	// +optional
	TctxEnrichments []TctxEnrichment `json:"tctxEnrichments,omitempty"`

	// RctxFields specifies which rctx fields to populate (e.g., "req_ip", "authn").
	// +optional
	RctxFields []string `json:"rctxFields,omitempty"`

	// TokenLifetime overrides the default token lifetime.
	// Subject to TokenPolicy ceiling.
	// +optional
	TokenLifetime string `json:"tokenLifetime,omitempty"`
}

// EndpointSpec identifies an API endpoint.
type EndpointSpec struct {
	// Path is the URL path pattern (e.g., "/api/v1/datasets/{datasetId}/analyze").
	// +kubebuilder:validation:Required
	Path string `json:"path"`

	// Method is the HTTP method (e.g., "POST", "GET").
	// +kubebuilder:validation:Required
	Method string `json:"method"`
}

// TctxFieldMapping defines how to extract a single tctx field from the request.
type TctxFieldMapping struct {
	// Source is where to extract the value from: "path", "body", "header", "query".
	// +kubebuilder:validation:Enum=path;body;header;query
	Source string `json:"source"`

	// Field is the field name to extract from the source.
	// +kubebuilder:validation:Required
	Field string `json:"field"`

	// Required indicates whether this field must be present in the request.
	// +optional
	Required bool `json:"required,omitempty"`
}

// TctxEnrichment defines a tctx field computed by the TTS.
type TctxEnrichment struct {
	// Field is the tctx field name.
	// +kubebuilder:validation:Required
	Field string `json:"field"`

	// Enricher is the name of the enricher plugin to invoke.
	// +kubebuilder:validation:Required
	Enricher string `json:"enricher"`
}

// TransactionTypeStatus defines the observed state of TransactionType.
type TransactionTypeStatus struct {
	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ProducedTctxFields lists all tctx fields this transaction type produces
	// (extracted + enriched + purpose).
	// +optional
	ProducedTctxFields []string `json:"producedTctxFields,omitempty"`

	// EffectiveTokenLifetime is the token lifetime after TokenPolicy ceiling is applied.
	// +optional
	EffectiveTokenLifetime string `json:"effectiveTokenLifetime,omitempty"`
}

// +kubebuilder:object:root=true

// TransactionTypeList contains a list of TransactionType.
type TransactionTypeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TransactionType `json:"items"`
}

// ============================================================================
// CRD 3: ServiceTokenRequirement — Service Owner, namespace-scoped
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=str
// +kubebuilder:subresource:status

// ServiceTokenRequirement defines what a service requires in incoming TxTokens.
// Owned by the service owner in their namespace.
type ServiceTokenRequirement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceTokenRequirementSpec   `json:"spec,omitempty"`
	Status ServiceTokenRequirementStatus `json:"status,omitempty"`
}

// ServiceTokenRequirementSpec defines verification requirements for incoming TxTokens.
type ServiceTokenRequirementSpec struct {
	// ServiceRef references the Kubernetes service this requirement applies to.
	ServiceRef ServiceReference `json:"serviceRef"`

	// Verification defines the TxToken verification requirements.
	Verification VerificationSpec `json:"verification"`

	// ExcludedEndpoints lists endpoints that skip TxToken verification.
	// +optional
	ExcludedEndpoints []EndpointSpec `json:"excludedEndpoints,omitempty"`

	// AutoNarrow, when true, causes the ext auth adapter to automatically
	// request a scope-narrowed replacement token when the inbound TxToken
	// has broader scope than requiredScope.
	// +optional
	AutoNarrow bool `json:"autoNarrow,omitempty"`
}

// ServiceReference identifies a Kubernetes service.
type ServiceReference struct {
	// Name is the Kubernetes service name.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// VerificationSpec defines what to verify in incoming TxTokens.
type VerificationSpec struct {
	// RequiredScope is the minimum scope the TxToken must have.
	// +optional
	RequiredScope string `json:"requiredScope,omitempty"`

	// RequiredTctxFields lists tctx fields that must be present in the TxToken.
	// +optional
	RequiredTctxFields []string `json:"requiredTctxFields,omitempty"`

	// Rules are CEL-based verification rules evaluated against the TxToken.
	// +optional
	Rules []VerificationRule `json:"rules,omitempty"`
}

// VerificationRule is a CEL expression evaluated against a TxToken.
type VerificationRule struct {
	// Name identifies this rule (used in error messages and metrics).
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// CEL is a CEL expression that must evaluate to true.
	// Available variables: `txtoken` (all TxToken claims), `request` (HTTP request).
	// +kubebuilder:validation:Required
	CEL string `json:"cel"`

	// Message is the error message when the rule fails.
	// +kubebuilder:validation:Required
	Message string `json:"message"`
}

// ServiceTokenRequirementStatus defines the observed state.
type ServiceTokenRequirementStatus struct {
	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ActiveVerificationRules is the count of active verification rules.
	// +optional
	ActiveVerificationRules int `json:"activeVerificationRules,omitempty"`

	// ExcludedEndpointCount is the count of excluded endpoints.
	// +optional
	ExcludedEndpointCount int `json:"excludedEndpointCount,omitempty"`
}

// +kubebuilder:object:root=true

// ServiceTokenRequirementList contains a list of ServiceTokenRequirement.
type ServiceTokenRequirementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceTokenRequirement `json:"items"`
}

// ============================================================================
// CRD 4: TokenPolicy — Security Admin, cluster-scoped
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=tp
// +kubebuilder:subresource:status

// TokenPolicy defines security guardrails for transaction tokens.
// Owned by the security admin.
type TokenPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TokenPolicySpec   `json:"spec,omitempty"`
	Status TokenPolicyStatus `json:"status,omitempty"`
}

// TokenPolicySpec defines the policy constraints.
type TokenPolicySpec struct {
	// TargetNamespaces limits this policy to specific namespaces.
	// If empty, the policy applies to all namespaces.
	// +optional
	TargetNamespaces *NamespaceSelector `json:"targetNamespaces,omitempty"`

	// AuthorizedTransactionNamespaces restricts which namespaces can define TransactionTypes.
	// +optional
	AuthorizedTransactionNamespaces *metav1.LabelSelector `json:"authorizedTransactionNamespaces,omitempty"`

	// AuthorizedRequesters restricts which service accounts can request TxTokens.
	// +optional
	AuthorizedRequesters []RequesterRule `json:"authorizedRequesters,omitempty"`

	// Constraints define ceilings that TransactionTypes cannot exceed.
	Constraints PolicyConstraints `json:"constraints,omitempty"`

	// IssuanceRules are CEL expressions evaluated by the TTS before issuing a TxToken.
	// All rules must evaluate to true for the token to be issued.
	// +optional
	IssuanceRules []IssuanceRule `json:"issuanceRules,omitempty"`

	// AccessEvaluationWebhook is an optional external webhook for policy decisions
	// that CEL cannot express.
	// +optional
	AccessEvaluationWebhook *WebhookConfig `json:"accessEvaluationWebhook,omitempty"`
}

// NamespaceSelector selects namespaces by name or labels.
type NamespaceSelector struct {
	// MatchNames selects namespaces by exact name.
	// +optional
	MatchNames []string `json:"matchNames,omitempty"`

	// MatchLabels selects namespaces by label.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// RequesterRule defines which service accounts can request TxTokens.
type RequesterRule struct {
	// NamespaceSelector selects namespaces for this rule.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// ServiceAccountNames is a list of allowed service account names.
	// Supports wildcards (e.g., "agent-*").
	// +optional
	ServiceAccountNames []string `json:"serviceAccountNames,omitempty"`
}

// PolicyConstraints define ceilings for token settings.
type PolicyConstraints struct {
	// MaxTokenLifetime is the maximum allowed token lifetime.
	// +optional
	MaxTokenLifetime string `json:"maxTokenLifetime,omitempty"`

	// MandatoryTctxFields are tctx fields required in ALL tokens.
	// +optional
	MandatoryTctxFields []string `json:"mandatoryTctxFields,omitempty"`

	// MandatoryRctxFields are rctx fields required in ALL tokens.
	// +optional
	MandatoryRctxFields []string `json:"mandatoryRctxFields,omitempty"`

	// DisallowedEnrichers blocks specific enricher plugins.
	// +optional
	DisallowedEnrichers []string `json:"disallowedEnrichers,omitempty"`
}

// IssuanceRule is a CEL expression evaluated before issuing a TxToken.
type IssuanceRule struct {
	// Name identifies this rule.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// CEL is a CEL expression that must evaluate to true.
	// Available variables: subject, scope, tctx, rctx, workload, namespace.
	// +kubebuilder:validation:Required
	CEL string `json:"cel"`

	// Message is the error message when the rule fails.
	// +kubebuilder:validation:Required
	Message string `json:"message"`
}

// WebhookConfig configures an external policy evaluation webhook.
type WebhookConfig struct {
	// Enabled controls whether the webhook is active.
	Enabled bool `json:"enabled"`

	// Endpoint is the URL of the webhook.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// FailurePolicy determines behavior on webhook failure.
	// +kubebuilder:validation:Enum=Deny;Allow
	// +kubebuilder:default=Deny
	FailurePolicy string `json:"failurePolicy,omitempty"`
}

// TokenPolicyStatus defines the observed state of TokenPolicy.
type TokenPolicyStatus struct {
	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true

// TokenPolicyList contains a list of TokenPolicy.
type TokenPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TokenPolicy `json:"items"`
}
