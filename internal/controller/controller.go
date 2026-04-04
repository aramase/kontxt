package controller

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aramase/kontxt/api/v1alpha1"
)

const (
	// ConfigMapNameGenerationRules is the ConfigMap name for generation rules.
	ConfigMapNameGenerationRules = "kontxt-generation-rules"
	// ConfigMapNameVerificationRules is the ConfigMap name for verification rules.
	ConfigMapNameVerificationRules = "kontxt-verification-rules"
	// ConfigMapNamespace is where rule ConfigMaps are created.
	ConfigMapNamespace = "kontxt-system"
	// ConfigMapDataKey is the data key within the ConfigMap.
	ConfigMapDataKey = "rules.json"

	// ConditionPolicyCompliant is the condition type for policy compliance.
	ConditionPolicyCompliant = "PolicyCompliant"
	// ConditionReady is the condition type for readiness.
	ConditionReady = "Ready"
)

// TransactionTypeReconciler reconciles TransactionType objects.
type TransactionTypeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=kontxt.io,resources=transactiontypes,verbs=get;list;watch
// +kubebuilder:rbac:groups=kontxt.io,resources=transactiontypes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kontxt.io,resources=tokenpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch

func (r *TransactionTypeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling TransactionType", "name", req.Name, "namespace", req.Namespace)

	// Fetch the TransactionType
	var tt v1alpha1.TransactionType
	if err := r.Get(ctx, req.NamespacedName, &tt); err != nil {
		if errors.IsNotFound(err) {
			// Object deleted — rebuild rules without it
			return ctrl.Result{}, r.rebuildGenerationRules(ctx)
		}
		return ctrl.Result{}, err
	}

	// Fetch applicable TokenPolicy
	policy, err := r.findApplicablePolicy(ctx, tt.Namespace)
	if err != nil {
		logger.Error(err, "failed to find applicable policy")
	}

	// Validate against policy
	violations := ValidateTransactionTypeAgainstPolicy(&tt, policy)

	// Update status
	producedFields := ComputeProducedTctxFields(&tt)
	effectiveLifetime := tt.Spec.TokenLifetime
	if policy != nil {
		effectiveLifetime = ClampTokenLifetime(tt.Spec.TokenLifetime, policy.Spec.Constraints.MaxTokenLifetime, "15s")
	}

	// Set PolicyCompliant condition
	if len(violations) > 0 {
		setCondition(&tt.Status.Conditions, ConditionPolicyCompliant, metav1.ConditionFalse,
			"PolicyViolation", fmt.Sprintf("violations: %v", violations))
	} else {
		setCondition(&tt.Status.Conditions, ConditionPolicyCompliant, metav1.ConditionTrue,
			"Compliant", "all policy constraints satisfied")
	}

	// Set Ready condition
	setCondition(&tt.Status.Conditions, ConditionReady, metav1.ConditionTrue, "Reconciled", "generation rules updated")

	tt.Status.ProducedTctxFields = producedFields
	tt.Status.EffectiveTokenLifetime = effectiveLifetime

	if err := r.Status().Update(ctx, &tt); err != nil {
		logger.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	// Rebuild generation rules ConfigMap
	if err := r.rebuildGenerationRules(ctx); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// rebuildGenerationRules lists all TransactionTypes and writes the generation rules ConfigMap.
func (r *TransactionTypeReconciler) rebuildGenerationRules(ctx context.Context) error {
	var ttList v1alpha1.TransactionTypeList
	if err := r.List(ctx, &ttList); err != nil {
		return fmt.Errorf("listing TransactionTypes: %w", err)
	}

	rules := make([]GenerationRule, 0, len(ttList.Items))
	for _, tt := range ttList.Items {
		// Find applicable policy for lifetime clamping
		policy, _ := r.findApplicablePolicy(ctx, tt.Namespace)
		effectiveLifetime := tt.Spec.TokenLifetime
		if policy != nil {
			effectiveLifetime = ClampTokenLifetime(tt.Spec.TokenLifetime, policy.Spec.Constraints.MaxTokenLifetime, "15s")
		}
		if effectiveLifetime == "" {
			effectiveLifetime = "15s"
		}

		rules = append(rules, GenerationRule{
			Namespace:       tt.Namespace,
			Name:            tt.Name,
			Endpoint:        tt.Spec.Endpoint,
			Purpose:         tt.Spec.Purpose,
			Scope:           tt.Spec.Scope,
			TctxMapping:     tt.Spec.TctxMapping,
			TctxEnrichments: tt.Spec.TctxEnrichments,
			RctxFields:      tt.Spec.RctxFields,
			TokenLifetime:   effectiveLifetime,
		})
	}

	rulesJSON, err := MarshalGenerationRules(rules)
	if err != nil {
		return err
	}

	return r.ensureConfigMap(ctx, ConfigMapNameGenerationRules, rulesJSON)
}

// findApplicablePolicy finds the TokenPolicy that applies to the given namespace.
func (r *TransactionTypeReconciler) findApplicablePolicy(ctx context.Context, namespace string) (*v1alpha1.TokenPolicy, error) {
	var policyList v1alpha1.TokenPolicyList
	if err := r.List(ctx, &policyList); err != nil {
		return nil, err
	}

	for _, policy := range policyList.Items {
		if policy.Spec.TargetNamespaces == nil {
			return &policy, nil // no target filter = applies to all
		}
		for _, name := range policy.Spec.TargetNamespaces.MatchNames {
			if name == namespace {
				return &policy, nil
			}
		}
	}

	// Look for a default policy (no target namespaces)
	for _, policy := range policyList.Items {
		if policy.Spec.TargetNamespaces == nil {
			return &policy, nil
		}
	}

	return nil, nil
}

// ensureConfigMap creates or updates a ConfigMap with the given data.
func (r *TransactionTypeReconciler) ensureConfigMap(ctx context.Context, name, data string) error {
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: name, Namespace: ConfigMapNamespace}

	err := r.Get(ctx, key, cm)
	if errors.IsNotFound(err) {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ConfigMapNamespace,
			},
			Data: map[string]string{
				ConfigMapDataKey: data,
			},
		}
		return r.Create(ctx, cm)
	}
	if err != nil {
		return err
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[ConfigMapDataKey] = data
	return r.Update(ctx, cm)
}

func (r *TransactionTypeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TransactionType{}).
		Complete(r)
}

// ServiceTokenRequirementReconciler reconciles ServiceTokenRequirement objects.
type ServiceTokenRequirementReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=kontxt.io,resources=servicetokenrequirements,verbs=get;list;watch
// +kubebuilder:rbac:groups=kontxt.io,resources=servicetokenrequirements/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch

func (r *ServiceTokenRequirementReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling ServiceTokenRequirement", "name", req.Name, "namespace", req.Namespace)

	// Fetch the ServiceTokenRequirement
	var str v1alpha1.ServiceTokenRequirement
	if err := r.Get(ctx, req.NamespacedName, &str); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, r.rebuildVerificationRules(ctx)
		}
		return ctrl.Result{}, err
	}

	// Validate CEL rules at reconcile time (compile check)
	celErrors := validateCELRules(str.Spec.Verification.Rules)

	// Update status
	if len(celErrors) > 0 {
		setCondition(&str.Status.Conditions, ConditionReady, metav1.ConditionFalse,
			"CELCompilationError", fmt.Sprintf("CEL errors: %v", celErrors))
	} else {
		setCondition(&str.Status.Conditions, ConditionReady, metav1.ConditionTrue,
			"Reconciled", "verification rules updated")
	}

	str.Status.ActiveVerificationRules = len(str.Spec.Verification.Rules)
	str.Status.ExcludedEndpointCount = len(str.Spec.ExcludedEndpoints)

	if err := r.Status().Update(ctx, &str); err != nil {
		logger.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	// Rebuild verification rules ConfigMap
	if err := r.rebuildVerificationRules(ctx); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ServiceTokenRequirementReconciler) rebuildVerificationRules(ctx context.Context) error {
	var strList v1alpha1.ServiceTokenRequirementList
	if err := r.List(ctx, &strList); err != nil {
		return fmt.Errorf("listing ServiceTokenRequirements: %w", err)
	}

	rules := make([]VerificationRule, 0, len(strList.Items))
	for _, str := range strList.Items {
		celRules := make([]CELRule, 0, len(str.Spec.Verification.Rules))
		for _, r := range str.Spec.Verification.Rules {
			celRules = append(celRules, CELRule{
				Name:    r.Name,
				CEL:     r.CEL,
				Message: r.Message,
			})
		}

		rules = append(rules, VerificationRule{
			Namespace:          str.Namespace,
			Name:               str.Name,
			ServiceName:        str.Spec.ServiceRef.Name,
			RequiredScope:      str.Spec.Verification.RequiredScope,
			RequiredTctxFields: str.Spec.Verification.RequiredTctxFields,
			CELRules:           celRules,
			ExcludedEndpoints:  str.Spec.ExcludedEndpoints,
			AutoNarrow:         str.Spec.AutoNarrow,
		})
	}

	rulesJSON, err := MarshalVerificationRules(rules)
	if err != nil {
		return err
	}

	return r.ensureConfigMap(ctx, ConfigMapNameVerificationRules, rulesJSON)
}

func (r *ServiceTokenRequirementReconciler) ensureConfigMap(ctx context.Context, name, data string) error {
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Name: name, Namespace: ConfigMapNamespace}

	err := r.Get(ctx, key, cm)
	if errors.IsNotFound(err) {
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: ConfigMapNamespace,
			},
			Data: map[string]string{ConfigMapDataKey: data},
		}
		return r.Create(ctx, cm)
	}
	if err != nil {
		return err
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	cm.Data[ConfigMapDataKey] = data
	return r.Update(ctx, cm)
}

func (r *ServiceTokenRequirementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ServiceTokenRequirement{}).
		Complete(r)
}

// validateCELRules does a basic syntax check on CEL expressions.
// In a full implementation, this would compile the expressions.
func validateCELRules(rules []v1alpha1.VerificationRule) []string {
	var errs []string
	for _, rule := range rules {
		if rule.CEL == "" {
			errs = append(errs, fmt.Sprintf("rule %q has empty CEL expression", rule.Name))
		}
	}
	return errs
}

// setCondition updates or adds a condition to the list.
func setCondition(conditions *[]metav1.Condition, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i, c := range *conditions {
		if c.Type == condType {
			(*conditions)[i].Status = status
			(*conditions)[i].Reason = reason
			(*conditions)[i].Message = message
			(*conditions)[i].LastTransitionTime = now
			return
		}
	}
	*conditions = append(*conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}

// MarshalRulesJSON is a helper to marshal any rules to JSON (used by ConfigMap data).
func MarshalRulesJSON(v any) (string, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
