package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aramase/kontxt/api/v1alpha1"
	"github.com/aramase/kontxt/pkg/tts"
)

// IssuancePublisher is implemented by ruleserver.RuleServer to push issuance
// rules to TTS instances. Narrower than RulePublisher because the policy
// reconciler should not be able to mutate generation or verification rules.
type IssuancePublisher interface {
	UpdateIssuanceRules(rules []IssuanceRule)
}

// TokenPolicyReconciler reconciles TokenPolicy objects. It pre-compiles every
// IssuanceRule's CEL expression and only pushes rules that compile cleanly.
// Compile failures are surfaced as a PolicyCompliant=False status condition so
// administrators can fix the policy without breaking the TTS request path.
type TokenPolicyReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	IssuancePublisher IssuancePublisher
}

// +kubebuilder:rbac:groups=kontxt.io,resources=tokenpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=kontxt.io,resources=tokenpolicies/status,verbs=get;update;patch

func (r *TokenPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling TokenPolicy", "name", req.Name)

	var policy v1alpha1.TokenPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if errors.IsNotFound(err) {
			// Object deleted — rebuild rules without it.
			return ctrl.Result{}, r.rebuildIssuanceRules(ctx)
		}
		return ctrl.Result{}, err
	}

	// Validate every CEL expression before publishing anything.
	compileErrs := validateIssuanceCEL(policy.Spec.IssuanceRules)

	if len(compileErrs) > 0 {
		setCondition(&policy.Status.Conditions, ConditionPolicyCompliant, metav1.ConditionFalse,
			"CELCompilationError", fmt.Sprintf("CEL errors: %v", compileErrs))
		setCondition(&policy.Status.Conditions, ConditionReady, metav1.ConditionFalse,
			"CELCompilationError", fmt.Sprintf("one or more issuance rules failed to compile: %v", compileErrs))
	} else {
		setCondition(&policy.Status.Conditions, ConditionPolicyCompliant, metav1.ConditionTrue,
			"Compliant", "all issuance rules compiled successfully")
		setCondition(&policy.Status.Conditions, ConditionReady, metav1.ConditionTrue,
			"Reconciled", "issuance rules updated")
	}

	if err := r.Status().Update(ctx, &policy); err != nil {
		logger.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	if err := r.rebuildIssuanceRules(ctx); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// rebuildIssuanceRules lists every TokenPolicy, drops rules with broken CEL,
// and pushes the flattened set to the TTS.
func (r *TokenPolicyReconciler) rebuildIssuanceRules(ctx context.Context) error {
	var policyList v1alpha1.TokenPolicyList
	if err := r.List(ctx, &policyList); err != nil {
		return fmt.Errorf("listing TokenPolicies: %w", err)
	}

	var rules []IssuanceRule
	for _, policy := range policyList.Items {
		// Skip rules that fail to compile so bad CEL is never pushed.
		compileErrs := validateIssuanceCEL(policy.Spec.IssuanceRules)
		broken := make(map[string]bool, len(compileErrs))
		for _, e := range compileErrs {
			broken[e.ruleName] = true
		}

		targetNS := resolveTargetNamespaces(policy.Spec.TargetNamespaces)
		for _, ir := range policy.Spec.IssuanceRules {
			if broken[ir.Name] {
				continue
			}
			rules = append(rules, IssuanceRule{
				PolicyName:       policy.Name,
				RuleName:         ir.Name,
				CEL:              ir.CEL,
				Message:          ir.Message,
				TargetNamespaces: targetNS,
			})
		}
	}

	if r.IssuancePublisher != nil {
		r.IssuancePublisher.UpdateIssuanceRules(rules)
	}
	return nil
}

func (r *TokenPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TokenPolicy{}).
		Complete(r)
}

// resolveTargetNamespaces converts the API selector to a flat namespace list
// the TTS can match against. Empty result means cluster-wide. Only MatchNames
// is supported in v0; MatchLabels resolution requires listing namespaces and is
// deferred.
//
// TODO(spike): support NamespaceSelector.MatchLabels by listing v1.Namespace
// and intersecting. Requires the controller to watch Namespace objects to
// re-reconcile policies when label sets change.
func resolveTargetNamespaces(sel *v1alpha1.NamespaceSelector) []string {
	if sel == nil {
		return nil
	}
	if len(sel.MatchNames) == 0 {
		return nil
	}
	out := make([]string, len(sel.MatchNames))
	copy(out, sel.MatchNames)
	return out
}

// issuanceCELError associates a rule name with its compile error.
type issuanceCELError struct {
	ruleName string
	err      string
}

func (e issuanceCELError) String() string {
	return fmt.Sprintf("%s: %s", e.ruleName, e.err)
}

// validateIssuanceCEL compiles every rule and returns errors keyed by rule name.
// Uses the same CEL environment the TTS uses at runtime so reconcile-time
// validation matches request-time evaluation.
func validateIssuanceCEL(rules []v1alpha1.IssuanceRule) []issuanceCELError {
	if len(rules) == 0 {
		return nil
	}

	configs := make([]tts.IssuanceRuleConfig, len(rules))
	for i, r := range rules {
		configs[i] = tts.IssuanceRuleConfig{Name: r.Name, CEL: r.CEL, Message: r.Message}
	}

	// CompileIssuanceRules stops at the first failure, so iterate per-rule to
	// surface every broken rule in one reconcile pass.
	var errs []issuanceCELError
	for _, cfg := range configs {
		if _, err := tts.CompileIssuanceRules([]tts.IssuanceRuleConfig{cfg}); err != nil {
			errs = append(errs, issuanceCELError{ruleName: cfg.Name, err: err.Error()})
		}
	}
	return errs
}
