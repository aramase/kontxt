package controller

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aramase/kontxt/api/v1alpha1"
)

// fakeIssuancePublisher captures pushed rules for assertions.
type fakeIssuancePublisher struct {
	mu    sync.Mutex
	last  []IssuanceRule
	calls int
}

func (p *fakeIssuancePublisher) UpdateIssuanceRules(rules []IssuanceRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Copy to insulate from caller mutations.
	p.last = append(p.last[:0], rules...)
	p.calls++
}

func (p *fakeIssuancePublisher) snapshot() []IssuanceRule {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]IssuanceRule, len(p.last))
	copy(out, p.last)
	return out
}

func newPolicyReconcilerFixture(t *testing.T, objs ...client.Object) (*TokenPolicyReconciler, *fakeIssuancePublisher) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.TokenPolicy{}).
		Build()

	pub := &fakeIssuancePublisher{}
	r := &TokenPolicyReconciler{
		Client:            c,
		Scheme:            scheme,
		IssuancePublisher: pub,
	}
	return r, pub
}

func TestTokenPolicyReconciler_ValidRule_Published(t *testing.T) {
	policy := &v1alpha1.TokenPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1alpha1.TokenPolicySpec{
			TargetNamespaces: &v1alpha1.NamespaceSelector{
				MatchNames: []string{"team-alpha", "team-beta"},
			},
			IssuanceRules: []v1alpha1.IssuanceRule{
				{Name: "no-admin", CEL: `!scope.contains("admin:all")`, Message: "admin:all forbidden"},
			},
		},
	}

	r, pub := newPolicyReconcilerFixture(t, policy)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "default"}})
	require.NoError(t, err)

	rules := pub.snapshot()
	require.Len(t, rules, 1)
	assert.Equal(t, "default", rules[0].PolicyName)
	assert.Equal(t, "no-admin", rules[0].RuleName)
	assert.Equal(t, []string{"team-alpha", "team-beta"}, rules[0].TargetNamespaces)

	// Status should show PolicyCompliant=True.
	var updated v1alpha1.TokenPolicy
	require.NoError(t, r.Get(context.Background(), client.ObjectKey{Name: "default"}, &updated))
	require.NotEmpty(t, updated.Status.Conditions)
	cond := findCondition(updated.Status.Conditions, ConditionPolicyCompliant)
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
}

func TestTokenPolicyReconciler_BrokenCEL_DroppedAndStatusFalse(t *testing.T) {
	policy := &v1alpha1.TokenPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1alpha1.TokenPolicySpec{
			IssuanceRules: []v1alpha1.IssuanceRule{
				{Name: "good", CEL: "true", Message: "ok"},
				{Name: "broken", CEL: "this is not valid CEL", Message: "won't compile"},
			},
		},
	}

	r, pub := newPolicyReconcilerFixture(t, policy)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "default"}})
	require.NoError(t, err)

	rules := pub.snapshot()
	require.Len(t, rules, 1, "only the well-formed rule should be pushed")
	assert.Equal(t, "good", rules[0].RuleName)

	var updated v1alpha1.TokenPolicy
	require.NoError(t, r.Get(context.Background(), client.ObjectKey{Name: "default"}, &updated))
	cond := findCondition(updated.Status.Conditions, ConditionPolicyCompliant)
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionFalse, cond.Status)
	assert.Contains(t, cond.Message, "broken")

	// Ready must also flip to False so operators see one consistent signal —
	// matches ServiceTokenRequirementReconciler's behavior on CEL errors.
	ready := findCondition(updated.Status.Conditions, ConditionReady)
	require.NotNil(t, ready)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, "CELCompilationError", ready.Reason)
}

func TestTokenPolicyReconciler_MultiplePolicies_Flattened(t *testing.T) {
	p1 := &v1alpha1.TokenPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p1"},
		Spec: v1alpha1.TokenPolicySpec{
			TargetNamespaces: &v1alpha1.NamespaceSelector{MatchNames: []string{"ns1"}},
			IssuanceRules: []v1alpha1.IssuanceRule{
				{Name: "r1", CEL: "true", Message: "m1"},
			},
		},
	}
	p2 := &v1alpha1.TokenPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "p2"},
		Spec: v1alpha1.TokenPolicySpec{
			TargetNamespaces: &v1alpha1.NamespaceSelector{MatchNames: []string{"ns2"}},
			IssuanceRules: []v1alpha1.IssuanceRule{
				{Name: "r1", CEL: "true", Message: "m2"},
				{Name: "r2", CEL: "subject != ''", Message: "m3"},
			},
		},
	}

	r, pub := newPolicyReconcilerFixture(t, p1, p2)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "p1"}})
	require.NoError(t, err)

	rules := pub.snapshot()
	require.Len(t, rules, 3)

	got := make(map[string][]string)
	for _, r := range rules {
		got[r.PolicyName] = append(got[r.PolicyName], r.RuleName)
	}
	assert.ElementsMatch(t, []string{"r1"}, got["p1"])
	assert.ElementsMatch(t, []string{"r1", "r2"}, got["p2"])
}

func TestTokenPolicyReconciler_PolicyDeleted_Rebuilds(t *testing.T) {
	p := &v1alpha1.TokenPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "to-delete"},
		Spec: v1alpha1.TokenPolicySpec{
			IssuanceRules: []v1alpha1.IssuanceRule{
				{Name: "r1", CEL: "true", Message: "m"},
			},
		},
	}
	r, pub := newPolicyReconcilerFixture(t, p)

	// Initial reconcile publishes the rule.
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "to-delete"}})
	require.NoError(t, err)
	require.Len(t, pub.snapshot(), 1)

	// Delete the policy and reconcile again — publisher should be called with empty set.
	require.NoError(t, r.Delete(context.Background(), p))
	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "to-delete"}})
	require.NoError(t, err)
	assert.Empty(t, pub.snapshot())
}

func TestTokenPolicyReconciler_EmptyTargetNamespaces_ClusterWide(t *testing.T) {
	p := &v1alpha1.TokenPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: v1alpha1.TokenPolicySpec{
			IssuanceRules: []v1alpha1.IssuanceRule{
				{Name: "r1", CEL: "true", Message: "m"},
			},
		},
	}
	r, pub := newPolicyReconcilerFixture(t, p)
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "cluster"}})
	require.NoError(t, err)

	rules := pub.snapshot()
	require.Len(t, rules, 1)
	assert.Empty(t, rules[0].TargetNamespaces, "empty TargetNamespaces selector should produce a cluster-wide rule")
}

func TestTokenPolicyReconciler_NoPublisher_NoCrash(t *testing.T) {
	// Belt-and-braces: a reconciler without a publisher (e.g. local dev) must not panic.
	policy := &v1alpha1.TokenPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1alpha1.TokenPolicySpec{
			IssuanceRules: []v1alpha1.IssuanceRule{
				{Name: "r1", CEL: "true", Message: "m"},
			},
		},
	}
	r, _ := newPolicyReconcilerFixture(t, policy)
	r.IssuancePublisher = nil

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "default"}})
	require.NoError(t, err)
}

// findCondition returns the named condition or nil.
func findCondition(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}

// TestValidateIssuanceCEL_FastPathAllValid asserts that a rule set with no
// errors short-circuits before any per-rule fallback runs.
func TestValidateIssuanceCEL_FastPathAllValid(t *testing.T) {
	errs := validateIssuanceCEL([]v1alpha1.IssuanceRule{
		{Name: "r1", CEL: "true", Message: "m"},
		{Name: "r2", CEL: "subject == 'alice'", Message: "m"},
		{Name: "r3", CEL: "scope.startsWith('read:')", Message: "m"},
	})
	assert.Empty(t, errs)
}

// TestValidateIssuanceCEL_FallbackSurfacesAllErrors asserts that when the
// fast-path aggregate compile fails, every broken rule (not just the first)
// is surfaced in one pass — this is the contract the per-rule fallback exists
// to uphold.
func TestValidateIssuanceCEL_FallbackSurfacesAllErrors(t *testing.T) {
	errs := validateIssuanceCEL([]v1alpha1.IssuanceRule{
		{Name: "ok", CEL: "true", Message: "m"},
		{Name: "broken-1", CEL: "this is not CEL", Message: "m"},
		{Name: "broken-2", CEL: "also not CEL %%", Message: "m"},
	})
	got := make(map[string]bool, len(errs))
	for _, e := range errs {
		got[e.ruleName] = true
	}
	assert.False(t, got["ok"], "valid rule should not appear in errs")
	assert.True(t, got["broken-1"], "first broken rule should be reported")
	assert.True(t, got["broken-2"], "second broken rule should also be reported in the same pass")
}
