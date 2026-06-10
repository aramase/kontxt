package tts

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileIssuanceRules_Valid(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{Name: "check-scope", CEL: `scope == "read:data"`, Message: "wrong scope"},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.Equal(t, "check-scope", rules[0].Name)
}

func TestCompileIssuanceRules_InvalidCEL(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{Name: "bad", CEL: `not valid cel!!!`, Message: "bad"},
	}

	_, err := CompileIssuanceRules(configs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "compiling issuance rule")
}

func TestCompileIssuanceRules_NonBoolReturn(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{Name: "returns-string", CEL: `subject`, Message: "returns string"},
	}

	_, err := CompileIssuanceRules(configs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must return bool")
}

func TestCompileIssuanceRules_EmptyCEL(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{Name: "empty", CEL: "", Message: "empty"},
	}

	_, err := CompileIssuanceRules(configs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty CEL")
}

func TestCompileIssuanceRules_Empty(t *testing.T) {
	rules, err := CompileIssuanceRules(nil)
	require.NoError(t, err)
	assert.Nil(t, rules)
}

func TestEvaluateIssuanceRules_AllPass(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{Name: "check-subject", CEL: `subject == "user@example.com"`, Message: "wrong subject"},
		{Name: "check-scope", CEL: `scope == "read:data"`, Message: "wrong scope"},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)

	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "user@example.com",
		Scope:   "read:data",
	})
	assert.NoError(t, err)
}

func TestEvaluateIssuanceRules_FirstFails(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{Name: "check-subject", CEL: `subject == "user@example.com"`, Message: "wrong subject"},
		{Name: "check-scope", CEL: `scope == "read:data"`, Message: "wrong scope"},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)

	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "attacker@evil.com",
		Scope:   "read:data",
	})
	require.Error(t, err)

	var denied *IssuanceDeniedError
	require.True(t, errors.As(err, &denied))
	assert.Equal(t, "check-subject", denied.RuleName)
	assert.Equal(t, "wrong subject", denied.Message)
}

func TestEvaluateIssuanceRules_SecondFails(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{Name: "check-subject", CEL: `subject == "user@example.com"`, Message: "wrong subject"},
		{Name: "check-scope", CEL: `scope == "admin:all"`, Message: "wrong scope"},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)

	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "user@example.com",
		Scope:   "read:data",
	})
	require.Error(t, err)

	var denied *IssuanceDeniedError
	require.True(t, errors.As(err, &denied))
	assert.Equal(t, "check-scope", denied.RuleName)
}

func TestEvaluateIssuanceRules_TctxAccess(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{
			Name:    "public-only",
			CEL:     `tctx.classification == "public"`,
			Message: "only public data allowed",
		},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)

	// Pass: classification is public
	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "user@example.com",
		Scope:   "read:data",
		Tctx:    map[string]any{"classification": "public"},
	})
	assert.NoError(t, err)

	// Fail: classification is pii
	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "user@example.com",
		Scope:   "read:data",
		Tctx:    map[string]any{"classification": "pii"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only public data allowed")
}

func TestEvaluateIssuanceRules_RctxAccess(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{
			Name:    "check-authn",
			CEL:     `rctx.authn == "oidc"`,
			Message: "must authenticate via OIDC",
		},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)

	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "user@example.com",
		Scope:   "read:data",
		Rctx:    map[string]any{"authn": "oidc"},
	})
	assert.NoError(t, err)

	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "user@example.com",
		Scope:   "read:data",
		Rctx:    map[string]any{"authn": "kubernetes-sa"},
	})
	assert.Error(t, err)
}

func TestEvaluateIssuanceRules_WorkloadAndNamespace(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{
			Name:    "restrict-namespace",
			CEL:     `workload_ns == "team-alpha"`,
			Message: "only team-alpha allowed",
		},
		{
			Name:    "restrict-workload",
			CEL:     `workload != "malicious-agent"`,
			Message: "blocked workload",
		},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)

	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject:    "user@example.com",
		Scope:      "read:data",
		Workload:   "good-agent",
		WorkloadNS: "team-alpha",
	})
	assert.NoError(t, err)

	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject:    "user@example.com",
		Scope:      "read:data",
		Workload:   "malicious-agent",
		WorkloadNS: "team-alpha",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked workload")
}

func TestEvaluateIssuanceRules_NilMapsDefaultToEmpty(t *testing.T) {
	configs := []IssuanceRuleConfig{
		{
			Name:    "always-pass",
			CEL:     `subject != ""`,
			Message: "subject required",
		},
	}

	rules, err := CompileIssuanceRules(configs)
	require.NoError(t, err)

	// nil tctx and rctx should not cause runtime errors
	err = EvaluateIssuanceRules(rules, &IssuanceContext{
		Subject: "user@example.com",
		Scope:   "read:data",
		Tctx:    nil,
		Rctx:    nil,
	})
	assert.NoError(t, err)
}

func TestEvaluateIssuanceRules_Empty(t *testing.T) {
	err := EvaluateIssuanceRules(nil, &IssuanceContext{Subject: "user"})
	assert.NoError(t, err, "no rules means no denial")
}

func TestIssuanceDeniedError_Format(t *testing.T) {
	err := &IssuanceDeniedError{RuleName: "test-rule", Message: "denied!"}
	assert.Contains(t, err.Error(), "test-rule")
	assert.Contains(t, err.Error(), "denied!")
}

func TestScopeContains(t *testing.T) {
	assert.True(t, ScopeContains("read:data write:reports", "read:data"))
	assert.True(t, ScopeContains("read:data write:reports", "write:reports"))
	assert.False(t, ScopeContains("read:data write:reports", "admin:all"))
	assert.False(t, ScopeContains("", "read:data"))
	assert.True(t, ScopeContains("single-scope", "single-scope"))
}

// TestRuleAppliesToNamespace_EmptyWorkloadNS verifies that a request with no
// identified workload namespace never matches a targeted rule, even when a
// misconfigured policy includes an empty string in matchNames. This locks
// the safety guard against silent namespace-scoped rule activation when the
// caller's namespace is unknown.
func TestRuleAppliesToNamespace_EmptyWorkloadNS(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
		want    bool
	}{
		{"empty-targets-cluster-wide", nil, true},
		{"named-targets-only", []string{"team-alpha", "team-beta"}, false},
		{"targets-include-empty-string", []string{"team-alpha", ""}, false},
		{"targets-only-empty-string", []string{""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ruleAppliesToNamespace(tc.targets, ""))
		})
	}
}

func TestEvaluateIssuanceRules_NamespaceFiltering(t *testing.T) {
	// Two rules: one targets team-alpha (would always deny), one is cluster-wide.
	rules, err := CompileIssuanceRules([]IssuanceRuleConfig{
		{
			Name:             "alpha-only-deny",
			CEL:              "false",
			Message:          "always deny for team-alpha",
			TargetNamespaces: []string{"team-alpha"},
		},
		{
			Name:    "cluster-wide-allow",
			CEL:     "true",
			Message: "always allow",
		},
	})
	require.NoError(t, err)

	// Request from team-alpha: targeted rule applies, must deny.
	err = EvaluateIssuanceRules(rules, &IssuanceContext{Subject: "user", WorkloadNS: "team-alpha"})
	require.Error(t, err)
	assert.IsType(t, &IssuanceDeniedError{}, err)

	// Request from team-beta: only the cluster-wide rule applies, no denial.
	err = EvaluateIssuanceRules(rules, &IssuanceContext{Subject: "user", WorkloadNS: "team-beta"})
	assert.NoError(t, err)

	// Request with no WorkloadNS (e.g. unauthenticated context): targeted rules
	// must NOT apply (don't accidentally trip on missing context).
	err = EvaluateIssuanceRules(rules, &IssuanceContext{Subject: "user", WorkloadNS: ""})
	assert.NoError(t, err)
}
