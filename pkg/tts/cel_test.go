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
