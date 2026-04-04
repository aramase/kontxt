package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileValidationRules_ValidExpression(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	rules := []ClaimValidationRule{
		{Expression: `claims.iss == "https://example.com"`, Message: "wrong issuer"},
	}

	compiled, err := compileValidationRules(env, rules)
	require.NoError(t, err)
	assert.Len(t, compiled, 1)
}

func TestCompileValidationRules_InvalidExpression(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	rules := []ClaimValidationRule{
		{Expression: `this is not valid CEL`, Message: "bad"},
	}

	_, err = compileValidationRules(env, rules)
	assert.Error(t, err)
}

func TestCompileValidationRules_NonBoolExpression(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	rules := []ClaimValidationRule{
		{Expression: `claims.iss`, Message: "returns string not bool"},
	}

	_, err = compileValidationRules(env, rules)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must return bool")
}

func TestEvaluateValidationRules_Pass(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	rules := []ClaimValidationRule{
		{Expression: `claims.iss == "https://example.com"`, Message: "wrong issuer"},
	}

	compiled, err := compileValidationRules(env, rules)
	require.NoError(t, err)

	err = evaluateValidationRules(compiled, map[string]any{
		"iss": "https://example.com",
	})
	assert.NoError(t, err)
}

func TestEvaluateValidationRules_Fail(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	rules := []ClaimValidationRule{
		{Expression: `claims.iss == "https://example.com"`, Message: "wrong issuer"},
	}

	compiled, err := compileValidationRules(env, rules)
	require.NoError(t, err)

	err = evaluateValidationRules(compiled, map[string]any{
		"iss": "https://other.com",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wrong issuer")
}

func TestEvaluateValidationRules_MultipleRules(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	rules := []ClaimValidationRule{
		{Expression: `claims.iss == "https://example.com"`, Message: "wrong issuer"},
		{Expression: `claims.aud == "my-app"`, Message: "wrong audience"},
	}

	compiled, err := compileValidationRules(env, rules)
	require.NoError(t, err)

	// Both pass
	err = evaluateValidationRules(compiled, map[string]any{
		"iss": "https://example.com",
		"aud": "my-app",
	})
	assert.NoError(t, err)

	// First passes, second fails
	err = evaluateValidationRules(compiled, map[string]any{
		"iss": "https://example.com",
		"aud": "other-app",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wrong audience")
}

func TestSubjectMapping_SimpleClaim(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	mapping := ClaimOrExpression{Claim: "email"}
	program, err := compileSubjectMapping(env, mapping)
	require.NoError(t, err)
	assert.Nil(t, program) // no CEL program needed for simple claim

	subject, err := evaluateSubjectMapping(mapping, program, map[string]any{
		"email": "user@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", subject)
}

func TestSubjectMapping_SimpleClaim_Missing(t *testing.T) {
	mapping := ClaimOrExpression{Claim: "email"}
	_, err := evaluateSubjectMapping(mapping, nil, map[string]any{
		"sub": "12345",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSubjectMapping_CELExpression(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	mapping := ClaimOrExpression{Expression: `claims.oid`}
	program, err := compileSubjectMapping(env, mapping)
	require.NoError(t, err)
	require.NotNil(t, program)

	subject, err := evaluateSubjectMapping(mapping, program, map[string]any{
		"oid": "00000000-0000-0000-0000-000000000001",
	})
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", subject)
}

func TestExtraMappings(t *testing.T) {
	env, err := newCELEnv()
	require.NoError(t, err)

	mappings := []ExtraMapping{
		{Key: "tenant", ValueExpression: `claims.tid`},
		{Key: "name", ValueExpression: `claims.name`},
	}

	compiled, err := compileExtraMappings(env, mappings)
	require.NoError(t, err)

	extra, err := evaluateExtraMappings(compiled, map[string]any{
		"tid":  "tenant-123",
		"name": "Jane Doe",
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-123", extra["tenant"])
	assert.Equal(t, "Jane Doe", extra["name"])
}

func TestExtraMappings_Empty(t *testing.T) {
	compiled, err := compileExtraMappings(nil, nil)
	require.NoError(t, err)
	assert.Empty(t, compiled)

	extra, err := evaluateExtraMappings(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, extra)
}
