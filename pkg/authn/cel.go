package authn

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// compiledRule is a pre-compiled CEL expression for claim validation.
type compiledRule struct {
	program cel.Program
	message string
}

// compiledMapping is a pre-compiled CEL expression for claim mapping.
type compiledMapping struct {
	program cel.Program
	key     string // for extra mappings
}

// newCELEnv creates a CEL environment with a `claims` variable available as a dynamic map.
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("claims", cel.DynType),
	)
}

// compileValidationRules compiles a list of claim validation rules into CEL programs.
func compileValidationRules(env *cel.Env, rules []ClaimValidationRule) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, rule := range rules {
		ast, issues := env.Compile(rule.Expression)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compiling validation rule %d (%q): %w", i, rule.Expression, issues.Err())
		}
		// Ensure the expression returns a bool
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("validation rule %d (%q): expression must return bool, got %s", i, rule.Expression, ast.OutputType())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("creating program for validation rule %d: %w", i, err)
		}
		compiled = append(compiled, compiledRule{program: prg, message: rule.Message})
	}
	return compiled, nil
}

// evaluateValidationRules runs all compiled validation rules against the claims.
// Returns an error with the rule's message if any rule returns false.
func evaluateValidationRules(rules []compiledRule, claims map[string]any) error {
	for _, rule := range rules {
		out, _, err := rule.program.Eval(map[string]any{
			"claims": claims,
		})
		if err != nil {
			return fmt.Errorf("evaluating validation rule: %w", err)
		}
		if out.Type() != types.BoolType {
			return fmt.Errorf("validation rule returned %s, expected bool", out.Type())
		}
		if out.Value().(bool) == false {
			return fmt.Errorf("claim validation failed: %s", rule.message)
		}
	}
	return nil
}

// compileSubjectMapping compiles the subject claim mapping.
// Returns nil program if a simple claim reference is used (no CEL needed).
func compileSubjectMapping(env *cel.Env, mapping ClaimOrExpression) (cel.Program, error) {
	if mapping.Expression == "" {
		return nil, nil // simple claim reference, no CEL
	}
	ast, issues := env.Compile(mapping.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compiling subject mapping expression %q: %w", mapping.Expression, issues.Err())
	}
	// Allow both string and dyn output types. Dynamic maps (claims) return dyn
	// for field access. The runtime value will be converted to string.
	outType := ast.OutputType()
	if outType != cel.StringType && outType != cel.DynType {
		return nil, fmt.Errorf("subject mapping expression %q must return string, got %s", mapping.Expression, outType)
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("creating program for subject mapping: %w", err)
	}
	return prg, nil
}

// evaluateSubjectMapping extracts the subject from claims using either a simple claim
// reference or a CEL expression.
func evaluateSubjectMapping(mapping ClaimOrExpression, program cel.Program, claims map[string]any) (string, error) {
	if mapping.Claim != "" {
		// Simple claim reference
		val, ok := claims[mapping.Claim]
		if !ok {
			return "", fmt.Errorf("subject claim %q not found in token", mapping.Claim)
		}
		s, ok := val.(string)
		if !ok {
			return "", fmt.Errorf("subject claim %q is not a string", mapping.Claim)
		}
		return s, nil
	}

	// CEL expression
	if program == nil {
		return "", fmt.Errorf("no subject mapping configured")
	}
	out, _, err := program.Eval(map[string]any{
		"claims": claims,
	})
	if err != nil {
		return "", fmt.Errorf("evaluating subject mapping: %w", err)
	}
	return out.Value().(string), nil
}

// compileExtraMappings compiles extra claim mappings into CEL programs.
func compileExtraMappings(env *cel.Env, mappings []ExtraMapping) ([]compiledMapping, error) {
	compiled := make([]compiledMapping, 0, len(mappings))
	for i, m := range mappings {
		ast, issues := env.Compile(m.ValueExpression)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compiling extra mapping %d (%q): %w", i, m.ValueExpression, issues.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("creating program for extra mapping %d: %w", i, err)
		}
		compiled = append(compiled, compiledMapping{program: prg, key: m.Key})
	}
	return compiled, nil
}

// evaluateExtraMappings runs compiled extra mappings against the claims.
func evaluateExtraMappings(mappings []compiledMapping, claims map[string]any) (map[string]string, error) {
	if len(mappings) == 0 {
		return nil, nil
	}
	extra := make(map[string]string, len(mappings))
	for _, m := range mappings {
		out, _, err := m.program.Eval(map[string]any{
			"claims": claims,
		})
		if err != nil {
			return nil, fmt.Errorf("evaluating extra mapping %q: %w", m.key, err)
		}
		extra[m.key] = refValueToString(out)
	}
	return extra, nil
}

// refValueToString converts a CEL ref.Val to a string.
func refValueToString(v ref.Val) string {
	if v.Type() == types.StringType {
		return v.Value().(string)
	}
	return fmt.Sprintf("%v", v.Value())
}
