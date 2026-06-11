// Package celverify compiles and evaluates CEL expressions for ServiceTokenRequirement
// verification rules. It is kept free of controller and extauth imports so both the
// controller (for pre-validation at reconcile time) and the ext-auth server (for
// evaluation at request time) can use the same compile path.
package celverify

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// Rule is the input form of a verification CEL rule.
type Rule struct {
	Name    string
	CEL     string
	Message string
}

// Program is a compiled verification CEL rule ready for evaluation.
type Program struct {
	Name    string
	program cel.Program
	message string
}

// Context contains the variables exposed to verification CEL expressions.
//
// Per the API contract (api/v1alpha1.VerificationRule.CEL), the available
// variables are:
//   - txtoken: the parsed TxToken claims (subject, scope, tctx, rctx, ...).
//   - request: HTTP request attributes (path, method, headers).
type Context struct {
	TxToken map[string]any
	Request map[string]any
}

// DeniedError is returned when a verification rule evaluates to false.
type DeniedError struct {
	RuleName string
	Message  string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("verification denied by rule %s: %s", e.RuleName, e.Message)
}

// NewEnv returns the CEL environment used for verification rules. Exported so
// callers that want to validate expressions without compiling a full program
// (e.g. webhook admission) can reuse the same variable set.
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("txtoken", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
}

// Compile compiles a list of verification rules into executable programs. It
// fails on the first invalid rule so callers (controller reconciler or ext-auth
// server) can surface a single deterministic error to operators.
func Compile(rules []Rule) ([]Program, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	out := make([]Program, 0, len(rules))
	for i, r := range rules {
		if r.CEL == "" {
			return nil, fmt.Errorf("verification rule %d (%q): empty CEL expression", i, r.Name)
		}

		ast, issues := env.Compile(r.CEL)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compiling verification rule %q: %w", r.Name, issues.Err())
		}

		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("verification rule %q: expression must return bool, got %s", r.Name, ast.OutputType())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("creating program for verification rule %q: %w", r.Name, err)
		}

		out = append(out, Program{
			Name:    r.Name,
			program: prg,
			message: r.Message,
		})
	}

	return out, nil
}

// Evaluate runs every compiled program against the supplied context and returns
// a DeniedError as soon as one rule rejects the request. Returns nil if every
// rule passes (or if there are no programs to evaluate).
func Evaluate(programs []Program, ctx *Context) error {
	if len(programs) == 0 {
		return nil
	}

	activation := map[string]any{
		"txtoken": ctx.TxToken,
		"request": ctx.Request,
	}
	// Default nil maps to empty maps so CEL field-access on absent objects
	// yields a clean error rather than a nil-deref.
	if activation["txtoken"] == nil {
		activation["txtoken"] = map[string]any{}
	}
	if activation["request"] == nil {
		activation["request"] = map[string]any{}
	}

	for _, p := range programs {
		out, _, err := p.program.Eval(activation)
		if err != nil {
			return fmt.Errorf("evaluating verification rule %q: %w", p.Name, err)
		}

		if out.Type() != types.BoolType {
			return fmt.Errorf("verification rule %q returned %s, expected bool", p.Name, out.Type())
		}

		if !out.Value().(bool) {
			return &DeniedError{RuleName: p.Name, Message: p.message}
		}
	}

	return nil
}
