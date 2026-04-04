package tts

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// IssuanceRule is a compiled CEL issuance rule evaluated before token issuance.
type IssuanceRule struct {
	Name    string
	program cel.Program
	message string
}

// IssuanceRuleConfig is the configuration for an issuance rule (from TokenPolicy).
type IssuanceRuleConfig struct {
	Name    string `json:"name" yaml:"name"`
	CEL     string `json:"cel" yaml:"cel"`
	Message string `json:"message" yaml:"message"`
}

// IssuanceContext contains the variables available to CEL issuance rules.
type IssuanceContext struct {
	Subject    string
	Scope      string
	Tctx       map[string]any
	Rctx       map[string]any
	Workload   string
	WorkloadNS string
}

// newIssuanceCELEnv creates a CEL environment for issuance rules.
func newIssuanceCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("subject", cel.StringType),
		cel.Variable("scope", cel.StringType),
		cel.Variable("tctx", cel.DynType),
		cel.Variable("rctx", cel.DynType),
		cel.Variable("workload", cel.StringType),
		cel.Variable("workload_ns", cel.StringType),
	)
}

// CompileIssuanceRules compiles a list of issuance rule configs into executable programs.
func CompileIssuanceRules(configs []IssuanceRuleConfig) ([]IssuanceRule, error) {
	if len(configs) == 0 {
		return nil, nil
	}

	env, err := newIssuanceCELEnv()
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	rules := make([]IssuanceRule, 0, len(configs))
	for i, cfg := range configs {
		if cfg.CEL == "" {
			return nil, fmt.Errorf("issuance rule %d (%q): empty CEL expression", i, cfg.Name)
		}

		ast, issues := env.Compile(cfg.CEL)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("compiling issuance rule %q: %w", cfg.Name, issues.Err())
		}

		// Must return bool
		if ast.OutputType() != cel.BoolType {
			return nil, fmt.Errorf("issuance rule %q: expression must return bool, got %s", cfg.Name, ast.OutputType())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("creating program for issuance rule %q: %w", cfg.Name, err)
		}

		rules = append(rules, IssuanceRule{
			Name:    cfg.Name,
			program: prg,
			message: cfg.Message,
		})
	}

	return rules, nil
}

// EvaluateIssuanceRules evaluates all compiled issuance rules against the given context.
// Returns nil if all rules pass. Returns an error with the failing rule's message otherwise.
func EvaluateIssuanceRules(rules []IssuanceRule, ictx *IssuanceContext) error {
	if len(rules) == 0 {
		return nil
	}

	// Build the activation map
	activation := map[string]any{
		"subject":     ictx.Subject,
		"scope":       ictx.Scope,
		"tctx":        ictx.Tctx,
		"rctx":        ictx.Rctx,
		"workload":    ictx.Workload,
		"workload_ns": ictx.WorkloadNS,
	}

	// Default nil maps to empty maps for CEL
	if activation["tctx"] == nil {
		activation["tctx"] = map[string]any{}
	}
	if activation["rctx"] == nil {
		activation["rctx"] = map[string]any{}
	}

	for _, rule := range rules {
		out, _, err := rule.program.Eval(activation)
		if err != nil {
			return fmt.Errorf("evaluating issuance rule %q: %w", rule.Name, err)
		}

		if out.Type() != types.BoolType {
			return fmt.Errorf("issuance rule %q returned %s, expected bool", rule.Name, out.Type())
		}

		if !out.Value().(bool) {
			return &IssuanceDeniedError{
				RuleName: rule.Name,
				Message:  rule.message,
			}
		}
	}

	return nil
}

// IssuanceDeniedError is returned when an issuance rule evaluates to false.
type IssuanceDeniedError struct {
	RuleName string
	Message  string
}

func (e *IssuanceDeniedError) Error() string {
	return fmt.Sprintf("issuance denied by rule %q: %s", e.RuleName, e.Message)
}

// ScopeContains checks if a space-delimited scope string contains a specific scope.
// This is a helper function available for use in application code; CEL rules use
// string operations directly.
func ScopeContains(scopeString, target string) bool {
	for _, s := range strings.Fields(scopeString) {
		if s == target {
			return true
		}
	}
	return false
}
