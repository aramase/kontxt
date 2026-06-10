package ruleclient

import (
	"fmt"

	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/pkg/tts"
)

// HandlerSetter adapts controller.IssuanceRule snapshots into compiled
// tts.IssuanceRule sets and applies them to a TTS Handler. Lives in the
// ruleclient package so pkg/tts does not depend on internal/controller.
type HandlerSetter struct {
	Handler *tts.Handler
}

// NewHandlerSetter returns an IssuanceSetter backed by the given handler.
func NewHandlerSetter(h *tts.Handler) *HandlerSetter {
	return &HandlerSetter{Handler: h}
}

// SetIssuanceRules compiles every CEL expression and replaces the handler's
// rule set. Returns an error if any rule fails to compile so the caller can
// keep the previous valid set in place.
func (s *HandlerSetter) SetIssuanceRules(rules []controller.IssuanceRule) error {
	if s.Handler == nil {
		return fmt.Errorf("handler is nil")
	}

	configs := make([]tts.IssuanceRuleConfig, len(rules))
	for i, r := range rules {
		configs[i] = tts.IssuanceRuleConfig{
			Name:             qualifiedName(r),
			CEL:              r.CEL,
			Message:          r.Message,
			TargetNamespaces: append([]string(nil), r.TargetNamespaces...),
		}
	}

	compiled, err := tts.CompileIssuanceRules(configs)
	if err != nil {
		return fmt.Errorf("compiling issuance rules: %w", err)
	}
	s.Handler.SetIssuanceRules(compiled)
	return nil
}

// qualifiedName produces a unique rule identifier for error messages of the
// form "[<policyNamespace>/]<policyName>/<ruleName>". PolicyNamespace is
// omitted today because TokenPolicy is cluster-scoped, but it is included
// when present so the identifier stays unambiguous if the CRD becomes
// namespaced in the future.
func qualifiedName(r controller.IssuanceRule) string {
	name := r.RuleName
	if r.PolicyName != "" {
		name = r.PolicyName + "/" + name
	}
	if r.PolicyNamespace != "" {
		name = r.PolicyNamespace + "/" + name
	}
	return name
}
