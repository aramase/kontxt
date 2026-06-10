package ruleclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/tts"
)

func newTestHandler(t *testing.T) *tts.Handler {
	t.Helper()
	km, err := keys.NewManager(2048, time.Hour)
	require.NoError(t, err)
	router := authn.NewRouter(nil)
	return tts.NewHandler(router, km, "https://tts.example.com", "trust-domain.example.com", 15*time.Second)
}

func TestHandlerSetter_NilHandler(t *testing.T) {
	s := &HandlerSetter{Handler: nil}
	err := s.SetIssuanceRules(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "handler is nil")
}

func TestHandlerSetter_EmptyRules(t *testing.T) {
	s := NewHandlerSetter(newTestHandler(t))
	require.NoError(t, s.SetIssuanceRules(nil))
	require.NoError(t, s.SetIssuanceRules([]controller.IssuanceRule{}))
}

func TestHandlerSetter_ValidRulesApplied(t *testing.T) {
	s := NewHandlerSetter(newTestHandler(t))
	err := s.SetIssuanceRules([]controller.IssuanceRule{
		{PolicyName: "p1", RuleName: "r1", CEL: "true", Message: "ok",
			TargetNamespaces: []string{"team-alpha"}},
	})
	require.NoError(t, err)
}

func TestHandlerSetter_BrokenCEL_Errors(t *testing.T) {
	s := NewHandlerSetter(newTestHandler(t))
	err := s.SetIssuanceRules([]controller.IssuanceRule{
		{PolicyName: "p1", RuleName: "broken", CEL: "this is not valid CEL", Message: "x"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compiling issuance rules")
}

func TestQualifiedName(t *testing.T) {
	cases := []struct {
		name string
		in   controller.IssuanceRule
		want string
	}{
		{"both", controller.IssuanceRule{PolicyName: "p1", RuleName: "r1"}, "p1/r1"},
		{"only-rule", controller.IssuanceRule{RuleName: "r1"}, "r1"},
		{"namespaced-policy", controller.IssuanceRule{PolicyNamespace: "team-a", PolicyName: "p1", RuleName: "r1"}, "team-a/p1/r1"},
		{"namespaced-policy-no-name", controller.IssuanceRule{PolicyNamespace: "team-a", RuleName: "r1"}, "team-a/r1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, qualifiedName(tc.in))
		})
	}
}
