package celverify

import (
	"errors"
	"strings"
	"testing"
)

func TestCompile_Success(t *testing.T) {
	programs, err := Compile([]Rule{
		{Name: "scope-ok", CEL: `txtoken.scope.contains("read:datasets")`, Message: "missing read scope"},
		{Name: "method-ok", CEL: `request.method == "GET"`, Message: "only GET allowed"},
	})
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	if len(programs) != 2 {
		t.Fatalf("Compile returned %d programs, want 2", len(programs))
	}
}

func TestCompile_EmptyInput(t *testing.T) {
	programs, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile(nil) returned error: %v", err)
	}
	if programs != nil {
		t.Fatalf("Compile(nil) returned non-nil programs: %v", programs)
	}
}

func TestCompile_EmptyExpression(t *testing.T) {
	_, err := Compile([]Rule{{Name: "blank", CEL: "", Message: "x"}})
	if err == nil {
		t.Fatal("Compile with empty CEL should fail")
	}
	if !strings.Contains(err.Error(), "empty CEL expression") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompile_SyntaxError(t *testing.T) {
	_, err := Compile([]Rule{{Name: "bad", CEL: "this is not cel ((", Message: "x"}})
	if err == nil {
		t.Fatal("Compile with bad CEL should fail")
	}
	if !strings.Contains(err.Error(), `compiling verification rule "bad"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompile_NonBoolOutput(t *testing.T) {
	_, err := Compile([]Rule{{Name: "int-rule", CEL: `1 + 1`, Message: "x"}})
	if err == nil {
		t.Fatal("Compile with non-bool CEL should fail")
	}
	if !strings.Contains(err.Error(), "must return bool") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEvaluate_AllPass(t *testing.T) {
	programs, err := Compile([]Rule{
		{Name: "scope-ok", CEL: `txtoken.scope.contains("read:datasets")`, Message: "missing read scope"},
		{Name: "classification-ok", CEL: `txtoken.tctx.classification in ["public", "internal"]`, Message: "bad classification"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ctx := &Context{
		TxToken: map[string]any{
			"scope": "read:datasets execute:analysis",
			"tctx":  map[string]any{"classification": "public"},
		},
		Request: map[string]any{"path": "/api/v1/data", "method": "GET"},
	}

	if err := Evaluate(programs, ctx); err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
}

func TestEvaluate_Denied(t *testing.T) {
	programs, err := Compile([]Rule{
		{Name: "no-pii", CEL: `txtoken.tctx.classification != "pii"`, Message: "PII access blocked"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ctx := &Context{
		TxToken: map[string]any{
			"tctx": map[string]any{"classification": "pii"},
		},
	}

	err = Evaluate(programs, ctx)
	if err == nil {
		t.Fatal("Evaluate should have denied")
	}
	var denied *DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *DeniedError, got %T: %v", err, err)
	}
	if denied.RuleName != "no-pii" {
		t.Errorf("RuleName = %q, want %q", denied.RuleName, "no-pii")
	}
	if denied.Message != "PII access blocked" {
		t.Errorf("Message = %q, want %q", denied.Message, "PII access blocked")
	}
	// Error() must not inject literal double-quotes around RuleName: the
	// string is embedded into a JSON response body downstream and naked %q
	// quoting is a JSON-injection vector.
	if strings.Contains(err.Error(), `"no-pii"`) {
		t.Errorf("Error() should not quote RuleName, got: %s", err.Error())
	}
}

func TestEvaluate_RuntimeError(t *testing.T) {
	programs, err := Compile([]Rule{
		{Name: "missing-field", CEL: `txtoken.tctx.classification == "pii"`, Message: "x"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// tctx has no classification field — CEL field access on absent key errors.
	ctx := &Context{TxToken: map[string]any{"tctx": map[string]any{}}}

	err = Evaluate(programs, ctx)
	if err == nil {
		t.Fatal("Evaluate should error on missing field")
	}
	var denied *DeniedError
	if errors.As(err, &denied) {
		t.Fatalf("runtime error should not be a DeniedError, got: %v", err)
	}
}

func TestEvaluate_EmptyContexts(t *testing.T) {
	// CEL expressions that don't dereference txtoken/request should work
	// with nil maps (Evaluate defaults them to empty).
	programs, err := Compile([]Rule{{Name: "trivial", CEL: `true`, Message: "x"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if err := Evaluate(programs, &Context{}); err != nil {
		t.Fatalf("Evaluate with empty Context: %v", err)
	}
}

func TestEvaluate_NoPrograms(t *testing.T) {
	if err := Evaluate(nil, &Context{}); err != nil {
		t.Fatalf("Evaluate(nil) returned error: %v", err)
	}
}

func TestEvaluate_FirstFailingRuleWins(t *testing.T) {
	programs, err := Compile([]Rule{
		{Name: "first", CEL: `txtoken.scope == "ok"`, Message: "first failed"},
		{Name: "second", CEL: `false`, Message: "second failed"},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	ctx := &Context{TxToken: map[string]any{"scope": "not-ok"}}

	err = Evaluate(programs, ctx)
	var denied *DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected DeniedError, got: %v", err)
	}
	if denied.RuleName != "first" {
		t.Errorf("RuleName = %q, want %q", denied.RuleName, "first")
	}
}
