package server

import (
	"context"
	"fmt"

	"github.com/dexidp/dex/pkg/cel"
	"github.com/dexidp/dex/storage"
)

// CompiledAuthPolicy holds compiled CEL programs for a single policy expression.
type CompiledAuthPolicy struct {
	Expression *cel.CompilationResult
	Message    *cel.CompilationResult // nil if no message expression
	Raw        storage.PolicyExpression
}

// CompileAuthPolicies compiles a slice of PolicyExpression using the given compiler.
// Expression must evaluate to bool, Message (if set) must evaluate to string.
func CompileAuthPolicies(compiler *cel.Compiler, policies []storage.PolicyExpression) ([]CompiledAuthPolicy, error) {
	compiled := make([]CompiledAuthPolicy, 0, len(policies))

	for i, p := range policies {
		if p.Expression == "" {
			return nil, fmt.Errorf("authPolicy[%d]: expression is required", i)
		}

		exprResult, err := compiler.CompileBool(p.Expression)
		if err != nil {
			return nil, fmt.Errorf("authPolicy[%d]: compiling expression: %w", i, err)
		}

		var msgResult *cel.CompilationResult
		if p.Message != "" {
			msgResult, err = compiler.CompileString(p.Message)
			if err != nil {
				return nil, fmt.Errorf("authPolicy[%d]: compiling message: %w", i, err)
			}
		}

		compiled = append(compiled, CompiledAuthPolicy{
			Expression: exprResult,
			Message:    msgResult,
			Raw:        p,
		})
	}

	return compiled, nil
}

// EvaluateAuthPolicy evaluates compiled policies against identity and request variables.
// Returns (denied bool, message string, err error). First matching rule wins.
func EvaluateAuthPolicy(ctx context.Context, policies []CompiledAuthPolicy, identity, request map[string]any) (bool, string, error) {
	if len(policies) == 0 {
		return false, "", nil
	}

	vars := map[string]any{
		"identity": identity,
		"request":  request,
	}

	for _, p := range policies {
		denied, err := cel.EvalBool(ctx, p.Expression, vars)
		if err != nil {
			return false, "", fmt.Errorf("evaluating expression %q: %w", p.Raw.Expression, err)
		}

		if !denied {
			continue
		}

		msg := ErrMsgAuthPolicyDenied
		if p.Message != nil {
			evalMsg, err := cel.EvalString(ctx, p.Message, vars)
			if err != nil {
				return false, "", fmt.Errorf("evaluating message for expression %q: %w", p.Raw.Expression, err)
			}
			if evalMsg != "" {
				msg = evalMsg
			}
		}

		return true, msg, nil
	}

	return false, "", nil
}
