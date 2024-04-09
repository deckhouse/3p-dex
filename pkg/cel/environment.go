package cel

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

type TokenEnv struct {
	internalEnv *cel.Env
}

func NewTokenEnv() (*TokenEnv, error) {
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("claims", decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar("now", decls.Int), // Unix timestamp
		),
		ext.Encoders(),
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
	)
	if err != nil {
		return nil, err
	}

	return &TokenEnv{internalEnv: env}, nil
}

func (e *TokenEnv) Compile(expr string, opts ...CompileOption) (*TokenProgram, error) {
	var err error
	comp := &compilation{}

	for _, ops := range opts {
		comp, err = ops(comp)
		if err != nil {
			return nil, fmt.Errorf("unexcepted option: %v", err)
		}
	}

	ast, issues := e.internalEnv.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}

	if comp.outputType != nil && !ast.OutputType().IsExactType(comp.outputType) {
		return nil, fmt.Errorf("unexcepted output type %q, expected %q", ast.OutputType(), comp.outputType)
	}

	prog, err := e.internalEnv.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("program creation failed: %v", err)
	}

	return &TokenProgram{internalProg: prog}, nil
}

type TokenProgram struct {
	internalProg cel.Program
}

func (p *TokenProgram) Eval(claims map[string]interface{}) (ref.Val, *cel.EvalDetails, error) {
	data := map[string]interface{}{
		"now":    time.Now().Unix(),
		"claims": claims,
	}
	return p.internalProg.Eval(data)
}
