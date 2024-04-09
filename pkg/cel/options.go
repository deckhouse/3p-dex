package cel

import "github.com/google/cel-go/cel"

type compilation struct {
	outputType *cel.Type
	errMsg     string
}

type CompileOption func(c *compilation) (*compilation, error)

func WithReturnType(outputType *cel.Type) CompileOption {
	return func(c *compilation) (*compilation, error) {
		c.outputType = outputType
		return c, nil
	}
}

func WithErrMessage(errMsg string) CompileOption {
	return func(c *compilation) (*compilation, error) {
		c.errMsg = errMsg
		return c, nil
	}
}
