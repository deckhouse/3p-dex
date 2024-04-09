package policy

import (
	"fmt"

	"github.com/dexidp/dex/pkg/cel"
)

// ClaimPolicy is an interface for a policy that can be applied to a token claims.
type ClaimPolicy interface {
	Apply(map[string]interface{}) error
}

// ValidateClaimPolicy is a policy that validates a claim in a token.
type validateClaimPolicy struct {
	prog    *cel.TokenProgram
	message string
}

func newValidateClaimPolicy(prog *cel.TokenProgram, message string) *validateClaimPolicy {
	return &validateClaimPolicy{
		prog:    prog,
		message: message,
	}
}

func (v *validateClaimPolicy) Apply(input map[string]interface{}) error {
	val, _, err := v.prog.Eval(input)
	if err != nil {
		return err
	}

	// The fact that the prog returns a boolean is guaranteed by the Compile function.
	if r, ok := val.Value().(bool); ok && r == false {
		if v.message != "" {
			return fmt.Errorf(v.message)
		} else {
			return fmt.Errorf("validation failed")
		}
	}

	return nil
}

// mutateClaimPolicy is a policy that mutates a claim in a token.
type mutateClaimPolicy struct {
	prog  *cel.TokenProgram
	claim string
}

func newMutateClaimPolicy(prog *cel.TokenProgram, claim string) *mutateClaimPolicy {
	return &mutateClaimPolicy{
		prog:  prog,
		claim: claim,
	}
}

func (m *mutateClaimPolicy) Apply(input map[string]interface{}) error {
	val, _, err := m.prog.Eval(input)
	if err != nil {
		return err
	}

	input[m.claim] = val.Value()

	return nil
}
