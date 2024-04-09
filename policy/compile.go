package policy

import (
	"fmt"
	"net/url"

	celgo "github.com/google/cel-go/cel"

	"github.com/dexidp/dex/pkg/cel"
	"github.com/dexidp/dex/storage"
)

// Compile compiles a list of policies into a list of claim policies.
func Compile(policies []storage.ClaimPolicy) ([]ClaimPolicy, error) {
	env, err := cel.NewTokenEnv()
	if err != nil {
		return nil, err
	}

	res := make([]ClaimPolicy, 0, len(policies))

	for _, policy := range policies {
		switch {
		case policy.Validate != nil && policy.Mutate != nil:
			return nil, fmt.Errorf("policy cannot have both validate and mutate")
		case policy.Validate == nil && policy.Mutate == nil:
			return nil, fmt.Errorf("policy must have either validate or mutate")
		case policy.Validate != nil:
			prog, err := env.Compile(policy.Validate.Expr, cel.WithReturnType(celgo.BoolType))
			if err != nil {
				return nil, err
			}
			res = append(res, newValidateClaimPolicy(prog, policy.Validate.Message))
		case policy.Mutate != nil:
			outputType, err := getMutateType(policy.Mutate.Claim)
			if err != nil {
				return nil, err
			}
			prog, err := env.Compile(policy.Mutate.Expr, cel.WithReturnType(outputType))
			if err != nil {
				return nil, err
			}
			res = append(res, newMutateClaimPolicy(prog, policy.Mutate.Claim))
		}
	}

	return res, nil
}

func getMutateType(claim string) (*celgo.Type, error) {
	switch claim {
	case "email":
		return celgo.StringType, nil
	case "email_verified":
		return celgo.BoolType, nil
	case "name", "preferred_username":
		return celgo.StringType, nil
	case "groups":
		return celgo.ListType(celgo.StringType), nil
	default:
		u, err := url.Parse(claim)
		if err != nil {
			return nil, fmt.Errorf("custom claim must be a valid URL, got %q: %v", claim, err)
		} else if u.Scheme == "" || u.Host == "" || u.Path == "" {
			return nil, fmt.Errorf("custom claim must be a valid URL with path, e.g. https://example.com/my-claim, got %q", claim)
		}
		// TODO(nabokihms): provide a better custom type check than non checking it at all.
		return nil /* do not check type */, nil
	}
}
