package cel

import (
	"testing"
	"time"

	"github.com/google/cel-go/cel"
)

func TestCelEnv(t *testing.T) {
	env, err := NewTokenEnv()
	if err != nil {
		t.Fatal(err)
	}

	// This is the expression that will be evaluated.
	// The expression is a string that represents a claim in a token
	prog, issues := env.Compile(`claims.expires_at > now`, WithReturnType(cel.BoolType))
	if issues.Err() != nil {
		t.Fatal(issues.Err())
	}

	t.Run("Success", func(t *testing.T) {
		// This is the input to the expression.
		_, _, err := prog.Eval(map[string]interface{}{
			"claims": map[string]interface{}{
				"expires_at": 23132313123123123,
			},
			"now": time.Now().Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Key error", func(t *testing.T) {
		_, _, err = prog.Eval(map[string]interface{}{
			"claims": map[string]interface{}{
				"sub": "test",
			},
			"now": time.Now().Unix(),
		})
		if err == nil {
			t.Fatal("error excepted")
		}
	})
}
