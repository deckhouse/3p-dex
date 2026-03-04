package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/pkg/cel"
	"github.com/dexidp/dex/storage"
)

func newAuthPolicyCompiler(t *testing.T) *cel.Compiler {
	t.Helper()
	vars := append(cel.IdentityVariables(), cel.RequestVariables()...)
	compiler, err := cel.NewCompiler(vars)
	require.NoError(t, err)
	return compiler
}

func TestCompileAuthPolicies(t *testing.T) {
	compiler := newAuthPolicyCompiler(t)

	tests := []struct {
		name     string
		policies []storage.PolicyExpression
		wantErr  string
	}{
		{
			name: "valid policy with message",
			policies: []storage.PolicyExpression{
				{Expression: "!identity.email.endsWith('@example.com')", Message: "'Login restricted to example.com'"},
			},
		},
		{
			name: "valid policy without message",
			policies: []storage.PolicyExpression{
				{Expression: "!identity.email_verified"},
			},
		},
		{
			name: "multiple valid policies",
			policies: []storage.PolicyExpression{
				{Expression: "!identity.email_verified", Message: "'Email not verified'"},
				{Expression: "!identity.email.endsWith('@example.com')", Message: "'Wrong domain'"},
			},
		},
		{
			name:     "empty policies",
			policies: []storage.PolicyExpression{},
		},
		{
			name: "empty expression",
			policies: []storage.PolicyExpression{
				{Expression: ""},
			},
			wantErr: "expression is required",
		},
		{
			name: "invalid expression syntax",
			policies: []storage.PolicyExpression{
				{Expression: "this is not valid CEL !!!"},
			},
			wantErr: "compiling expression",
		},
		{
			name: "expression returns string instead of bool",
			policies: []storage.PolicyExpression{
				{Expression: "identity.email"},
			},
			wantErr: "expected expression output type bool",
		},
		{
			name: "message returns bool instead of string",
			policies: []storage.PolicyExpression{
				{Expression: "true", Message: "true"},
			},
			wantErr: "compiling message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CompileAuthPolicies(compiler, tt.policies)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, result, len(tt.policies))
		})
	}
}

func TestEvaluateAuthPolicy(t *testing.T) {
	compiler := newAuthPolicyCompiler(t)

	identity := map[string]any{
		"user_id":            "user-123",
		"username":           "testuser",
		"preferred_username": "testuser",
		"email":              "user@example.com",
		"email_verified":     true,
		"groups":             []string{"developers", "team-a"},
	}

	request := map[string]any{
		"client_id":    "my-app",
		"connector_id": "ldap",
		"scopes":       []string{"openid", "profile"},
		"redirect_uri": "http://localhost/callback",
	}

	tests := []struct {
		name        string
		policies    []storage.PolicyExpression
		identity    map[string]any
		request     map[string]any
		wantDenied  bool
		wantMessage string
	}{
		{
			name:       "empty policies allow access",
			policies:   nil,
			identity:   identity,
			request:    request,
			wantDenied: false,
		},
		{
			name: "policy does not match - access allowed",
			policies: []storage.PolicyExpression{
				{Expression: "!identity.email.endsWith('@example.com')", Message: "'Wrong domain'"},
			},
			identity:   identity,
			request:    request,
			wantDenied: false,
		},
		{
			name: "policy matches - access denied with message",
			policies: []storage.PolicyExpression{
				{Expression: "!identity.email.endsWith('@corp.com')", Message: "'Login restricted to corp.com'"},
			},
			identity:    identity,
			request:     request,
			wantDenied:  true,
			wantMessage: "Login restricted to corp.com",
		},
		{
			name: "first match wins",
			policies: []storage.PolicyExpression{
				{Expression: "!identity.email_verified", Message: "'Email not verified'"},
				{Expression: "!('admin' in identity.groups)", Message: "'Admin required'"},
			},
			identity:    identity,
			request:     request,
			wantDenied:  true,
			wantMessage: "Admin required",
		},
		{
			name: "request variables work",
			policies: []storage.PolicyExpression{
				{Expression: "request.connector_id != 'okta'", Message: "'Only Okta allowed'"},
			},
			identity:    identity,
			request:     request,
			wantDenied:  true,
			wantMessage: "Only Okta allowed",
		},
		{
			name: "group membership check passes",
			policies: []storage.PolicyExpression{
				{Expression: "!('developers' in identity.groups)", Message: "'Must be a developer'"},
			},
			identity:   identity,
			request:    request,
			wantDenied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := CompileAuthPolicies(compiler, tt.policies)
			require.NoError(t, err)

			denied, msg, err := EvaluateAuthPolicy(context.Background(), compiled, tt.identity, tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.wantDenied, denied)
			if tt.wantDenied {
				assert.Equal(t, tt.wantMessage, msg)
			}
		})
	}
}

func TestEvaluateAuthPolicyDefaultMessage(t *testing.T) {
	compiler := newAuthPolicyCompiler(t)

	policies := []storage.PolicyExpression{
		{Expression: "true"}, // always deny, no message
	}

	compiled, err := CompileAuthPolicies(compiler, policies)
	require.NoError(t, err)

	identity := map[string]any{
		"user_id":            "user-123",
		"username":           "testuser",
		"preferred_username": "testuser",
		"email":              "user@example.com",
		"email_verified":     true,
		"groups":             []string{},
	}
	request := map[string]any{
		"client_id":    "app",
		"connector_id": "mock",
		"scopes":       []string{"openid"},
		"redirect_uri": "http://localhost/callback",
	}

	denied, msg, err := EvaluateAuthPolicy(context.Background(), compiled, identity, request)
	require.NoError(t, err)
	assert.True(t, denied)
	assert.Equal(t, ErrMsgAuthPolicyDenied, msg)
}
