package server

import "github.com/dexidp/dex/server/authflow"

// User-facing error messages are defined by the authflow package and re-exported
// here so the public server API is unchanged.
const (
	ErrMsgLoginError           = authflow.ErrMsgLoginError
	ErrMsgAuthenticationFailed = authflow.ErrMsgAuthenticationFailed
	ErrMsgInternalServerError  = authflow.ErrMsgInternalServerError
	ErrMsgDatabaseError        = authflow.ErrMsgDatabaseError
	ErrMsgInvalidRequest       = authflow.ErrMsgInvalidRequest
	ErrMsgMethodNotAllowed     = authflow.ErrMsgMethodNotAllowed
	ErrMsgNotInRequiredGroups  = authflow.ErrMsgNotInRequiredGroups
)
