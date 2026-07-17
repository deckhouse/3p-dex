package authflow

import (
	"context"

	"github.com/google/uuid"
)

// logRequestKey types the context keys used to carry per-request logging
// attributes (request ID, client IP) from the server's middleware down into the
// handlers and the logger. They live here because the flow handlers read them
// and both the top-level server and the CLI logger reference them.
type logRequestKey string

const (
	RequestKeyRequestID logRequestKey = "request_id"
	RequestKeyRemoteIP  logRequestKey = "client_remote_addr"
)

// WithRequestID attaches a fresh request ID to the context.
func WithRequestID(ctx context.Context) context.Context {
	return context.WithValue(ctx, RequestKeyRequestID, uuid.NewString())
}

// WithRemoteIP attaches the client's remote IP to the context.
func WithRemoteIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, RequestKeyRemoteIP, ip)
}
