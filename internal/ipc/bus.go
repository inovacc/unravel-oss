/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"context"
	"encoding/json"
)

// HandlerFunc dispatches one verb call. Exactly one of (result, *ErrorBody)
// must be non-nil in the return.
type HandlerFunc func(ctx context.Context, params json.RawMessage) (any, *ErrorBody)

// Bus is the client-side interface used by internal/supervisor/clients/.
type Bus interface {
	Call(ctx context.Context, method string, params any) (json.RawMessage, error)
	Notify(ctx context.Context, method string, params any) error
	Close() error
}
