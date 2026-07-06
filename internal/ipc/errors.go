/*
Copyright (c) 2026 Security Research
*/
// Package ipc implements unravel's host-singleton IPC layer (JSON-RPC 2.0
// over UDS on POSIX, named pipe on Windows). See spec
// docs/superpowers/specs/2026-05-27-supervisor-singleton-pattern-design.md
package ipc

import "fmt"

// Error codes — exposed as constants in this package for reuse on both
// the supervisor-side (handler returns) and the client-side (typed-error
// translation in internal/supervisor/clients/).
const (
	CodeInvalidArg   = 400
	CodeUnauthorized = 401
	CodeForbidden    = 403
	CodeNotFound     = 404
	CodeTimeout      = 408
	CodeConflict     = 409
	CodeInternal     = 500
	CodeUpstream     = 502
	CodeUnavailable  = 503
)

// ErrorBody is the wire-shape of a JSON-RPC 2.0 error object.
type ErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *ErrorBody) Error() string {
	return fmt.Sprintf("ipc error %d: %s", e.Code, e.Message)
}
