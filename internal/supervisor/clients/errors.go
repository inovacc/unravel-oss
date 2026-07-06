/*
Copyright (c) 2026 Security Research
*/
// Package clients exposes typed Go wrappers around the supervisor's IPC
// verb catalog. Each wrapper translates wire-level ipc.ErrorBody codes
// into typed sentinel errors so callers can use errors.Is/As.
package clients

import (
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// Sentinel errors. Use errors.Is to compare; wrap with fmt.Errorf to add
// context (the original message is preserved through %w).
var (
	ErrAgentNotFound        = errors.New("agent not found")
	ErrSessionNotFound      = errors.New("session not found")
	ErrWorkspaceNotFound    = errors.New("workspace not found")
	ErrBadRequest           = errors.New("bad request")
	ErrConflict             = errors.New("conflict")
	ErrEnrichRunNotFound    = errors.New("enrich: run not found")
	ErrEnrichModuleNotFound = errors.New("enrich: module not found")
	ErrDriftNoBaseline      = errors.New("drift: no baseline set for app")
	ErrDriftRunNotFound     = errors.New("drift: run not found")
)

// translateErr converts a raw ipc error into a typed sentinel. The
// classifier hint disambiguates which "not found" sentinel maps to the
// 404 code for the current verb.
func translateErr(err error, notFound error) error {
	if err == nil {
		return nil
	}
	var eb *ipc.ErrorBody
	if !errors.As(err, &eb) {
		return err
	}
	switch eb.Code {
	case ipc.CodeNotFound:
		if notFound == nil {
			notFound = errors.New("not found")
		}
		return fmt.Errorf("%w: %s", notFound, eb.Message)
	case ipc.CodeInvalidArg:
		return fmt.Errorf("%w: %s", ErrBadRequest, eb.Message)
	case ipc.CodeConflict:
		return fmt.Errorf("%w: %s", ErrConflict, eb.Message)
	default:
		return err
	}
}
