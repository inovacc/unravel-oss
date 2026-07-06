/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"encoding/json"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// decodeParams is the shared preamble for verb handlers that take a mandatory
// JSON params body. It guards the DB pool (delegating the group-specific
// "no DB pool" error to noDB) and unmarshals params into dst, returning a
// ready-to-return ipc error on failure or nil on success. Field-level
// validation stays in each handler. Handlers with optional params (those that
// guard on len(params) > 0) keep their own inline preamble.
func (sv *Supervisor) decodeParams(verb string, params json.RawMessage, dst any, noDB func() *ipc.ErrorBody) *ipc.ErrorBody {
	if sv.db == nil {
		return noDB()
	}
	if err := json.Unmarshal(params, dst); err != nil {
		return &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: verb + ": " + err.Error()}
	}

	return nil
}
