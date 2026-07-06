/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// RegisterVerb adds a handler to the supervisor's verb registry.
func (sv *Supervisor) RegisterVerb(method string, h ipc.HandlerFunc) {
	sv.server.RegisterVerb(method, h)
}

// HasVerb reports whether method is registered.
func (sv *Supervisor) HasVerb(method string) bool {
	return sv.server.HasVerb(method)
}

// registerLifecycleVerbs wires hello + ping. Called from New().
func (sv *Supervisor) registerLifecycleVerbs() {
	sv.RegisterVerb("hello", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		return ipc.HelloResponse{
			ServerVersion:   "v2.17.0-dev",
			ServerUID:       "todo", // PG-V17-4 wires from os.Getuid() (POSIX) / SID (Windows)
			ProtocolVersion: "1",
		}, nil
	})
	sv.RegisterVerb("ping", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		return map[string]any{
			"ok":  true,
			"now": sv.now().UTC().Format(time.RFC3339),
		}, nil
	})
}

// registerStateVerbs wires the agent / session / workspace verb groups
// implemented in PG-V17-4. Called from New().
func (sv *Supervisor) registerStateVerbs() {
	sv.registerAgentVerbs()
	sv.registerSessionVerbs()
	sv.registerWorkspaceVerbs()
}
