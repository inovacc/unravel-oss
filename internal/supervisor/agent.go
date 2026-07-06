/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// AgentRegisterParams is the request body for agent.register.
type AgentRegisterParams struct {
	ClientKind string `json:"client_kind"`
	CWD        string `json:"cwd"`
}

// AgentRegisterResult is the response body for agent.register.
type AgentRegisterResult struct {
	AgentID string `json:"agent_id"`
}

// AgentListResult is the response body for agent.list.
type AgentListResult struct {
	Agents []*AgentRecord `json:"agents"`
}

// AgentUnregisterParams is the request body for agent.unregister.
type AgentUnregisterParams struct {
	AgentID string `json:"agent_id"`
}

// newID returns a 128-bit random hex id. crypto/rand is used so the
// supervisor doesn't add a new module dependency (e.g. google/uuid).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail; if it does the process is
		// in a bad state and we panic to surface it.
		panic(fmt.Errorf("supervisor: crypto/rand failed: %w", err))
	}
	return hex.EncodeToString(b[:])
}

// registerAgentVerbs wires agent.register / agent.list / agent.unregister.
func (sv *Supervisor) registerAgentVerbs() {
	sv.RegisterVerb("agent.register", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p AgentRegisterParams
		if len(params) > 0 {
			if err := json.Unmarshal(params, &p); err != nil {
				return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "agent.register: " + err.Error()}
			}
		}
		if p.ClientKind == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "agent.register: client_kind required"}
		}
		rec := &AgentRecord{
			AgentID:     newID(),
			ClientKind:  p.ClientKind,
			CWD:         p.CWD,
			ConnectedAt: sv.now(),
		}
		sv.agentsMu.Lock()
		sv.agents[rec.AgentID] = rec
		sv.agentsMu.Unlock()
		return AgentRegisterResult{AgentID: rec.AgentID}, nil
	})

	sv.RegisterVerb("agent.list", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		sv.agentsMu.RLock()
		out := make([]*AgentRecord, 0, len(sv.agents))
		for _, a := range sv.agents {
			out = append(out, a)
		}
		sv.agentsMu.RUnlock()
		return AgentListResult{Agents: out}, nil
	})

	sv.RegisterVerb("agent.unregister", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p AgentUnregisterParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "agent.unregister: " + err.Error()}
		}
		if p.AgentID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "agent.unregister: agent_id required"}
		}

		sv.agentsMu.Lock()
		_, ok := sv.agents[p.AgentID]
		if !ok {
			sv.agentsMu.Unlock()
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "agent not found: " + p.AgentID}
		}
		delete(sv.agents, p.AgentID)
		sv.agentsMu.Unlock()

		// Cascade: disconnect all sessions owned by this agent. We collect
		// session ids first under the read lock, then call detach helpers
		// per session to keep workspace ref-counting consistent.
		sv.sessionsMu.RLock()
		victims := make([]string, 0)
		for sid, s := range sv.sessions {
			if s.AgentID == p.AgentID {
				victims = append(victims, sid)
			}
		}
		sv.sessionsMu.RUnlock()

		for _, sid := range victims {
			sv.detachSession(sid)
		}

		return map[string]any{}, nil
	})
}
