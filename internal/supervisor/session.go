/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// SessionConnectParams is the request body for session.connect.
type SessionConnectParams struct {
	AgentID     string `json:"agent_id"`
	CWD         string `json:"cwd"`
	WorkspaceID string `json:"workspace_id,omitempty"`
}

// SessionConnectResult is the response body for session.connect.
type SessionConnectResult struct {
	SessionID string `json:"session_id"`
}

// SessionIDParams covers verbs that take only {session_id}.
type SessionIDParams struct {
	SessionID string `json:"session_id"`
}

// SessionRebindParams is the request body for session.rebind_cwd.
type SessionRebindParams struct {
	SessionID string `json:"session_id"`
	CWD       string `json:"cwd"`
}

// registerSessionVerbs wires session.connect / disconnect / rebind_cwd /
// heartbeat / show.
func (sv *Supervisor) registerSessionVerbs() {
	sv.RegisterVerb("session.connect", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p SessionConnectParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.connect: " + err.Error()}
		}
		if p.AgentID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.connect: agent_id required"}
		}

		sv.agentsMu.RLock()
		_, ok := sv.agents[p.AgentID]
		sv.agentsMu.RUnlock()
		if !ok {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "agent not found: " + p.AgentID}
		}

		rec := &SessionRecord{
			SessionID:     newID(),
			AgentID:       p.AgentID,
			WorkspaceID:   p.WorkspaceID,
			CWD:           p.CWD,
			LastHeartbeat: sv.now(),
		}
		sv.sessionsMu.Lock()
		sv.sessions[rec.SessionID] = rec
		sv.sessionsMu.Unlock()
		return SessionConnectResult{SessionID: rec.SessionID}, nil
	})

	sv.RegisterVerb("session.disconnect", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p SessionIDParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.disconnect: " + err.Error()}
		}
		if p.SessionID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.disconnect: session_id required"}
		}
		if !sv.detachSession(p.SessionID) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "session not found: " + p.SessionID}
		}
		return map[string]any{}, nil
	})

	sv.RegisterVerb("session.rebind_cwd", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p SessionRebindParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.rebind_cwd: " + err.Error()}
		}
		if p.SessionID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.rebind_cwd: session_id required"}
		}
		sv.sessionsMu.Lock()
		s, ok := sv.sessions[p.SessionID]
		if !ok {
			sv.sessionsMu.Unlock()
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "session not found: " + p.SessionID}
		}
		s.CWD = p.CWD
		sv.sessionsMu.Unlock()
		return map[string]any{}, nil
	})

	sv.RegisterVerb("session.heartbeat", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p SessionIDParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.heartbeat: " + err.Error()}
		}
		if p.SessionID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.heartbeat: session_id required"}
		}
		sv.sessionsMu.Lock()
		s, ok := sv.sessions[p.SessionID]
		if !ok {
			sv.sessionsMu.Unlock()
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "session not found: " + p.SessionID}
		}
		s.LastHeartbeat = sv.now()
		sv.sessionsMu.Unlock()
		return map[string]any{}, nil
	})

	sv.RegisterVerb("session.show", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p SessionIDParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.show: " + err.Error()}
		}
		if p.SessionID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "session.show: session_id required"}
		}
		sv.sessionsMu.RLock()
		s, ok := sv.sessions[p.SessionID]
		sv.sessionsMu.RUnlock()
		if !ok {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "session not found: " + p.SessionID}
		}
		// return a copy so the caller cannot mutate map state
		cp := *s
		return &cp, nil
	})
}

// detachSession removes a session from the map and decrements its
// workspace ref-count (cleaning up the workspace row if AgentSet becomes
// empty). Returns false if the session_id was not present.
func (sv *Supervisor) detachSession(sessionID string) bool {
	sv.sessionsMu.Lock()
	s, ok := sv.sessions[sessionID]
	if !ok {
		sv.sessionsMu.Unlock()
		return false
	}
	wsID := s.WorkspaceID
	agentID := s.AgentID
	delete(sv.sessions, sessionID)
	sv.sessionsMu.Unlock()

	if wsID != "" {
		sv.detachAgentFromWorkspace(wsID, agentID)
	}
	return true
}
