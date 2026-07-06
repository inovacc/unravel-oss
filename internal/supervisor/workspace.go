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

// WorkspaceActivateParams is the request body for workspace.activate.
type WorkspaceActivateParams struct {
	SessionID string `json:"session_id"`
	App       string `json:"app"`
}

// WorkspaceActivateResult is the response body for workspace.activate.
type WorkspaceActivateResult struct {
	WorkspaceID string `json:"workspace_id"`
}

// WorkspaceIDParams covers verbs that take only {workspace_id}.
type WorkspaceIDParams struct {
	WorkspaceID string `json:"workspace_id"`
}

// WorkspaceView is the response shape for workspace.list / workspace.show.
// Adds derived pin_count (== len(AgentSet)) to the bare record.
type WorkspaceView struct {
	WorkspaceID string    `json:"workspace_id"`
	App         string    `json:"app"`
	PinCount    int       `json:"pin_count"`
	AgentIDs    []string  `json:"agent_ids"`
	ActivatedAt time.Time `json:"activated_at"`
}

// WorkspaceListResult is the response body for workspace.list.
type WorkspaceListResult struct {
	Workspaces []WorkspaceView `json:"workspaces"`
}

func workspaceToView(w *WorkspaceRecord) WorkspaceView {
	agents := make([]string, 0, len(w.AgentSet))
	for a := range w.AgentSet {
		agents = append(agents, a)
	}
	return WorkspaceView{
		WorkspaceID: w.WorkspaceID,
		App:         w.App,
		PinCount:    len(w.AgentSet),
		AgentIDs:    agents,
		ActivatedAt: w.ActivatedAt,
	}
}

// registerWorkspaceVerbs wires workspace.activate / deactivate / list / show.
func (sv *Supervisor) registerWorkspaceVerbs() {
	sv.RegisterVerb("workspace.activate", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p WorkspaceActivateParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "workspace.activate: " + err.Error()}
		}
		if p.SessionID == "" || p.App == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "workspace.activate: session_id and app required"}
		}

		// Resolve the session to find its agent id.
		sv.sessionsMu.RLock()
		sess, ok := sv.sessions[p.SessionID]
		sv.sessionsMu.RUnlock()
		if !ok {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "session not found: " + p.SessionID}
		}
		agentID := sess.AgentID

		// Find or create a workspace row for this app. Workspaces are
		// keyed by app within a single supervisor: one row per distinct
		// app, ref-counted by AgentSet.
		sv.workspacesMu.Lock()
		var ws *WorkspaceRecord
		for _, w := range sv.workspaces {
			if w.App == p.App {
				ws = w
				break
			}
		}
		if ws == nil {
			ws = &WorkspaceRecord{
				WorkspaceID: newID(),
				App:         p.App,
				AgentSet:    map[string]struct{}{},
				ActivatedAt: sv.now(),
			}
			sv.workspaces[ws.WorkspaceID] = ws
		}
		ws.AgentSet[agentID] = struct{}{}
		wsID := ws.WorkspaceID
		sv.workspacesMu.Unlock()

		// Bind the workspace id on the session record.
		sv.sessionsMu.Lock()
		if s, ok := sv.sessions[p.SessionID]; ok {
			s.WorkspaceID = wsID
		}
		sv.sessionsMu.Unlock()

		return WorkspaceActivateResult{WorkspaceID: wsID}, nil
	})

	sv.RegisterVerb("workspace.deactivate", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p SessionIDParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "workspace.deactivate: " + err.Error()}
		}
		if p.SessionID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "workspace.deactivate: session_id required"}
		}

		sv.sessionsMu.Lock()
		sess, ok := sv.sessions[p.SessionID]
		if !ok {
			sv.sessionsMu.Unlock()
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "session not found: " + p.SessionID}
		}
		wsID := sess.WorkspaceID
		agentID := sess.AgentID
		sess.WorkspaceID = "" // unbind on the session
		sv.sessionsMu.Unlock()

		if wsID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "workspace.deactivate: session has no workspace"}
		}

		sv.detachAgentFromWorkspace(wsID, agentID)
		return map[string]any{}, nil
	})

	sv.RegisterVerb("workspace.list", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		sv.workspacesMu.RLock()
		out := make([]WorkspaceView, 0, len(sv.workspaces))
		for _, w := range sv.workspaces {
			out = append(out, workspaceToView(w))
		}
		sv.workspacesMu.RUnlock()
		return WorkspaceListResult{Workspaces: out}, nil
	})

	sv.RegisterVerb("workspace.show", func(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
		var p WorkspaceIDParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "workspace.show: " + err.Error()}
		}
		if p.WorkspaceID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "workspace.show: workspace_id required"}
		}
		sv.workspacesMu.RLock()
		w, ok := sv.workspaces[p.WorkspaceID]
		var view WorkspaceView
		if ok {
			view = workspaceToView(w)
		}
		sv.workspacesMu.RUnlock()
		if !ok {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: "workspace not found: " + p.WorkspaceID}
		}
		return view, nil
	})
}

// detachAgentFromWorkspace removes agentID from the workspace's AgentSet.
// If AgentSet becomes empty the workspace row is deleted (lensr Phase 45
// ref-counting semantics).
func (sv *Supervisor) detachAgentFromWorkspace(workspaceID, agentID string) {
	sv.workspacesMu.Lock()
	defer sv.workspacesMu.Unlock()
	w, ok := sv.workspaces[workspaceID]
	if !ok {
		return
	}
	delete(w.AgentSet, agentID)
	if len(w.AgentSet) == 0 {
		delete(sv.workspaces, workspaceID)
	}
}
