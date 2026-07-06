/*
Copyright (c) 2026 Security Research
*/
package clients

import (
	"context"
	"encoding/json"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// WorkspaceClient wraps the workspace.* verbs.
type WorkspaceClient struct {
	bus ipc.Bus
}

// NewWorkspaceClient returns a wrapper over bus for the workspace.* verb group.
func NewWorkspaceClient(bus ipc.Bus) *WorkspaceClient {
	return &WorkspaceClient{bus: bus}
}

// Activate calls workspace.activate and returns the workspace id.
func (c *WorkspaceClient) Activate(ctx context.Context, sessionID, app string) (string, error) {
	raw, err := c.bus.Call(ctx, "workspace.activate", supervisor.WorkspaceActivateParams{
		SessionID: sessionID, App: app,
	})
	if err != nil {
		return "", translateErr(err, ErrWorkspaceNotFound)
	}
	var out supervisor.WorkspaceActivateResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.WorkspaceID, nil
}

// Deactivate calls workspace.deactivate (keyed by session_id).
func (c *WorkspaceClient) Deactivate(ctx context.Context, sessionID string) error {
	_, err := c.bus.Call(ctx, "workspace.deactivate", supervisor.SessionIDParams{SessionID: sessionID})
	return translateErr(err, ErrWorkspaceNotFound)
}

// List calls workspace.list.
func (c *WorkspaceClient) List(ctx context.Context) ([]supervisor.WorkspaceView, error) {
	raw, err := c.bus.Call(ctx, "workspace.list", map[string]any{})
	if err != nil {
		return nil, translateErr(err, ErrWorkspaceNotFound)
	}
	var out supervisor.WorkspaceListResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Workspaces, nil
}

// Show calls workspace.show.
func (c *WorkspaceClient) Show(ctx context.Context, workspaceID string) (*supervisor.WorkspaceView, error) {
	raw, err := c.bus.Call(ctx, "workspace.show", supervisor.WorkspaceIDParams{WorkspaceID: workspaceID})
	if err != nil {
		return nil, translateErr(err, ErrWorkspaceNotFound)
	}
	var out supervisor.WorkspaceView
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Compile-time assertion: ipc.Bus is satisfied by *ipc.Client.
var _ ipc.Bus = (*ipc.Client)(nil)
