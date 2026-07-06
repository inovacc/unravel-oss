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

// SessionClient wraps the session.* verbs.
type SessionClient struct {
	bus ipc.Bus
}

// NewSessionClient returns a wrapper over bus for the session.* verb group.
func NewSessionClient(bus ipc.Bus) *SessionClient {
	return &SessionClient{bus: bus}
}

// Connect calls session.connect and returns the new session id.
func (c *SessionClient) Connect(ctx context.Context, agentID, cwd, workspaceID string) (string, error) {
	raw, err := c.bus.Call(ctx, "session.connect", supervisor.SessionConnectParams{
		AgentID: agentID, CWD: cwd, WorkspaceID: workspaceID,
	})
	if err != nil {
		return "", translateErr(err, ErrSessionNotFound)
	}
	var out supervisor.SessionConnectResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.SessionID, nil
}

// Disconnect calls session.disconnect.
func (c *SessionClient) Disconnect(ctx context.Context, sessionID string) error {
	_, err := c.bus.Call(ctx, "session.disconnect", supervisor.SessionIDParams{SessionID: sessionID})
	return translateErr(err, ErrSessionNotFound)
}

// RebindCWD calls session.rebind_cwd.
func (c *SessionClient) RebindCWD(ctx context.Context, sessionID, cwd string) error {
	_, err := c.bus.Call(ctx, "session.rebind_cwd", supervisor.SessionRebindParams{
		SessionID: sessionID, CWD: cwd,
	})
	return translateErr(err, ErrSessionNotFound)
}

// Heartbeat calls session.heartbeat.
func (c *SessionClient) Heartbeat(ctx context.Context, sessionID string) error {
	_, err := c.bus.Call(ctx, "session.heartbeat", supervisor.SessionIDParams{SessionID: sessionID})
	return translateErr(err, ErrSessionNotFound)
}

// Show calls session.show.
func (c *SessionClient) Show(ctx context.Context, sessionID string) (*supervisor.SessionRecord, error) {
	raw, err := c.bus.Call(ctx, "session.show", supervisor.SessionIDParams{SessionID: sessionID})
	if err != nil {
		return nil, translateErr(err, ErrSessionNotFound)
	}
	var out supervisor.SessionRecord
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
