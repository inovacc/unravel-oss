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

// AgentClient wraps the agent.* verbs.
type AgentClient struct {
	bus ipc.Bus
}

// NewAgentClient returns a wrapper over bus for the agent.* verb group.
func NewAgentClient(bus ipc.Bus) *AgentClient {
	return &AgentClient{bus: bus}
}

// Register calls agent.register and returns the new agent id.
func (c *AgentClient) Register(ctx context.Context, clientKind, cwd string) (string, error) {
	raw, err := c.bus.Call(ctx, "agent.register", supervisor.AgentRegisterParams{
		ClientKind: clientKind, CWD: cwd,
	})
	if err != nil {
		return "", translateErr(err, ErrAgentNotFound)
	}
	var out supervisor.AgentRegisterResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.AgentID, nil
}

// List calls agent.list.
func (c *AgentClient) List(ctx context.Context) ([]*supervisor.AgentRecord, error) {
	raw, err := c.bus.Call(ctx, "agent.list", map[string]any{})
	if err != nil {
		return nil, translateErr(err, ErrAgentNotFound)
	}
	var out supervisor.AgentListResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Agents, nil
}

// Unregister calls agent.unregister.
func (c *AgentClient) Unregister(ctx context.Context, agentID string) error {
	_, err := c.bus.Call(ctx, "agent.unregister", supervisor.AgentUnregisterParams{AgentID: agentID})
	return translateErr(err, ErrAgentNotFound)
}
