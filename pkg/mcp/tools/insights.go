/*
Copyright (c) 2026 Security Research
*/

// insights.go — MCP tool that lets subagents emit insights events
// from CC contexts. Wraps pkg/insights.Record so the self-improvement
// loop captures slash-command + subagent activity that lives outside
// the unravel Go process.

package mcptools

import (
	"context"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/insights"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type insightsRecordInput struct {
	EventType string         `json:"event_type" jsonschema:"event kind: command_invoked | mcp_tool_call | task_dispatched | subagent_returned | retry | failure | goal_started | goal_completed"`
	SessionID string         `json:"session_id,omitempty" jsonschema:"session identifier (optional; will fall back to anonymous)"`
	GoalID    string         `json:"goal_id,omitempty" jsonschema:"goal envelope identifier (optional)"`
	Payload   map[string]any `json:"payload,omitempty" jsonschema:"event-type-specific structured payload"`
}

type insightsStartGoalInput struct {
	Name string `json:"name" jsonschema:"human-readable goal description (e.g. 'enrich 25 teams modules')"`
}

type insightsCompleteGoalInput struct {
	GoalID  string `json:"goal_id" jsonschema:"goal envelope id returned by start_goal"`
	Outcome string `json:"outcome" jsonschema:"success | partial | abandoned"`
}

func registerInsightsTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_insights_record",
		Description: "Append one event to unravel's self-improvement insights stream. Local-only — no telemetry leaves the machine. Disable globally with env UNRAVEL_INSIGHTS=off.",
	}, handleInsightsRecord)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_insights_start_goal",
		Description: "Open a new goal envelope for jump-counting and friction analysis. Idempotent within a UTC day for the same name.",
	}, handleInsightsStartGoal)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_insights_complete_goal",
		Description: "Stamp an open goal envelope with outcome (success/partial/abandoned) and emit a goal_completed event.",
	}, handleInsightsCompleteGoal)
}

func handleInsightsRecord(_ context.Context, _ *mcp.CallToolRequest, input insightsRecordInput) (*mcp.CallToolResult, any, error) {
	ev := insights.Event{
		Type:      insights.EventType(input.EventType),
		SessionID: input.SessionID,
		GoalID:    input.GoalID,
		Payload:   input.Payload,
	}
	if err := insights.Record(ev); err != nil {
		return errorResult(err), nil, nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("recorded: %s", input.EventType)}}}, nil, nil
}

func handleInsightsStartGoal(_ context.Context, _ *mcp.CallToolRequest, input insightsStartGoalInput) (*mcp.CallToolResult, any, error) {
	g, err := insights.StartGoal(input.Name)
	if err != nil {
		return errorResult(err), nil, nil
	}
	out := fmt.Sprintf("goal_id=%s name=%q started_at=%s", g.GoalID, g.Name, g.StartedAt.Format("2006-01-02T15:04:05Z"))
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: out}}}, nil, nil
}

func handleInsightsCompleteGoal(_ context.Context, _ *mcp.CallToolRequest, input insightsCompleteGoalInput) (*mcp.CallToolResult, any, error) {
	if err := insights.CompleteGoal(input.GoalID, insights.Outcome(input.Outcome)); err != nil {
		return errorResult(err), nil, nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("completed: goal_id=%s outcome=%s", input.GoalID, input.Outcome)}}}, nil, nil
}
