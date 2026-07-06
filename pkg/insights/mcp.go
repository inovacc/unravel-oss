/*
Copyright (c) 2026 Security Research
*/

package insights

import (
	"time"
)

// MCPCallEnd is the closure returned by MCPCallStart; defer-call it
// from an MCP handler to record one mcp_tool_call event with the
// observed elapsed time and outcome.
type MCPCallEnd func(err error)

// MCPCallStart returns a deferred-end closure that records one
// mcp_tool_call event. Usage:
//
//	defer insights.MCPCallStart(toolName, sessionID)(returnedErr)
//
// or
//
//	end := insights.MCPCallStart("unravel_kb_pending_enrich", "")
//	... handler body ...
//	end(nil)
//
// Silent no-op when insights is disabled.
func MCPCallStart(toolName, sessionID string) MCPCallEnd {
	if IsDisabled() {
		return func(error) {}
	}
	start := time.Now()
	return func(err error) {
		evType := EventMCPToolCall
		payload := map[string]any{
			"tool":       toolName,
			"elapsed_ms": time.Since(start).Milliseconds(),
		}
		if err != nil {
			payload["error"] = truncMsg(err.Error(), 120)
			evType = EventFailure
		}
		_ = Record(Event{Type: evType, SessionID: sessionID, Payload: payload})
	}
}

func truncMsg(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
