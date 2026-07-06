/*
Copyright (c) 2026 Security Research
*/

// Package mcpclient connects to MCP servers via stdio to enumerate capabilities.
package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// DefaultTimeout is the maximum time to wait for MCP server enumeration.
const DefaultTimeout = 10 * time.Second

// ProbeResult holds the enumerated capabilities of an MCP server.
type ProbeResult struct {
	ServerName    string        `json:"server_name,omitempty"`
	ServerVersion string        `json:"server_version,omitempty"`
	ProtocolVer   string        `json:"protocol_version,omitempty"`
	Tools         []ToolInfo    `json:"tools,omitempty"`
	Resources     []ResInfo     `json:"resources,omitempty"`
	Prompts       []PromptInfo  `json:"prompts,omitempty"`
	Error         string        `json:"error,omitempty"`
	Duration      time.Duration `json:"duration"`
}

// ToolInfo describes a single MCP tool.
type ToolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// ResInfo describes a single MCP resource.
type ResInfo struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// PromptInfo describes a single MCP prompt.
type PromptInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// jsonrpcRequest is a JSON-RPC 2.0 request/notification.
type jsonrpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int   `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// jsonrpcResponse is a JSON-RPC 2.0 response.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// initializeResult is the expected shape of an initialize response.
type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

// toolsListResult is the expected shape of a tools/list response.
type toolsListResult struct {
	Tools []struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	} `json:"tools"`
}

// resourcesListResult is the expected shape of a resources/list response.
type resourcesListResult struct {
	Resources []struct {
		URI         string `json:"uri"`
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"resources"`
}

// promptsListResult is the expected shape of a prompts/list response.
type promptsListResult struct {
	Prompts []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"prompts"`
}

// Probe launches an MCP server via stdio and enumerates its capabilities.
// command is the executable, args are its arguments (e.g., "node", ["server.js"]).
func Probe(ctx context.Context, command string, args ...string) (*ProbeResult, error) {
	start := time.Now()

	timeout := DefaultTimeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcpclient: stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcpclient: stdout pipe: %w", err)
	}

	// Discard stderr to avoid blocking.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcpclient: start %q: %w", command, err)
	}

	// Ensure process is cleaned up.
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Read responses in a goroutine, dispatched by ID.
	var (
		mu        sync.Mutex
		responses = make(map[int]*jsonrpcResponse)
		readErr   error
		done      = make(chan struct{})
	)

	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var resp jsonrpcResponse
			if err := json.Unmarshal(line, &resp); err != nil {
				continue // skip non-JSON lines (e.g., logs)
			}

			if resp.ID != nil {
				mu.Lock()
				responses[*resp.ID] = &resp
				mu.Unlock()
			}
		}

		if err := scanner.Err(); err != nil {
			readErr = err
		}
	}()

	// Helper to send a JSON-RPC message.
	send := func(msg jsonrpcRequest) error {
		data, err := json.Marshal(msg)
		if err != nil {
			return err
		}

		data = append(data, '\n')
		_, err = stdin.Write(data)

		return err
	}

	// Helper to wait for a response by ID.
	waitFor := func(id int) (*jsonrpcResponse, error) {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				mu.Lock()
				r := responses[id]
				mu.Unlock()

				if r != nil {
					return r, nil
				}

				return nil, fmt.Errorf("mcpclient: server closed before response id=%d", id)
			case <-ticker.C:
				mu.Lock()
				r := responses[id]
				mu.Unlock()

				if r != nil {
					return r, nil
				}
			}
		}
	}

	result := &ProbeResult{}

	// Step 1: initialize
	initID := 1
	if err := send(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      &initID,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "unravel-probe",
				"version": "1.0.0",
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("mcpclient: send initialize: %w", err)
	}

	initResp, err := waitFor(initID)
	if err != nil {
		result.Error = fmt.Sprintf("initialize failed: %v", err)
		result.Duration = time.Since(start)

		return result, nil
	}

	if initResp.Error != nil {
		result.Error = fmt.Sprintf("initialize error: %s", initResp.Error.Message)
		result.Duration = time.Since(start)

		return result, nil
	}

	// Parse server info.
	var initRes initializeResult
	if err := json.Unmarshal(initResp.Result, &initRes); err == nil {
		result.ServerName = initRes.ServerInfo.Name
		result.ServerVersion = initRes.ServerInfo.Version
		result.ProtocolVer = initRes.ProtocolVersion
	}

	// Step 2: send initialized notification.
	if err := send(jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}); err != nil {
		result.Error = fmt.Sprintf("send initialized notification: %v", err)
		result.Duration = time.Since(start)

		return result, nil
	}

	// Step 3: enumerate tools.
	toolsID := 2
	if err := send(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      &toolsID,
		Method:  "tools/list",
		Params:  map[string]any{},
	}); err == nil {
		if resp, err := waitFor(toolsID); err == nil && resp.Error == nil {
			var tl toolsListResult
			if err := json.Unmarshal(resp.Result, &tl); err == nil {
				for _, t := range tl.Tools {
					result.Tools = append(result.Tools, ToolInfo{
						Name:        t.Name,
						Description: t.Description,
						InputSchema: t.InputSchema,
					})
				}
			}
		}
	}

	// Step 4: enumerate resources (optional, server may not support).
	resID := 3
	if err := send(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      &resID,
		Method:  "resources/list",
		Params:  map[string]any{},
	}); err == nil {
		if resp, err := waitFor(resID); err == nil && resp.Error == nil {
			var rl resourcesListResult
			if err := json.Unmarshal(resp.Result, &rl); err == nil {
				for _, r := range rl.Resources {
					result.Resources = append(result.Resources, ResInfo{
						URI:         r.URI,
						Name:        r.Name,
						Description: r.Description,
					})
				}
			}
		}
	}

	// Step 5: enumerate prompts (optional, server may not support).
	promptsID := 4
	if err := send(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      &promptsID,
		Method:  "prompts/list",
		Params:  map[string]any{},
	}); err == nil {
		if resp, err := waitFor(promptsID); err == nil && resp.Error == nil {
			var pl promptsListResult
			if err := json.Unmarshal(resp.Result, &pl); err == nil {
				for _, p := range pl.Prompts {
					result.Prompts = append(result.Prompts, PromptInfo{
						Name:        p.Name,
						Description: p.Description,
					})
				}
			}
		}
	}

	_ = readErr // best-effort; response data already collected.
	result.Duration = time.Since(start)

	return result, nil
}
