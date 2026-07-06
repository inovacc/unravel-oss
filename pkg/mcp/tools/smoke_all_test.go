/*
Copyright (c) 2026 Security Research

smoke_all_test.go — protocol-level smoke for every registered MCP tool.

For each of the 144 tools advertised by the server, call it with empty
arguments and assert that *something* comes back — either a real result
or an `IsError=true` result (the canonical InvalidParams shape). What
must NOT happen: a JSON-RPC error, a panic, or an orphan request that
never gets a response.

This catches: nil-deref in handlers that don't validate args, missing
handler registration (tool advertised but not wired), malformed
inputSchema that breaks request marshalling, and any panic that escapes
the recover() inside the server.

Out of scope: semantic correctness. A handler that returns the wrong
shape on *valid* input will pass this smoke. Per-tool fixtures should be
added incrementally (see MCP-SMOKE-HARNESS in docs/BACKLOG.md).

Runtime is dominated by 144 round trips serially over an in-memory
transport. Skipped under -short.
*/
package mcptools_test

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	mcptools "github.com/inovacc/unravel-oss/pkg/mcp/tools"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSmokeAllTools(t *testing.T) {
	if testing.Short() {
		t.Skip("smoke harness: long-running, skipped under -short")
	}

	srv := mcptools.NewServer(mcptools.ServerConfig{
		OnServer: func(s *mcp.Server) {
			mcptools.RegisterKB(s, nil)
			mcptools.RegisterKBImportExport(s)
		},
	})

	ctx := t.Context()

	st, ct := mcp.NewInMemoryTransports()

	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	list, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(list.Tools) == 0 {
		t.Fatal("smoke: no tools advertised")
	}

	// Tools that intentionally do disk I/O on minimal args and would
	// blow the per-call timeout under the smoke. They have no required
	// schema fields — empty args is a legal "scan everything" invocation.
	// Skipped in smoke; cover with per-tool fixture tests instead.
	skipSlow := map[string]string{
		"unravel_extension_scan": "scans every installed browser profile from disk",
	}

	// Deterministic order so failures are reproducible.
	names := make([]string, 0, len(list.Tools))
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)

	type failure struct {
		tool string
		err  string
	}
	var protoFailures []failure
	var okList, isErrList []string
	var schemaRejectCount, skippedCount int

	for _, name := range names {
		if reason, ok := skipSlow[name]; ok {
			t.Logf("smoke: skip %s (%s)", name, reason)
			skippedCount++
			continue
		}
		// Per-tool timeout: 5s is well above any normal handler.
		// Handlers that block forever on empty args (e.g. waiting on a
		// nil DB) get cut off and reported as protocol failures.
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		res, callErr := cs.CallTool(callCtx, &mcp.CallToolParams{
			Name:      name,
			Arguments: map[string]any{},
		})
		cancel()

		switch {
		case callErr != nil:
			// Schema-validation rejections are canonical and healthy —
			// they prove the inputSchema is wired and the server is
			// catching bad input before the handler. Look for the SDK's
			// validator phrase. Anything else (transport, panic, "method
			// not found") is a real protocol failure.
			msg := callErr.Error()
			if strings.Contains(msg, "invalid params") && strings.Contains(msg, "validating") {
				schemaRejectCount++
			} else {
				protoFailures = append(protoFailures, failure{name, msg})
			}
		case res == nil:
			protoFailures = append(protoFailures, failure{name, "nil result with no error"})
		case res.IsError:
			// Canonical InvalidParams from the handler itself: handler
			// ran past schema validation and returned a structured
			// error. Counts as healthy.
			isErrList = append(isErrList, name)
		default:
			okList = append(okList, name)
		}
	}

	t.Logf("smoke: %d tools  ok=%d  isError=%d  schemaReject=%d  skipped=%d  protoFailures=%d",
		len(names), len(okList), len(isErrList), schemaRejectCount, skippedCount, len(protoFailures))
	if testing.Verbose() {
		t.Logf("ok tools (%d): %v", len(okList), okList)
		t.Logf("isError tools (%d): %v", len(isErrList), isErrList)
	}

	if len(protoFailures) > 0 {
		var sb strings.Builder
		for _, f := range protoFailures {
			sb.WriteString("\n  ")
			sb.WriteString(f.tool)
			sb.WriteString(": ")
			sb.WriteString(f.err)
		}
		t.Fatalf("smoke: %d tools failed protocol round-trip:%s",
			len(protoFailures), sb.String())
	}
}
