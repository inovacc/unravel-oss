/*
Copyright (c) 2026 Security Research

smoke_registration_test.go — fast, infra-free registration smoke guard over
the full MCP tool surface (~173 tools). Complements the exact-count invariant
in registry_test.go (TestToolCountInvariant) with looser, drift-tolerant
assertions that don't need updating every time a tool is added: a count
floor, name uniqueness, the taxonomy name-format rule (unravel_ prefix,
lowercase snake_case), non-empty descriptions, and a present input schema.
Registration-only — no handlers are invoked, so no Postgres/network is
required and the whole test runs in well under a second.
*/
package mcptools_test

import (
	"regexp"
	"testing"

	mcptools "github.com/inovacc/unravel-oss/pkg/mcp/tools"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolNamePattern is the taxonomy mirror rule (§8): every MCP tool name must
// be lowercase, underscore-separated, and carry the unravel_ prefix. This
// catches drift like a stray camelCase or hyphenated name slipping in.
var toolNamePattern = regexp.MustCompile(`^unravel_[a-z0-9]+(_[a-z0-9]+)*$`)

// TestToolRegistrationSmoke builds the full tool set the same way
// TestToolCountInvariant does (NewServer + OnServer wiring the kb_* tool
// families with a nil DB pool) and asserts registration-level invariants
// over every tool: a count floor, unique names, taxonomy-compliant name
// format, a non-empty description, and a present input schema. It does NOT
// invoke any handler, so it needs no Postgres and no network.
func TestToolRegistrationSmoke(t *testing.T) {
	srv := mcptools.NewServer(mcptools.ServerConfig{
		OnServer: func(s *mcp.Server) {
			// Mirror cmd/mcp.go wiring: kb tools are registered post-built-ins
			// via OnServer with a (possibly nil) DB, same as registry_test.go.
			mcptools.RegisterKB(s, nil)
			mcptools.RegisterKBImportExport(s)
		},
	})

	ctx := t.Context()

	// In-memory transports allow us to enumerate via ListTools without
	// stdio, network, or Postgres. Connect server + client over a paired
	// transport, same mechanism as TestToolCountInvariant.
	st, ct := mcp.NewInMemoryTransports()

	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "smoke-test", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}

	// 1. Count floor: guards against a whole file's init silently dropping
	// its tool registrations. >= (not ==) so adding tools later doesn't
	// break this test; registry_test.go's exact-count invariant is the
	// atomic-update guard for the precise number.
	const minTools = 170
	if got := len(res.Tools); got < minTools {
		t.Fatalf("MCP tool count: got %d, want >= %d (a tool family's init "+
			"may have silently failed to register)", got, minTools)
	}

	seen := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		// 2. Unique names: a duplicate would otherwise panic at server
		// startup (mcp.AddTool panics on a name collision) — assert it here
		// deterministically instead of via a runtime crash.
		if seen[tool.Name] {
			t.Errorf("duplicate tool name registered: %q", tool.Name)
			continue
		}
		seen[tool.Name] = true

		// 3. Name format: taxonomy mirror rule (§8).
		if !toolNamePattern.MatchString(tool.Name) {
			t.Errorf("tool name %q does not match taxonomy pattern %s", tool.Name, toolNamePattern.String())
		}

		// 4. Non-empty description.
		if tool.Description == "" {
			t.Errorf("tool %q has an empty description", tool.Name)
		}

		// 5. Input schema present. Registration-only: we do not invoke the
		// handler (that would require a live Postgres pool for the kb_*
		// tools), we only assert the schema the SDK advertised at
		// registration time is usable.
		if tool.InputSchema == nil {
			t.Errorf("tool %q has a nil input schema", tool.Name)
		}
	}
}
