//go:build integration

/*
Copyright (c) 2026 Security Research

Phase 36 Plan 01: kb query-surface driver helpers.

These helpers in-process drive `unravel kb apps`, `unravel kb timeline`,
`unravel kb diff`, and `unravel kb search` against a testcontainers
Postgres DSN — mirroring the `driveKbCapture` pattern from P35-02
(cmd/kb_capture_e2e_integration_test.go).

Each helper:
  - Snapshots and restores the corresponding cobra-bound flag state via
    t.Cleanup so parallel subtests don't bleed into each other.
  - Forces JSON output so the caller parses structured data, not the
    human-readable table.
  - Captures stdout via cobra.Command.SetOut(buf) and returns the
    JSON-decoded payload as the loose `map[string]any` shape used by the
    underlying commands' MCP/JSON contract.
  - Fails the test on JSON unmarshal error — broken structured output
    is a real defect, not a skip condition.

Note on the `mode` parameter to driveKbSearch: the underlying `kb search`
cobra command takes a single positional <query> and runs trigram fuzzy
match against modules.search_text. There is no `--package-id` or
`--display-name` flag on the command. The `mode` argument here is
documentary only — it informs the caller's expectation framing
(exact-package vs. substring-display) but the helper still passes the
caller-supplied string as the positional <query>. Both modes thus exercise
the same code path; the assertion shape (top-hit vs. any-hit) differs at
the call site.
*/

package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"testing"
)

// driveKbApps runs `unravel kb apps --json` in-process and returns the
// parsed `items` array as a slice of map[string]any.
func driveKbApps(t *testing.T, ctx context.Context, db *sql.DB) []map[string]any {
	t.Helper()
	_ = db // db is held by the caller for cross-checks; not required here.

	saved := kbAppsFlags
	t.Cleanup(func() { kbAppsFlags = saved })
	kbAppsFlags.platform = ""
	kbAppsFlags.framework = ""
	kbAppsFlags.risk = ""
	kbAppsFlags.tags = nil
	kbAppsFlags.since = ""
	kbAppsFlags.limit = 1000
	kbAppsFlags.includeAliases = false
	kbAppsFlags.json = true

	var buf bytes.Buffer
	cmd := appsCmd
	cmd.SetContext(ctx)
	cmd.SetOut(&buf)
	if err := runKbApps(cmd, []string{}); err != nil {
		t.Fatalf("runKbApps: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal kb apps json: %v\nraw: %s", err, buf.String())
	}
	return coerceItems(t, payload, "items")
}

// driveKbTimeline runs `unravel kb timeline <kbID> --json` in-process and
// returns the parsed `epochs` array.
func driveKbTimeline(t *testing.T, ctx context.Context, db *sql.DB, kbID string) []map[string]any {
	t.Helper()
	_ = db

	saved := kbTimelineFlags
	t.Cleanup(func() { kbTimelineFlags = saved })
	kbTimelineFlags.reverse = false
	kbTimelineFlags.json = true

	var buf bytes.Buffer
	cmd := timelineCmd
	cmd.SetContext(ctx)
	cmd.SetOut(&buf)
	if err := runKbTimeline(cmd, []string{kbID}); err != nil {
		t.Fatalf("runKbTimeline(%s): %v", kbID, err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal kb timeline json: %v\nraw: %s", err, buf.String())
	}
	return coerceItems(t, payload, "epochs")
}

// driveKbDiff runs `unravel kb diff <kbID> --from <fromEpoch> --to <toEpoch> --json`
// in-process and returns the parsed DiffResult as a generic map.
func driveKbDiff(t *testing.T, ctx context.Context, db *sql.DB, kbID string, fromEpoch, toEpoch int) map[string]any {
	t.Helper()
	_ = db

	savedFrom := kbDiffFrom
	savedTo := kbDiffTo
	savedCat := kbDiffCategory
	savedJSON := kbDiffJSON
	savedDSN := kbDiffDSN
	t.Cleanup(func() {
		kbDiffFrom = savedFrom
		kbDiffTo = savedTo
		kbDiffCategory = savedCat
		kbDiffJSON = savedJSON
		kbDiffDSN = savedDSN
	})
	kbDiffFrom = int64(fromEpoch)
	kbDiffTo = int64(toEpoch)
	kbDiffCategory = nil
	kbDiffJSON = true

	var buf bytes.Buffer
	cmd := diffCmd
	cmd.SetContext(ctx)
	cmd.SetOut(&buf)
	if err := runKbDiff(cmd, []string{kbID}); err != nil {
		t.Fatalf("runKbDiff(%s, %d->%d): %v", kbID, fromEpoch, toEpoch, err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal kb diff json: %v\nraw: %s", err, buf.String())
	}
	return payload
}

// driveKbSearch runs `unravel kb search <query> --json` in-process and
// returns the parsed `items` array. `mode` ∈ {"exact-package",
// "substring-display"} is documentary — see file header for rationale.
func driveKbSearch(t *testing.T, ctx context.Context, db *sql.DB, query string, mode string) []map[string]any {
	t.Helper()
	_ = db
	switch mode {
	case "exact-package", "substring-display":
		// supported framings; both pass `query` as the positional arg.
	default:
		t.Fatalf("driveKbSearch: unsupported mode %q (want exact-package|substring-display)", mode)
	}

	savedApp := searchApp
	savedComponent := searchComponent
	savedFactType := searchFactType
	savedLang := searchLang
	savedSince := searchSince
	savedLimit := searchLimit
	savedCursor := searchCursor
	savedJSON := searchJSON
	savedDSN := searchDSN
	t.Cleanup(func() {
		searchApp = savedApp
		searchComponent = savedComponent
		searchFactType = savedFactType
		searchLang = savedLang
		searchSince = savedSince
		searchLimit = savedLimit
		searchCursor = savedCursor
		searchJSON = savedJSON
		searchDSN = savedDSN
	})
	searchApp = ""
	searchComponent = ""
	searchFactType = ""
	searchLang = ""
	searchSince = ""
	searchLimit = 50
	searchCursor = ""
	searchJSON = true

	var buf bytes.Buffer
	cmd := kbSearchCmd
	cmd.SetContext(ctx)
	cmd.SetOut(&buf)
	if err := runKbSearch(kbSearchCmd, []string{query}); err != nil {
		t.Fatalf("runKbSearch(%q, %s): %v", query, savedDSN, err)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal kb search json: %v\nraw: %s", err, buf.String())
	}
	return coerceItems(t, payload, "items")
}

// coerceItems extracts a `[]map[string]any` from payload[key]. The
// command JSON encoders emit `null` for empty slices, which json.Unmarshal
// converts to nil — that case is returned as an empty slice (not a nil
// slice) so the caller's `len(...)` checks behave consistently.
func coerceItems(t *testing.T, payload map[string]any, key string) []map[string]any {
	t.Helper()
	raw, ok := payload[key]
	if !ok || raw == nil {
		return []map[string]any{}
	}
	arr, ok := raw.([]any)
	if !ok {
		t.Fatalf("coerceItems: payload[%q] not array, got %T", key, raw)
	}
	out := make([]map[string]any, 0, len(arr))
	for i, v := range arr {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("coerceItems: payload[%q][%d] not object, got %T", key, i, v)
		}
		out = append(out, m)
	}
	return out
}
