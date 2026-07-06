/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

func TestKBVerbs_AllRegistered(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	want := []string{
		"kb.search",
		"kb.facts",
		"kb.gaps",
		"kb.stats",
		"kb.apps",
		"kb.diff_apps",
		"kb.export",
		"kb.import",
		"kb.dump",
		"kb.timeline",
		"kb.pull_gap",
		"kb.push_answer",
		"kb.doctor",
	}
	for _, v := range want {
		if !sv.HasVerb(v) {
			t.Errorf("supervisor missing verb %q", v)
		}
	}
}

func TestKBVerbs_NoDBReturnsUnavailable(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp}) // no DSN ⇒ no pool
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	// Drive a kb.search request directly via the handler by invoking it
	// against the supervisor through a net.Pipe round-trip. We reuse
	// the bus pattern from registry_test (when present) here.
	_, eb := sv.kbSearch(context.Background(), mustJSON(t, KBSearchParams{Query: "x"}))
	if eb == nil {
		t.Fatalf("kbSearch with no DB: want ErrorBody, got nil")
	}
	if eb.Code != ipc.CodeUnavailable {
		t.Errorf("kbSearch no-DB: got code %d, want %d", eb.Code, ipc.CodeUnavailable)
	}
}

func TestKBVerbs_BadParamShape(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	// kb.search with empty query → 400 even though DB is nil because
	// the no-DB short-circuit runs first. Validate that the verb
	// surface treats no-DB as the more-fundamental error.
	_, eb := sv.kbSearch(context.Background(), mustJSON(t, KBSearchParams{Query: ""}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.search empty-query no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.diff_apps now goes through kbstore.DiffApps, so no-DB short-
	// circuits at CodeUnavailable just like the other read verbs.
	_, eb = sv.kbDiffApps(context.Background(), mustJSON(t, KBDiffAppsParams{AppA: "", AppB: ""}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.diff_apps no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.timeline now goes through kbstore.Timeline (Phase A4), so no-DB
	// short-circuits at CodeUnavailable just like the other read verbs.
	// Missing-kb_id validation only fires once the DB pool is present.
	_, eb = sv.kbTimeline(context.Background(), mustJSON(t, KBTimelineParams{}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.timeline no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.push_answer with gap_id=0 → CodeUnavailable wins because no DB
	// is wired; the no-DB short-circuit runs before parameter validation
	// (same pattern as kb.search/kb.timeline).
	_, eb = sv.kbPushAnswer(context.Background(), mustJSON(t, KBPushAnswerParams{GapID: 0, Value: "ans"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.push_answer no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.pull_gap with no DB short-circuits to CodeUnavailable too.
	_, eb = sv.kbPullGap(context.Background(), mustJSON(t, KBPullGapParams{App: "x"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.pull_gap no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}
}

func TestKBVerbs_NotImplementedReturnsUpstream(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	// kb.diff_apps was extracted into kbstore.DiffApps as part of the
	// v2.17 thin-client refactor (Phase A1); with no DB pool the verb
	// now short-circuits to CodeUnavailable instead of CodeUpstream.
	_, eb := sv.kbDiffApps(context.Background(), mustJSON(t, KBDiffAppsParams{AppA: "a", AppB: "b"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.diff_apps no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.export was extracted into kbstore.Export as part of the v2.17
	// thin-client refactor (Phase A2); with no DB pool the verb now
	// short-circuits to CodeUnavailable instead of CodeUpstream.
	_, eb = sv.kbExport(context.Background(), mustJSON(t, KBExportParams{KBID: "x"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.export no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.import was extracted into kbstore.Import as part of the v2.17
	// thin-client refactor (Phase A3); with no DB pool the verb now
	// short-circuits to CodeUnavailable instead of CodeUpstream.
	_, eb = sv.kbImport(context.Background(), mustJSON(t, KBImportParams{Path: "/tmp/x"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.import no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.timeline was extracted into kbstore.Timeline as part of the v2.17
	// thin-client refactor (Phase A4); with no DB pool the verb now
	// short-circuits to CodeUnavailable instead of CodeUpstream.
	_, eb = sv.kbTimeline(context.Background(), mustJSON(t, KBTimelineParams{KbID: "x"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.timeline no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.pull_gap was extracted into kbstore.PullGap as part of the v2.17
	// thin-client refactor (Phase A5); with no DB pool the verb now
	// short-circuits to CodeUnavailable instead of CodeUpstream.
	_, eb = sv.kbPullGap(context.Background(), mustJSON(t, KBPullGapParams{App: "x"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.pull_gap no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.push_answer was extracted into kbstore.PushAnswer as part of the
	// v2.17 thin-client refactor (Phase A6); with no DB pool the verb now
	// short-circuits to CodeUnavailable instead of CodeUpstream.
	_, eb = sv.kbPushAnswer(context.Background(), mustJSON(t, KBPushAnswerParams{GapID: 1, Value: "x"}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.push_answer no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.apps was extracted into kbstore.Apps as part of the v2.17
	// thin-client refactor (Phase A-Apps); with no DB pool the verb now
	// short-circuits to CodeUnavailable.
	_, eb = sv.kbApps(context.Background(), mustJSON(t, KBAppsParams{}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.apps no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}

	// kb.doctor was extracted into kbstore.Doctor as part of the v2.17
	// thin-client refactor (Phase A7); with no DB pool the verb now
	// short-circuits to CodeUnavailable.
	_, eb = sv.kbDoctor(context.Background(), mustJSON(t, KBDoctorParams{}))
	if eb == nil || eb.Code != ipc.CodeUnavailable {
		t.Fatalf("kb.doctor no-DB: got eb=%v, want code %d", eb, ipc.CodeUnavailable)
	}
}

// TestKBImportParams_VerifyKeyWireShape locks the additive verify_key_path
// field onto the kb.import wire contract (hardening #7), so an operator-
// supplied pinned key reaches kbstore.Import via the supervisor/MCP path,
// not only the CLI. omitempty keeps existing unsigned imports unchanged.
func TestKBImportParams_VerifyKeyWireShape(t *testing.T) {
	raw := mustJSON(t, KBImportParams{Path: "/tmp/x", VerifyKeyPath: "/keys/pub.key"})
	var back KBImportParams
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.VerifyKeyPath != "/keys/pub.key" {
		t.Fatalf("verify_key_path round-trip: got %q", back.VerifyKeyPath)
	}
	// omitempty: an empty key must not emit the field, preserving the
	// pre-hardening wire shape for default (unsigned) imports.
	rawEmpty := mustJSON(t, KBImportParams{Path: "/tmp/x"})
	if string(rawEmpty) == "" || containsField(string(rawEmpty), "verify_key_path") {
		t.Fatalf("empty verify_key_path should be omitted, got %s", rawEmpty)
	}
}

func containsField(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// Smoke test that the ipc.ErrorBody marshalling round-trips so client-side
// translateKBErr can pattern-match on the Code field.
func TestKBErrorBodyShape(t *testing.T) {
	eb := &ipc.ErrorBody{Code: ipc.CodeUpstream, Message: "kb.export: not_implemented"}
	if eb.Error() == "" {
		t.Fatal("ErrorBody.Error() empty")
	}
	var asEB *ipc.ErrorBody
	if !errors.As(eb, &asEB) {
		t.Fatal("errors.As on *ErrorBody failed")
	}
	if asEB.Code != ipc.CodeUpstream {
		t.Errorf("code = %d, want %d", asEB.Code, ipc.CodeUpstream)
	}
}
