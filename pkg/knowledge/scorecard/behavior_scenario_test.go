/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBehaviorScenario_DetectsClasses loads the hermetic WhatsApp fixture and
// asserts ≥4 scenario classes hit at 6 pts each.
func TestBehaviorScenario_DetectsClasses(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "whatsapp_frames_excerpt.ndjson"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	tmp := t.TempDir()
	// Writer keys the -kb dir off the package FAMILY (Name_PublisherId);
	// the scorer is handed the full MSIX identity and normalizes to it.
	fullIdent := "WhatsAppDesktop_2.0.0.0_x64__test"
	family := "WhatsAppDesktop_test"
	kbDir := filepath.Join(tmp, family+"-kb")
	if err := os.MkdirAll(kbDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kbDir, "frames.ndjson"), fixture, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	orig := scorecardBaseDir
	scorecardBaseDir = tmp
	defer func() { scorecardBaseDir = orig }()

	got := scoreBehaviorScenarios(fullIdent)
	if got < 24 {
		t.Fatalf("scoreBehaviorScenarios = %d, want ≥24 (≥4 classes × 6 pts)", got)
	}
	if got > 30 {
		t.Fatalf("scoreBehaviorScenarios = %d, exceeds cap 30", got)
	}
}

// TestBehaviorScenario_PackageFamilyKeyReconciled is the H4 path-contract
// regression guard (72-EVIDENCE.md PRIMARY ROOT CAUSE). The writer keys the
// -kb dir off the package FAMILY ($pkgId, e.g. MSTeams_8wekyb3d8bbwe) while
// the reader receives the MSIX FULL IDENTITY
// (Name_Version_Arch__PublisherId). Before the fix these never coincide and
// the scenario bonus is structurally unreachable. After the fix the reader
// normalizes the full identity down to the package-family key so a sidecar
// written under <family>-kb/ is resolved.
func TestBehaviorScenario_PackageFamilyKeyReconciled(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "whatsapp_frames_excerpt.ndjson"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	cases := []struct {
		name       string
		fullIdent  string // what MSIXInfo.PackageName carries in production
		familyName string // what frames_writer.go keyed the -kb dir off ($pkgId)
	}{
		{
			name:       "teams full identity -> family",
			fullIdent:  "MSTeams_24295.605.3225.8804_x64__8wekyb3d8bbwe",
			familyName: "MSTeams_8wekyb3d8bbwe",
		},
		{
			name:       "whatsapp full identity -> family",
			fullIdent:  "5319275A.WhatsAppDesktop_2.2616.100.0_x64__cv1g1gvanyjgm",
			familyName: "5319275A.WhatsAppDesktop_cv1g1gvanyjgm",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			// Writer wrote the sidecar under the FAMILY-keyed -kb dir.
			kbDir := filepath.Join(tmp, tc.familyName+"-kb")
			if err := os.MkdirAll(kbDir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(kbDir, "frames.ndjson"), fixture, 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			orig := scorecardBaseDir
			scorecardBaseDir = tmp
			defer func() { scorecardBaseDir = orig }()

			// Reader is handed the FULL IDENTITY (production H4 condition).
			// Post-fix it must normalize to the family key and resolve the
			// writer's sidecar.
			if got := scoreBehaviorScenarios(tc.fullIdent); got < 24 {
				t.Fatalf("scoreBehaviorScenarios(%q) = %d, want ≥24 (path-key reconciled to %q-kb)", tc.fullIdent, got, tc.familyName)
			}

			// And the normalizer itself: full identity -> package family.
			if got := packageFamilyKey(tc.fullIdent); got != tc.familyName {
				t.Fatalf("packageFamilyKey(%q) = %q, want %q", tc.fullIdent, got, tc.familyName)
			}
		})
	}

	// A value that is ALREADY a family key (no version/arch middle) is a
	// no-op — the normalizer must be idempotent.
	if got := packageFamilyKey("MSTeams_8wekyb3d8bbwe"); got != "MSTeams_8wekyb3d8bbwe" {
		t.Fatalf("packageFamilyKey idempotency: got %q, want %q", got, "MSTeams_8wekyb3d8bbwe")
	}
	// A bare Name with no underscore is returned unchanged.
	if got := packageFamilyKey("5319275A.WhatsAppDesktop"); got != "5319275A.WhatsAppDesktop" {
		t.Fatalf("packageFamilyKey bare-name: got %q, want %q", got, "5319275A.WhatsAppDesktop")
	}
}

// TestBehaviorScenario_MissingFile points at a nonexistent kbDir and asserts
// zero with no error (no panic, no log).
func TestBehaviorScenario_MissingFile(t *testing.T) {
	orig := scorecardBaseDir
	scorecardBaseDir = t.TempDir()
	defer func() { scorecardBaseDir = orig }()

	if got := scoreBehaviorScenarios("DoesNotExist"); got != 0 {
		t.Fatalf("missing-file score = %d, want 0", got)
	}
	if got := scoreBehaviorScenarios(""); got != 0 {
		t.Fatalf("empty packageName score = %d, want 0", got)
	}
}

// TestBehaviorScenario_CapAt30 synthesises all 5 classes ×2 each in-memory and
// asserts the sum is capped at 30.
func TestBehaviorScenario_CapAt30(t *testing.T) {
	// All 5 classes, each appearing twice, to prove single-hit-per-class +
	// cap-at-30 invariant.
	lines := []string{
		`{"opcode":1,"dir":"recv","payload_len":1,"payload_truncated":"5461726765742e6174746163686564546f546172676574"}`,
		`{"opcode":1,"dir":"recv","payload_len":1,"payload_truncated":"5461726765742e6174746163686564546f546172676574"}`,
		`{"opcode":1,"dir":"recv","payload_len":1,"payload_truncated":"506167652e6672616d654e6176696761746564"}`,
		`{"opcode":1,"dir":"recv","payload_len":1,"payload_truncated":"506167652e6672616d654e6176696761746564"}`,
		`{"opcode":1,"dir":"recv","payload_len":1,"payload_truncated":"4e6574776f726b2e7265717565737457696c6c426553656e74"}`,
		`{"opcode":1,"dir":"recv","payload_len":1,"payload_truncated":"4e6574776f726b2e7265717565737457696c6c426553656e74"}`,
		`{"opcode":1,"dir":"sent","payload_len":18,"payload_truncated":"7b2274797065223a2263686174227d"}`,
		`{"opcode":1,"dir":"sent","payload_len":18,"payload_truncated":"7b2274797065223a2263686174227d"}`,
		`{"opcode":8,"dir":"recv","payload_len":0,"payload_truncated":""}`,
		`{"opcode":8,"dir":"recv","payload_len":0,"payload_truncated":""}`,
	}
	got := scoreScenariosFromReader(strings.NewReader(strings.Join(lines, "\n")), defaultScenarios)
	if got != 30 {
		t.Fatalf("cap test score = %d, want exactly 30", got)
	}
}

// TestBehaviorScenario_MalformedLinesIgnored — additive-only invariant: a
// malformed NDJSON line MUST NOT cause an error or short-circuit; subsequent
// valid lines still contribute.
func TestBehaviorScenario_MalformedLinesIgnored(t *testing.T) {
	lines := []string{
		`not-json-at-all`,
		`{`,
		`{"opcode":8,"dir":"recv","payload_len":0,"payload_truncated":""}`,
	}
	got := scoreScenariosFromReader(strings.NewReader(strings.Join(lines, "\n")), defaultScenarios)
	if got != 6 {
		t.Fatalf("malformed-ignore score = %d, want 6 (session_close only)", got)
	}
}
