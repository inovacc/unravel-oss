//go:build evidence

/*
Copyright (c) 2026 Security Research

Build-tagged helper that emits Teams score evidence to stderr when run with
`go test -run TestPrintTeamsEvidence -v` — used during plan 13-03 live
verification when the full `unravel` binary cannot link due to unrelated
sibling-plan WIP.
*/

package risk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

func TestPrintTeamsEvidence(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "teams_caps.json"))
	if err != nil {
		t.Fatal(err)
	}
	var caps []uwp.CapabilityRef
	if err := json.Unmarshal(raw, &caps); err != nil {
		t.Fatal(err)
	}
	score := Score(caps, uwp.SignatureInfo{Status: "trusted-microsoft", Subject: "CN=Microsoft Corporation"}, DefaultRubric())
	outPath := os.Getenv("UNRAVEL_EVIDENCE_OUT")
	if outPath == "" {
		outPath = filepath.Join(os.TempDir(), "teams_evidence.txt")
	}
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	fmt.Fprintf(out, "VALUE=%d LEVEL=%s BASE=%d MULT=%.2f\n", score.Value, score.Level, score.Base, score.Multiplier)
	for _, e := range score.Evidence {
		fmt.Fprintf(out, "EV: %s\n", e)
	}
	t.Logf("evidence written to %s", out.Name())
}
