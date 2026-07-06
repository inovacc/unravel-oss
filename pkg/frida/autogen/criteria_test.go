/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/frida"
	"github.com/inovacc/unravel-oss/pkg/inject"
)

func TestCriteria_LinuxHasPreflightEvent(t *testing.T) {
	yes := true
	s := inject.Seam{
		Kind:                 "DT_NEEDED",
		Confidence:           inject.ConfidenceMedium,
		Framework:            inject.FrameworkElectron,
		Evidence:             []inject.Evidence{{Type: inject.EvidenceFileContent, Path: "libdl.so.2"}},
		PtraceEligibleBinary: &yes,
	}
	out, err := renderCriteria(s, "linux", "abc12345")
	if err != nil {
		t.Fatal(err)
	}
	str := string(out)
	if !strings.Contains(str, "preflight_failed") {
		t.Error("linux criteria must include preflight_failed event")
	}
	if !strings.Contains(str, "pre_attach_check") {
		t.Error("linux criteria must include pre_attach_check field (embedded in hook description)")
	}
}

func TestCriteria_MacOSHasDlopen(t *testing.T) {
	s := inject.Seam{Kind: "LC_LOAD_DYLIB", Framework: inject.FrameworkMacOS, Confidence: inject.ConfidenceHigh}
	out, err := renderCriteria(s, "macos", "cafef00d")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "dlopen_intercepted") {
		t.Error("macos criteria must include dlopen_intercepted")
	}
}

func TestCriteria_WindowsNoPreflight(t *testing.T) {
	s := inject.Seam{Kind: "IAT", Framework: inject.FrameworkElectron, Confidence: inject.ConfidenceHigh}
	out, err := renderCriteria(s, "windows", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "preflight_failed") {
		t.Error("windows criteria must not include preflight_failed")
	}
}

func TestCriteria_RoundTrip_DecodesAsCriteriaFile(t *testing.T) {
	s := inject.Seam{Kind: "IAT", Framework: inject.FrameworkElectron, Confidence: inject.ConfidenceHigh}
	out, err := renderCriteria(s, "windows", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	var cf frida.CriteriaFile
	if err := json.Unmarshal(out, &cf); err != nil {
		t.Fatalf("unmarshal as CriteriaFile: %v", err)
	}
	if cf.SchemaVersion != 1 {
		t.Errorf("schema_version = %d; want 1", cf.SchemaVersion)
	}
	if len(cf.Hooks) == 0 {
		t.Error("hooks must be non-empty")
	}
	if cf.Script == "" {
		t.Error("script must be set")
	}
}
