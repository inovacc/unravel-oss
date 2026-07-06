/*
Copyright (c) 2026 Security Research
*/
package risk

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

func TestDefaultWeights_AllAnchorsPresent(t *testing.T) {
	w := DefaultWeights()
	anchors := map[string]int{
		"internetClient":             40,
		"internetClientServer":       60,
		"privateNetworkClientServer": 60,
		"webcam":                     70,
		"microphone":                 70,
		"location":                   70,
		"screenCapture":              75,
		"userDataSystem":             75,
		"removableStorage":           40,
		"bluetooth":                  40,
		"wifiControl":                50,
		"phoneCall":                  45,
		"radios":                     40,
		"lowLevelDevices":            50,
		"musicLibrary":               15,
		"videosLibrary":              15,
		"userAccountInformation":     20,
		"chat":                       15,
		"objects3D":                  10,
		"recordedCallsFolder":        15,
		"runFullTrust":               100,
		"allowElevation":             100,
		"broadFileSystemAccess":      100,
		"documentsLibrary":           100,
		"picturesLibrary":            100,
		"enterpriseAuthentication":   100,
		"confirmAppClose":            100,
		"inputObservation":           100,
		"inputInjectionBrokered":     100,
	}
	for name, want := range anchors {
		got, ok := w[name]
		if !ok {
			t.Errorf("DefaultWeights missing anchor %q", name)
			continue
		}
		if got != want {
			t.Errorf("DefaultWeights[%q]=%d want %d", name, got, want)
		}
	}
}

func TestDefaultRubric_Shape(t *testing.T) {
	r := DefaultRubric()
	if r.UnknownCapBucket != "high" {
		t.Errorf("UnknownCapBucket=%q want high", r.UnknownCapBucket)
	}
	if r.UnknownCapWeight != 50 {
		t.Errorf("UnknownCapWeight=%d want 50", r.UnknownCapWeight)
	}
	if r.SignatureMultipliers["unsigned"] != 2.0 {
		t.Errorf("SignatureMultipliers[unsigned]=%v want 2.0", r.SignatureMultipliers["unsigned"])
	}
	if r.SignatureMultipliers["trusted-microsoft"] != 0.8 {
		t.Errorf("SignatureMultipliers[trusted-microsoft]=%v want 0.8", r.SignatureMultipliers["trusted-microsoft"])
	}
	if r.TrustedMicrosoftMaxLevel != "high" {
		t.Errorf("TrustedMicrosoftMaxLevel=%q want high", r.TrustedMicrosoftMaxLevel)
	}
	if len(r.Buckets) != 4 {
		t.Errorf("len(Buckets)=%d want 4", len(r.Buckets))
	}
}

func TestLoadRubric_Override(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.yaml")
	if err := os.WriteFile(path, []byte(`weights:
  internetClient: 99
`), 0o644); err != nil {
		t.Fatal(err)
	}
	rub, err := LoadRubric(path)
	if err != nil {
		t.Fatalf("LoadRubric: %v", err)
	}
	if rub.Weights["internetClient"] != 99 {
		t.Errorf("override weight=%d want 99", rub.Weights["internetClient"])
	}
	// Defaults preserved for untouched keys.
	if rub.Weights["webcam"] != 70 {
		t.Errorf("webcam default=%d want 70", rub.Weights["webcam"])
	}
}

func TestLoadRubric_AbsentFile(t *testing.T) {
	_, err := LoadRubric("/nonexistent/caps.yaml")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestLoadRubric_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("weights:\n  internetClient: [oops]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRubric(path)
	if err == nil {
		t.Error("expected error on malformed yaml")
	}
}

// TestRubric_TeamsZeroUnknowns verifies BUG-05: scoring the captured Teams
// capability set must produce zero `unknown_capability:` evidence lines.
// Source fixture: pkg/uwp/risk/testdata/teams_caps.json.
func TestRubric_TeamsZeroUnknowns(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "teams_caps.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var caps []uwp.CapabilityRef
	if err := json.Unmarshal(raw, &caps); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	sig := uwp.SignatureInfo{Status: "trusted-microsoft"}
	score := Score(caps, sig, DefaultRubric())

	for _, e := range score.Evidence {
		if strings.HasPrefix(e, "unknown_capability:") {
			t.Errorf("unexpected unknown_capability evidence: %q", e)
		}
	}
}

// TestRubric_GraphicsCaptureWithoutBorderCritical verifies that the silent
// screen-capture cap forces level=critical even with the trusted-microsoft
// 0.8 multiplier that would otherwise pull the bucket down.
func TestRubric_GraphicsCaptureWithoutBorderCritical(t *testing.T) {
	caps := []uwp.CapabilityRef{
		{Name: "graphicsCaptureWithoutBorder", Namespace: "uap6", Index: 0},
	}
	sig := uwp.SignatureInfo{Status: "trusted-microsoft"}
	score := Score(caps, sig, DefaultRubric())
	if score.Level != "critical" {
		t.Errorf("Level=%q want critical (evidence=%v)", score.Level, score.Evidence)
	}
}

// TestRubric_NamespaceNormalize_UapW10_11 verifies that the raw URI namespace
// emitted by the AppxManifest parser ("unknown:http://...uap/windows10/11")
// is folded onto "uap6" before rubric lookup.
func TestRubric_NamespaceNormalize_UapW10_11(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"unknown:http://schemas.microsoft.com/appx/manifest/uap/windows10/11", "uap6"},
		{"http://schemas.microsoft.com/appx/manifest/uap/windows10/11", "uap6"},
		{"unknown:http://schemas.microsoft.com/appx/manifest/uap/windows10/10", "uap5"},
		{"uap6", "uap6"},
		{"rescap", "rescap"},
		{"", ""},
	}
	for _, tc := range cases {
		got := normalizeNamespace(tc.in)
		if got != tc.want {
			t.Errorf("normalizeNamespace(%q)=%q want %q", tc.in, got, tc.want)
		}
	}

	// End-to-end: a graphicsCapture cap declared under the raw URI must
	// resolve through the rubric (no `unknown_capability:` evidence).
	caps := []uwp.CapabilityRef{
		{Name: "graphicsCapture", Namespace: "unknown:http://schemas.microsoft.com/appx/manifest/uap/windows10/11"},
	}
	score := Score(caps, uwp.SignatureInfo{Status: "trusted-microsoft"}, DefaultRubric())
	for _, e := range score.Evidence {
		if strings.HasPrefix(e, "unknown_capability:") {
			t.Fatalf("namespace not normalized; got unknown_capability evidence: %v", score.Evidence)
		}
	}
}
