/*
Copyright (c) 2026 Security Research
*/
package risk

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

func sigUnsigned() uwp.SignatureInfo     { return uwp.SignatureInfo{Status: "unsigned"} }
func sigTrustedMS() uwp.SignatureInfo    { return uwp.SignatureInfo{Status: "trusted-microsoft"} }
func sigTrustedOther() uwp.SignatureInfo { return uwp.SignatureInfo{Status: "trusted-other"} }
func sigSelfSigned() uwp.SignatureInfo   { return uwp.SignatureInfo{Status: "self-signed"} }

func TestScore_Empty(t *testing.T) {
	s := Score(nil, sigUnsigned(), nil)
	if s.Value != 0 {
		t.Errorf("Value=%d want 0", s.Value)
	}
	if s.Level != "low" {
		t.Errorf("Level=%q want low", s.Level)
	}
	if s.Multiplier != 2.0 {
		t.Errorf("Multiplier=%v want 2.0", s.Multiplier)
	}
	if !strings.Contains(strings.Join(s.Evidence, "|"), "no capabilities") {
		t.Errorf("evidence missing 'no capabilities': %v", s.Evidence)
	}
}

func TestScore_OnlyInternetClient_Medium(t *testing.T) {
	caps := []uwp.CapabilityRef{{Name: "internetClient"}}
	s := Score(caps, sigTrustedOther(), nil)
	if s.Level != "medium" {
		t.Errorf("Level=%q want medium (value=%d, base=%d)", s.Level, s.Value, s.Base)
	}
	if s.Value < 26 || s.Value > 50 {
		t.Errorf("Value=%d outside [26,50]", s.Value)
	}
}

func TestScore_RescapAutoCritical(t *testing.T) {
	caps := []uwp.CapabilityRef{{Name: "runFullTrust", Namespace: "rescap"}}
	// Even with the trusted-microsoft cap, rescap forces critical (D-12).
	s := Score(caps, sigTrustedMS(), nil)
	if s.Level != "critical" {
		t.Errorf("Level=%q want critical", s.Level)
	}
	found := false
	for _, e := range s.Evidence {
		if strings.HasPrefix(e, "rescap auto-critical: runFullTrust") {
			found = true
		}
	}
	if !found {
		t.Errorf("evidence missing rescap trace: %v", s.Evidence)
	}
}

func TestScore_UnknownCapHigh(t *testing.T) {
	caps := []uwp.CapabilityRef{{Name: "contoso.weirdCapability_xxx", Namespace: "custom"}}
	s := Score(caps, sigTrustedOther(), nil)

	// Should be at least "high" per D-12.
	if s.Level != "high" && s.Level != "critical" {
		t.Errorf("Level=%q want high or critical", s.Level)
	}
	found := false
	for _, e := range s.Evidence {
		if e == "unknown_capability:contoso.weirdCapability_xxx" {
			found = true
		}
	}
	if !found {
		t.Errorf("evidence missing 'unknown_capability:contoso.weirdCapability_xxx': %v", s.Evidence)
	}
}

func TestScore_TrustedMSCapsBucket(t *testing.T) {
	caps := []uwp.CapabilityRef{
		{Name: "webcam"},
		{Name: "microphone"},
		{Name: "screenCapture", Namespace: "uap8"},
	}
	s := Score(caps, sigTrustedMS(), nil)
	// D-13: cap at "high" (one bucket below critical).
	if s.Level == "critical" {
		t.Errorf("trusted-microsoft should cap below critical, got %q", s.Level)
	}
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	if rank[s.Level] > rank["high"] {
		t.Errorf("Level=%q exceeds high cap", s.Level)
	}
}

func TestScore_UnsignedDoubles(t *testing.T) {
	// Pick a single ~40-weight capability so signed<100 and unsigned<=100,
	// keeping unsigned strictly larger than signed.
	caps := []uwp.CapabilityRef{{Name: "internetClient"}} // weight 40
	signed := Score(caps, sigTrustedOther(), nil)         // 40 * 1.0 = 40
	unsigned := Score(caps, sigUnsigned(), nil)           // 40 * 2.0 = 80
	if unsigned.Value <= signed.Value {
		t.Errorf("unsigned value=%d should exceed signed value=%d", unsigned.Value, signed.Value)
	}
	// Signed (40) -> "medium"; unsigned (80) -> "critical" (bucket maxes
	// are 25/50/75/100). Verify a strict upgrade by exactly two ranks.
	if signed.Level != "medium" {
		t.Errorf("signed level=%q want medium", signed.Level)
	}
	if unsigned.Level != "critical" {
		t.Errorf("unsigned level=%q want critical (value=%d)", unsigned.Level, unsigned.Value)
	}
}

func TestScore_UnsignedClampedAtCritical(t *testing.T) {
	// Heavy capability set with 2x multiplier should saturate at "critical".
	caps := []uwp.CapabilityRef{
		{Name: "webcam"},
		{Name: "microphone"},
		{Name: "screenCapture", Namespace: "uap8"},
	}
	unsigned := Score(caps, sigUnsigned(), nil)
	if unsigned.Level != "critical" {
		t.Errorf("unsigned level=%q want critical", unsigned.Level)
	}
	if unsigned.Value != 100 {
		t.Errorf("unsigned value=%d want 100 (clamped)", unsigned.Value)
	}
}

func TestScore_SelfSignedMultiplier(t *testing.T) {
	caps := []uwp.CapabilityRef{{Name: "internetClient"}}
	s := Score(caps, sigSelfSigned(), nil)
	if s.Multiplier != 1.5 {
		t.Errorf("Multiplier=%v want 1.5", s.Multiplier)
	}
	// Roughly 1.5 * 40 = 60.
	if s.Value < 55 || s.Value > 65 {
		t.Errorf("Value=%d not approximately 1.5x base 40", s.Value)
	}
}

func TestScore_EvidenceTraceStable(t *testing.T) {
	caps := []uwp.CapabilityRef{
		{Name: "webcam"},
		{Name: "microphone"},
		{Name: "internetClient"},
	}
	s := Score(caps, sigUnsigned(), nil)
	joined := strings.Join(s.Evidence, "\n")

	// Required trace ingredients.
	if !strings.Contains(joined, "unsigned multiplier 2.0") {
		t.Errorf("evidence missing multiplier trace: %v", s.Evidence)
	}
	// Top-3 weight contributors should appear.
	for _, want := range []string{"webcam +70", "microphone +70"} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence missing top-3 contributor %q: %v", want, s.Evidence)
		}
	}
}

func TestScore_NilRubricUsesDefaults(t *testing.T) {
	caps := []uwp.CapabilityRef{{Name: "internetClient"}}
	s1 := Score(caps, sigTrustedOther(), nil)
	s2 := Score(caps, sigTrustedOther(), DefaultRubric())
	if s1.Value != s2.Value || s1.Level != s2.Level {
		t.Errorf("nil rubric != DefaultRubric: %+v vs %+v", s1, s2)
	}
}

func TestScore_LoadRubricOverrideEffect(t *testing.T) {
	r := DefaultRubric()
	r.Weights["internetClient"] = 99
	caps := []uwp.CapabilityRef{{Name: "internetClient"}}
	s := Score(caps, sigTrustedOther(), r)
	// 99 * 1.0 = 99 -> "critical"
	if s.Value != 99 {
		t.Errorf("Value=%d want 99", s.Value)
	}
	if s.Level != "critical" {
		t.Errorf("Level=%q want critical", s.Level)
	}
}

func TestScore_NoEvidencePIIPaths(t *testing.T) {
	// T-04-10: ensure evidence strings never embed paths.
	caps := []uwp.CapabilityRef{
		{Name: "webcam"},
		{Name: "weirdCustomCap", Namespace: "custom"},
	}
	s := Score(caps, sigUnsigned(), nil)
	for _, e := range s.Evidence {
		if strings.Contains(e, "/") || strings.Contains(e, "\\") {
			t.Errorf("evidence leaks path-like characters: %q", e)
		}
	}
}
