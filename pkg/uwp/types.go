/*
Copyright (c) 2026 Security Research
*/

package uwp

import "github.com/inovacc/unravel-oss/pkg/winui"

// FrameworkInfo is a re-export of winui.FrameworkInfo (D-01). The canonical
// home for the type is pkg/winui; pkg/uwp aliases it so dissect callers can
// pass slices interchangeably without conversion.
type FrameworkInfo = winui.FrameworkInfo

// Result aggregates everything known about a UWP packaged application.
// Manifest and Score are populated by plan 02; XAMLIndex by plans 03/04/05;
// DPAPIBlobs by plan 05 (D-18 carry-forward — flag-only, never decrypted).
type Result struct {
	IsUWP      bool             `json:"is_uwp"`
	Frameworks []FrameworkInfo  `json:"frameworks,omitempty"`
	Manifest   *ManifestSummary `json:"manifest,omitempty"`
	Score      *Score           `json:"score,omitempty"`
	XAMLIndex  *winui.XAMLIndex `json:"xaml_index,omitempty"`
	DPAPIBlobs []DPAPIBlob      `json:"dpapi_blobs,omitempty"`
	Errors     []string         `json:"errors,omitempty"`
}

// ManifestSummary holds the fields extracted from an AppxManifest.xml that the
// scoring layer cares about (D-04 manifest-order, FRM-07/FRM-08 capability
// surface). It is a denormalised view of msix.AppxManifest produced by
// pkg/uwp/manifest.Summarize.
type ManifestSummary struct {
	PFN            string          `json:"pfn"`
	Identity       IdentityInfo    `json:"identity"`
	TargetFamilies []string        `json:"target_families,omitempty"`
	Capabilities   []CapabilityRef `json:"capabilities"`
	EntryPoints    []EntryPoint    `json:"entry_points,omitempty"`
}

// IdentityInfo mirrors the Identity element of an AppxManifest.
type IdentityInfo struct {
	Name          string `json:"name"`
	Publisher     string `json:"publisher"`
	Version       string `json:"version"`
	ProcessorArch string `json:"processor_arch,omitempty"`
}

// EntryPoint represents a single <Application> element of an AppxManifest.
type EntryPoint struct {
	Id         string `json:"id"`
	Executable string `json:"executable"`
	EntryPoint string `json:"entry_point,omitempty"`
}

// CapabilityRef is one capability declaration in manifest order. Namespace is
// "" (foundation) | "uap" | "uap2" | ... | "uap15" | "rescap" | "device" |
// "custom" | "unknown" (or "unknown:<uri>").
type CapabilityRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Index     int    `json:"index"`
}

// IsRescap reports whether this CapabilityRef belongs to the
// restrictedcapabilities namespace (D-12 auto-critical trigger).
func (c CapabilityRef) IsRescap() bool { return c.Namespace == "rescap" }

// IsUnknown reports whether the capability namespace was not recognised by the
// parser. Unknown capabilities are scored at the configured minimum bucket
// (D-12: "high" by default).
func (c CapabilityRef) IsUnknown() bool {
	return c.Namespace == "unknown" || (len(c.Namespace) > 8 && c.Namespace[:8] == "unknown:")
}

// SignatureInfo is the result of inspecting an MSIX/Appx digital signature.
// Status is one of: "trusted-microsoft" | "trusted-other" | "self-signed" |
// "unsigned" | "invalid".
type SignatureInfo struct {
	Status  string `json:"status"`
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// Score is the categorical-plus-numeric capability risk score (D-10).
// Level is "low" | "medium" | "high" | "critical". Value is 0..100 post-multiplier.
// Base is the pre-multiplier weighted sum. Multiplier is the signature multiplier (D-13).
// Evidence is a stable, greppable trace of the rules that fired.
type Score struct {
	Value      int      `json:"value"`
	Level      string   `json:"level"`
	Base       int      `json:"base"`
	Multiplier float64  `json:"multiplier"`
	Evidence   []string `json:"evidence,omitempty"`
}

// Bucket describes one entry of the categorical bucket ladder.
type Bucket struct {
	Name string `json:"name" yaml:"name"`
	Max  int    `json:"max"  yaml:"max"`
}

// Rubric is the resolved capability-scoring policy: weights (per-capability),
// auto-critical rules, unknown-capability handling, signature multipliers, and
// the bucket ladder. Built from Go defaults or a YAML override (D-11).
//
// LevelOverrides (BUG-05 / D-05) maps capability name → minimum level that the
// final score must satisfy when that capability is present. The override
// promotes the bucket-derived level upward but never downgrades it. This is
// how silent screen-capture caps (graphicsCaptureWithoutBorder) stay critical
// even with a trusted-microsoft signature multiplier (0.8) that would
// otherwise pull the bucket down.
type Rubric struct {
	Weights                  map[string]int     `json:"weights"`
	LevelOverrides           map[string]string  `json:"level_overrides,omitempty"`
	AutoCriticalNamespaces   []string           `json:"auto_critical_namespaces,omitempty"`
	AutoCriticalNames        []string           `json:"auto_critical_names,omitempty"`
	UnknownCapBucket         string             `json:"unknown_cap_bucket"`
	UnknownCapWeight         int                `json:"unknown_cap_weight"`
	SignatureMultipliers     map[string]float64 `json:"signature_multipliers"`
	TrustedMicrosoftMaxLevel string             `json:"trusted_microsoft_max_level"`
	Buckets                  []Bucket           `json:"buckets"`
}
