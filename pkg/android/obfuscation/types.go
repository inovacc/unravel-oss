/*
Copyright (c) 2026 Security Research
*/
package obfuscation

// ObfuscationType identifies the obfuscation tool detected.
type ObfuscationType string

const (
	ObfNone     ObfuscationType = "none"
	ObfProGuard ObfuscationType = "proguard"
	ObfR8       ObfuscationType = "r8"
	ObfDexGuard ObfuscationType = "dexguard"
	ObfPacker   ObfuscationType = "packer"
	ObfUnknown  ObfuscationType = "unknown"
)

// Indicator is a single piece of evidence for obfuscation.
type Indicator struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
	Detected    bool    `json:"detected"`
	Details     string  `json:"details,omitempty"`
}

// PackerInfo describes a detected packer.
type PackerInfo struct {
	Name       string  `json:"name"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
}

// Result holds the complete obfuscation analysis.
type Result struct {
	Type            ObfuscationType `json:"type"`
	Confidence      float64         `json:"confidence"` // 0-100
	Label           string          `json:"label"`      // "none", "low", "medium", "high", "very high"
	Indicators      []Indicator     `json:"indicators"`
	HasMapping      bool            `json:"has_mapping"`
	Packer          *PackerInfo     `json:"packer,omitempty"`
	ShortClassPct   float64         `json:"short_class_pct"`  // % of single/double-letter class names
	ShortMethodPct  float64         `json:"short_method_pct"` // % of single-letter methods
	AvgClassNameLen float64         `json:"avg_class_name_len"`
	AvgPkgDepth     float64         `json:"avg_pkg_depth"`
}
