/*
Copyright (c) 2026 Security Research
*/
package autogen

// Options controls Generate behavior.
type Options struct {
	// Platform, if non-empty, restricts generation to seams on this platform
	// ("windows" | "macos" | "linux"). Empty means generate for all.
	Platform string
}

// GeneratedScript is one (script + criteria) pair emitted by Generate.
type GeneratedScript struct {
	SeamID       string `json:"seam_id"`
	Platform     string `json:"platform"`
	ScriptPath   string `json:"script_path"`
	CriteriaPath string `json:"criteria_path"`
}

// GenerateResult is the aggregate output of a Generate run.
type GenerateResult struct {
	OutDir  string            `json:"out_dir"`
	Scripts []GeneratedScript `json:"scripts"`
	Skipped int               `json:"skipped"`
}
