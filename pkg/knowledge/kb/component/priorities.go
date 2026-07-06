/*
Copyright (c) 2026 Security Research
*/

package component

// Priorities resolves equal-confidence ties in Apply. Higher wins.
// Locked by D-31-MULTI-MATCH; do NOT reorder without phase decision.
var Priorities = map[string]int{
	"auth":          10,
	"crypto":        9,
	"security":      8,
	"telemetry":     7,
	"storage":       6,
	"communication": 5,
	"ipc":           4,
	"stealth":       3,
	"protocol":      2,
	"ui":            1,
	"other":         0,
}
