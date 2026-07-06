/*
Copyright (c) 2026 Security Research
*/
package scorecard

// CanonicalDims is the ordered list of 12 dimension IDs sourced from
// .scripts/whatsapp-W-00-baseline.ps1. Rubric.Score emits dims in this order
// regardless of init() link order so output is deterministic.
var CanonicalDims = []string{
	"identity", "filesystem", "binary_surface", "source_layer",
	"ipc", "api", "wire", "storage",
	"auth", "crypto", "state_machines", "behavior",
}
