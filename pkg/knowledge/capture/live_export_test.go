/*
Copyright (c) 2026 Security Research
*/

package capture

// Exports for testing — keep internal helpers verifiable without
// exporting them in the public API.
var (
	PickFreePort   = pickFreePort
	BuildLaunchCmd = buildLaunchCmd
)
