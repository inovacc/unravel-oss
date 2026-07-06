/*
Copyright (c) 2026 Security Research
*/

// Package runtime is a convenience blank-import that wires the UWP
// orchestrator implementation into the public pkg/uwp API:
//
//	import _ "github.com/inovacc/unravel-oss/pkg/uwp/runtime"
package runtime

import (
	_ "github.com/inovacc/unravel-oss/pkg/uwp/internal/orchestrator" // wire AnalyzeImpl
)
