/*
Copyright (c) 2026 Security Research
*/

// Package runtime is a convenience blank-import that wires the winui
// analysis orchestrator into the public pkg/winui API. Callers that
// want the full Analyze pipeline (XAML walk + XBF decode + PRI parse +
// PE-embedded scan) should add an underscore import:
//
//	import _ "github.com/inovacc/unravel-oss/pkg/winui/runtime"
//
// Without this import, winui.Analyze returns an "orchestrator not
// initialised" error; the AnalyzeQuick fallback continues to work.
package runtime

import (
	_ "github.com/inovacc/unravel-oss/pkg/winui/internal/orchestrator" // wire AnalyzeImpl
)
