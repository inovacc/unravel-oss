/*
Copyright (c) 2026 Security Research
*/
// Package registry blank-imports every per-framework inject scanner so each
// scanner's init() registers itself with pkg/inject.RegisterScanner.
//
// This mirrors pkg/knowledge/registry/dep_extractors.go: callers that want
// the full registry populated import this package for side effects.
package registry

import (
	_ "github.com/inovacc/unravel-oss/pkg/inject/electron"
	_ "github.com/inovacc/unravel-oss/pkg/inject/linux"
	_ "github.com/inovacc/unravel-oss/pkg/inject/macos"
	_ "github.com/inovacc/unravel-oss/pkg/inject/tauri"
	_ "github.com/inovacc/unravel-oss/pkg/inject/webview2"
)
