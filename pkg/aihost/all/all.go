/*
Copyright (c) 2026 Security Research
*/

// Package all is a barrel-import that triggers every host package's
// init() so they register themselves into aihost.All(). Import this
// package (blank-import) anywhere you need the full host registry.
package all

import (
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/all"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/claude"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/codex"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/gemini"
)
