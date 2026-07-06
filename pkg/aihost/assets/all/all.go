/*
Copyright (c) 2026 Security Research
*/

// Package all is a barrel-import that triggers every functional asset
// category's init() so they register themselves into aihost.All().
package all

import (
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/cleanroom"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/cli"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/convert"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/dissect"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/enrich"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/knowledge"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/ops"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/supervisor"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/transpile"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/xref"
)
