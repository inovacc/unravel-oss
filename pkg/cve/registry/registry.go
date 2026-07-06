/*
Copyright (c) 2026 Security Research
*/

// Package registry imports the per-ecosystem packages purely for their
// init() side-effects: each package registers a cve.LatestProber
// implementation with pkg/cve. Importing this package once at the binary
// entry point is enough to wire up Go/npm/PyPI/NuGet latest-version probes
// for cve.Client.Query.
package registry

import (
	_ "github.com/inovacc/unravel-oss/pkg/dotnet"
	_ "github.com/inovacc/unravel-oss/pkg/godeps"
	_ "github.com/inovacc/unravel-oss/pkg/npm"
	_ "github.com/inovacc/unravel-oss/pkg/pydeps"
)
