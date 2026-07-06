/*
Copyright (c) 2026 Security Research
*/
package registry

// Wire per-ecosystem DepExtractors into the knowledge pipeline at init time.
//
// The ecosystem packages (pkg/npm, pkg/dotnet, etc.) cannot import
// pkg/knowledge directly — pkg/knowledge transitively imports pkg/dissect
// which imports both ecosystem packages, creating a cycle. The fix:
// extractors live in their ecosystem packages with only a pkg/cve dep, and
// this wiring file (which already lives under pkg/knowledge/) registers
// them.
//
// 14-04 extends this with godeps + pydeps.
import (
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/godeps"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/npm"
	"github.com/inovacc/unravel-oss/pkg/pydeps"
)

func init() {
	knowledge.RegisterDepExtractor(npm.NPMExtractor{})
	knowledge.RegisterDepExtractor(dotnet.DotNetExtractor{})
	knowledge.RegisterDepExtractor(godeps.GoExtractor{})
	knowledge.RegisterDepExtractor(pydeps.PyExtractor{})
}
