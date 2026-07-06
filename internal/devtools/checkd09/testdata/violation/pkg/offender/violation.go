// Phase 45 / LLMC-03 — D-09 negative-fixture: a file outside any
// allowlisted directory that imports the forbidden Anthropic SDK at the
// top level. Lives under testdata/ so the Go toolchain ignores it for
// build, but checkd09's scanner is tested AGAINST this tree explicitly.
package offender

import (
	_ "github.com/anthropics/anthropic-sdk-go"
)
