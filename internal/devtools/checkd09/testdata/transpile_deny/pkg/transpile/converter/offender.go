// TRANSPILE-PHASE2-GAPS — D-09 explicit-deny fixture: a file under the named
// pkg/transpile deny subtree that imports the forbidden Anthropic SDK at the
// top level. Lives under testdata/ so the Go toolchain ignores it for build,
// but checkd09's scanner is tested AGAINST this tree to assert the explicit
// pkg/transpile deny path fires with its distinct, self-explaining message.
package converter

import (
	_ "github.com/anthropics/anthropic-sdk-go"
)
