//go:build goresym

package goresym

// LookupGoresymForTest exposes the unexported lookupGoresym resolver to the
// external (_test) test package so its skip-probes resolve the GoReSym
// executable through the exact same candidate-name logic as the backend —
// keeping the tests honest about presence/absence on every OS.
func LookupGoresymForTest() (string, error) { return lookupGoresym() }

// BuildGoresymArgsForTest exposes the unexported argv builder so the
// argument-injection guards (GoVersion shape check, "--" end-of-options marker,
// absolutised path) can be unit-tested without spawning the external tool.
func BuildGoresymArgsForTest(opts Options, path string) []string {
	return buildGoresymArgs(opts, path)
}
