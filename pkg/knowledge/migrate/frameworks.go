/*
Copyright (c) 2026 Security Research
*/
package migrate

// validFrameworks is the canonical list of migration target frameworks
// shipped in Phase 7 (CONTEXT D-07 + RESEARCH OQ4 recommendation).
//
// Deferred frameworks (e.g. ruby-on-rails, qt, tkinter) are intentionally
// rejected by IsValid so the user gets a clear error pointing at the
// supported set rather than a silent no-op.
var validFrameworks = []string{
	"react",
	"vue",
	"angular",
	"svelte",
	"wpf",
	"winui3",
	"flutter",
	"react-native",
}

// ValidFrameworks returns a copy of the canonical target framework list.
func ValidFrameworks() []string {
	out := make([]string, len(validFrameworks))
	copy(out, validFrameworks)
	return out
}

// IsValid reports whether fw is a recognised migration target framework.
// Comparison is case-sensitive — caller is expected to lowercase user input.
func IsValid(fw string) bool {
	for _, v := range validFrameworks {
		if v == fw {
			return true
		}
	}
	return false
}
