/*
Copyright (c) 2026 Security Research

Package security registers positive rules that classify modules into the
security taxonomy bucket.
*/
package security

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathSec = regexp.MustCompile(`(?i)(^|/)(security|sandbox|sec|policy)/`)
	nameSec = regexp.MustCompile(`(?i)(Sandbox|Permission|CSP|Sanitize|Policy|Safe|Verify|Validator)`)
)

func init() {
	component.Register(component.Rule{
		Name: "security/path-name-symbol", Component: "security", Confidence: 0.95, Priority: 8,
		PathRegex: pathSec, NameRegex: nameSec,
		SymbolKeywords: []string{"csp", "sandbox", "sanitize", "allowlist", "blocklist", "permission", "capability"},
	})
	component.Register(component.Rule{
		Name: "security/name-symbol", Component: "security", Confidence: 0.80, Priority: 8,
		NameRegex:      nameSec,
		SymbolKeywords: []string{"sandbox", "sanitize", "permission", "policy"},
	})
	component.Register(component.Rule{
		Name: "security/path-symbol", Component: "security", Confidence: 0.80, Priority: 8,
		PathRegex:      pathSec,
		SymbolKeywords: []string{"csp", "sandbox", "permission"},
	})
}
