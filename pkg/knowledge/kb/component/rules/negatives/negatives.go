/*
Copyright (c) 2026 Security Research

Package negatives registers cross-cutting suppression rules per
D-31-NEGATIVE-RULES. Negative rules fire BEFORE positive rules; if any
matches, all positive rules for the same Component are suppressed for that
module. Mitigates PITFALLS-MOD-3 (rule-based classifier false positives).
*/
package negatives

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	nameTest     = regexp.MustCompile(`(?i)(_test|Test)`)
	pathDocs     = regexp.MustCompile(`(?i)(^|/)docs?(/|$)`)
	nameGraphics = regexp.MustCompile(`(?i)^(Animation|Graphics|Render|Sprite|Texture)`)
	pathCmd      = regexp.MustCompile(`(?i)(^|/)cmd(/|$)`)
)

func init() {
	component.Register(component.Rule{
		Name: "neg/test-token-not-auth", Suppress: true, Component: "auth",
		NameRegex:      nameTest,
		SymbolKeywords: []string{"token"},
	})
	component.Register(component.Rule{
		Name: "neg/docs-oauth-not-auth", Suppress: true, Component: "auth",
		PathRegex:      pathDocs,
		SymbolKeywords: []string{"oauth"},
	})
	component.Register(component.Rule{
		Name: "neg/graphics-crypto-not-crypto", Suppress: true, Component: "crypto",
		NameRegex:      nameGraphics,
		SymbolKeywords: []string{"crypto"},
	})
	component.Register(component.Rule{
		Name: "neg/cmd-login-not-auth", Suppress: true, Component: "auth",
		PathRegex:      pathCmd,
		SymbolKeywords: []string{"Login"},
	})
}
