/*
Copyright (c) 2026 Security Research

Package stealth registers positive rules that classify modules into the
stealth taxonomy bucket. Targets the cluely/openCluely/perssua/pluely family
that hides itself from screen capture via setContentProtection and analogs.
*/
package stealth

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathStealth = regexp.MustCompile(`(?i)(^|/)(stealth|hide|cloak|overlay)/`)
	nameStealth = regexp.MustCompile(`(?i)(Stealth|Hide|Overlay|Invisible|Cloak)`)
)

func init() {
	component.Register(component.Rule{
		Name: "stealth/path-name-symbol", Component: "stealth", Confidence: 0.95, Priority: 3,
		PathRegex: pathStealth, NameRegex: nameStealth,
		SymbolKeywords: []string{"setContentProtection", "allow-set-content-protected", "ToolWindow", "WS_EX_NOACTIVATE", "hideFromCapture"},
	})
	component.Register(component.Rule{
		Name: "stealth/name-symbol", Component: "stealth", Confidence: 0.80, Priority: 3,
		NameRegex:      nameStealth,
		SymbolKeywords: []string{"setContentProtection", "ToolWindow", "hideFromCapture"},
	})
	component.Register(component.Rule{
		Name: "stealth/symbol-strict", Component: "stealth", Confidence: 0.65, Priority: 3,
		SymbolKeywords: []string{"setContentProtection", "allow-set-content-protected", "WS_EX_NOACTIVATE"},
	})
}
