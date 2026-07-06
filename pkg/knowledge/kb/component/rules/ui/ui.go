/*
Copyright (c) 2026 Security Research

Package ui registers positive rules that classify modules into the ui
taxonomy bucket.
*/
package ui

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathUI = regexp.MustCompile(`(?i)(^|/)(ui|view|component|page|screen|widget|render|xaml)/`)
	nameUI = regexp.MustCompile(`(?i)(View|Component|Page|Screen|Widget|Render|Layout)`)
)

func init() {
	component.Register(component.Rule{
		Name: "ui/path-name-symbol", Component: "ui", Confidence: 0.95, Priority: 1,
		PathRegex: pathUI, NameRegex: nameUI,
		SymbolKeywords: []string{"React", "Vue", "Svelte", "Solid", "Angular", "render", "useState", "h.createElement", "XAML"},
	})
	component.Register(component.Rule{
		Name: "ui/name-symbol", Component: "ui", Confidence: 0.80, Priority: 1,
		NameRegex:      nameUI,
		SymbolKeywords: []string{"React", "Vue", "Svelte", "useState", "h.createElement"},
	})
	component.Register(component.Rule{
		Name: "ui/path-symbol", Component: "ui", Confidence: 0.80, Priority: 1,
		PathRegex:      pathUI,
		SymbolKeywords: []string{"React", "Vue", "Svelte", "Angular", "XAML"},
	})
}
