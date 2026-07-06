/*
Copyright (c) 2026 Security Research

Package telemetry registers positive rules that classify modules into the
telemetry taxonomy bucket.
*/
package telemetry

import (
	"regexp"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

var (
	pathTel = regexp.MustCompile(`(?i)(^|/)(telemetry|analytics|metrics|tracking|reporting)/`)
	nameTel = regexp.MustCompile(`(?i)(Telemetry|Analytics|Metric|Tracker|Beacon|Heartbeat)`)
)

func init() {
	component.Register(component.Rule{
		Name: "telemetry/path-name-symbol", Component: "telemetry", Confidence: 0.95, Priority: 7,
		PathRegex: pathTel, NameRegex: nameTel,
		SymbolKeywords: []string{"telemetry", "analytics", "sentry", "segment", "mixpanel", "amplitude", "datadog", "posthog", "beacon"},
	})
	component.Register(component.Rule{
		Name: "telemetry/name-symbol", Component: "telemetry", Confidence: 0.80, Priority: 7,
		NameRegex:      nameTel,
		SymbolKeywords: []string{"telemetry", "analytics", "sentry", "beacon"},
	})
	component.Register(component.Rule{
		Name: "telemetry/path-symbol", Component: "telemetry", Confidence: 0.80, Priority: 7,
		PathRegex:      pathTel,
		SymbolKeywords: []string{"telemetry", "analytics", "beacon"},
	})
}
