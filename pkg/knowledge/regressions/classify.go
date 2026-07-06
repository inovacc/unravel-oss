/*
Copyright (c) 2026 Security Research

classify.go — apply []Rule against a Snapshot, producing []Regression.

Conditions implemented:

	added_value_contains          — string token added to a CSP-like list
	true_added                    — a flag toggled to true (e.g. dangerous perm)
	value_changed_to:<v>          — a setting flipped to a literal value
	array_length_increased        — list grew (telemetry, endpoints)
	removed                       — a flag/feature dropped (cert pinning)
*/
package regressions

import (
	"fmt"
	"strings"
)

// Classify walks rules and emits regressions for each rule whose match
// predicate fires against snap.
func Classify(snap Snapshot, rules []Rule) []Regression {
	if len(rules) == 0 {
		return nil
	}
	out := make([]Regression, 0)
	for _, r := range rules {
		if reg, ok := evalRule(r, snap); ok {
			out = append(out, reg)
		}
	}
	return out
}

func evalRule(r Rule, snap Snapshot) (Regression, bool) {
	switch r.ID {
	case "csp-unsafe-inline-added":
		return cspContainsRule(r, snap, "unsafe-inline")
	case "csp-unsafe-eval-added":
		return cspContainsRule(r, snap, "unsafe-eval")
	case "dangerous-permission-added":
		return dangerousPermissionRule(r, snap)
	case "sandbox-flag-removed":
		return webPrefFlippedRule(r, snap, "sandbox", "false")
	case "contextisolation-disabled":
		return webPrefFlippedRule(r, snap, "contextIsolation", "false")
	case "nodeintegration-enabled":
		return webPrefFlippedRule(r, snap, "nodeIntegration", "true")
	case "telemetry-sdk-added":
		return arrayGrewRule(r, snap, "telemetry")
	case "external-api-endpoint-added":
		return arrayGrewRule(r, snap, "endpoints")
	case "cert-pinning-removed":
		return certPinningRemovedRule(r, snap)
	}

	// Generic dispatch by condition (covers user-added rubric rules
	// targeting the same dimensions but new IDs). A best-effort match —
	// rules whose key shape we do not understand are silently skipped.
	return evalByCondition(r, snap)
}

func cspContainsRule(r Rule, snap Snapshot, token string) (Regression, bool) {
	if snap.SecurityConfig == nil {
		return Regression{}, false
	}
	for _, add := range snap.SecurityConfig.CSPAdditions {
		if strings.Contains(add, token) {
			return mkRegression(r,
				fmt.Sprintf("CSP gained %q — known XSS vector", token),
				[]string{add},
			), true
		}
	}
	return Regression{}, false
}

func dangerousPermissionRule(r Rule, snap Snapshot) (Regression, bool) {
	if snap.Permissions == nil {
		return Regression{}, false
	}
	var ev []string
	for _, p := range snap.Permissions.AndroidAdded {
		if p.Dangerous {
			ev = append(ev, p.Name)
		}
	}
	if len(ev) == 0 {
		return Regression{}, false
	}
	return mkRegression(r,
		fmt.Sprintf("dangerous Android permission(s) added: %s", strings.Join(ev, ", ")),
		ev,
	), true
}

func webPrefFlippedRule(r Rule, snap Snapshot, name, want string) (Regression, bool) {
	if snap.SecurityConfig == nil || snap.SecurityConfig.WebPrefsChanged == nil {
		return Regression{}, false
	}
	change, ok := snap.SecurityConfig.WebPrefsChanged[name]
	if !ok {
		return Regression{}, false
	}
	if fmt.Sprint(change.New) != want {
		return Regression{}, false
	}
	return mkRegression(r,
		fmt.Sprintf("%s changed to %s (was %v)", name, want, change.Old),
		[]string{fmt.Sprintf("%s: %v -> %v", name, change.Old, change.New)},
	), true
}

func arrayGrewRule(r Rule, snap Snapshot, kind string) (Regression, bool) {
	if snap.Structural == nil {
		return Regression{}, false
	}
	switch kind {
	case "telemetry":
		if snap.Structural.TelemetryCountNew > snap.Structural.TelemetryCountOld {
			added := snap.Structural.TelemetryAdded
			return mkRegression(r,
				fmt.Sprintf("telemetry SDK list grew (%d -> %d)",
					snap.Structural.TelemetryCountOld, snap.Structural.TelemetryCountNew),
				added,
			), true
		}
	case "endpoints":
		if snap.Structural.EndpointsCountNew > snap.Structural.EndpointsCountOld {
			return mkRegression(r,
				fmt.Sprintf("API endpoint list grew (%d -> %d)",
					snap.Structural.EndpointsCountOld, snap.Structural.EndpointsCountNew),
				snap.Structural.EndpointsAdded,
			), true
		}
	}
	return Regression{}, false
}

func certPinningRemovedRule(r Rule, snap Snapshot) (Regression, bool) {
	if snap.SecurityConfig == nil || !snap.SecurityConfig.CertPinningRemoved {
		return Regression{}, false
	}
	return mkRegression(r, "certificate pinning removed", nil), true
}

// evalByCondition is a generic dispatcher used for user rubric rules whose
// IDs do not match a known hardcoded handler. It keys off the rule's
// `condition` and the rule's dimension to decide which dimension struct to
// inspect.
func evalByCondition(r Rule, snap Snapshot) (Regression, bool) {
	cond := r.Match.Condition
	switch {
	case cond == "added_value_contains" && r.Dimension == DimSecurityConfig && snap.SecurityConfig != nil:
		for _, add := range snap.SecurityConfig.CSPAdditions {
			if r.Match.Value != "" && strings.Contains(add, r.Match.Value) {
				return mkRegression(r, fmt.Sprintf("matched %q in security config addition", r.Match.Value), []string{add}), true
			}
		}
	case cond == "array_length_increased" && r.Dimension == DimStructural && snap.Structural != nil:
		// Coarse: any array grew.
		if snap.Structural.TelemetryCountNew > snap.Structural.TelemetryCountOld ||
			snap.Structural.EndpointsCountNew > snap.Structural.EndpointsCountOld {
			return mkRegression(r, "structural list grew", nil), true
		}
	}
	return Regression{}, false
}

func mkRegression(r Rule, msg string, evidence []string) Regression {
	src := r.Source
	if src == "" {
		src = SourceHardcoded
	}
	return Regression{
		RuleID:    r.ID,
		Dimension: r.Dimension,
		Severity:  r.Severity,
		Source:    src,
		Message:   msg,
		Evidence:  evidence,
	}
}
