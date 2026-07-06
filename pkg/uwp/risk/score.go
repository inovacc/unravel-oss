/*
Copyright (c) 2026 Security Research
*/
package risk

import (
	"fmt"
	"sort"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

// Score evaluates a capability set against the rubric and returns a categorical
// + numeric score per D-10 / D-12 / D-13.
//
//   - rescap auto-critical (D-12): any capability whose namespace is listed in
//     rubric.AutoCriticalNamespaces (default: ["rescap"]) forces Level=critical.
//   - Unknown capability minimum-bucket (D-12): unrecognised capability names
//     contribute rubric.UnknownCapWeight and force a minimum bucket of
//     rubric.UnknownCapBucket (default "high"). Evidence carries
//     "unknown_capability:<name>".
//   - Signature multiplier (D-13): post-multiplier value = clamp(base * mult, 0, 100).
//     Trusted-microsoft signatures cap the resulting bucket at
//     rubric.TrustedMicrosoftMaxLevel (default "high") UNLESS auto-critical
//     fired (rescap is never silenced by the multiplier cap).
//
// The Evidence slice is stable + greppable; downstream tooling depends on the
// exact prefixes "rescap auto-critical:", "unknown_capability:",
// "<status> multiplier", and "<name> +<weight>".
func Score(caps []uwp.CapabilityRef, sig uwp.SignatureInfo, rubric *uwp.Rubric) uwp.Score {
	if rubric == nil {
		rubric = DefaultRubric()
	}

	autoCriticalNS := stringSet(rubric.AutoCriticalNamespaces)
	autoCriticalNames := stringSet(rubric.AutoCriticalNames)

	var (
		evidence     []string
		base         int
		autoCritical bool
		forceMinHigh bool
		contributors []weightContrib
	)

	if len(caps) == 0 {
		evidence = append(evidence, "no capabilities")
	}

	for _, c := range caps {
		// Namespace normalization (BUG-05 / D-05): fold vendor URI
		// namespaces (e.g. "unknown:http://schemas.microsoft.com/appx/manifest/uap/windows10/11")
		// onto canonical short codes ("uap6") before any rubric lookup.
		c.Namespace = normalizeNamespace(c.Namespace)

		// Auto-critical: by namespace OR by explicit name list.
		if autoCriticalNS[c.Namespace] || autoCriticalNames[c.Name] {
			autoCritical = true
			evidence = append(evidence, "rescap auto-critical: "+c.Name)
			// Still add weight so the trace is complete; bucket is forced regardless.
			if w, ok := rubric.Weights[c.Name]; ok {
				base += w
				contributors = append(contributors, weightContrib{name: c.Name, weight: w})
			}
			continue
		}

		if w, ok := rubric.Weights[c.Name]; ok {
			base += w
			contributors = append(contributors, weightContrib{name: c.Name, weight: w})
			continue
		}

		// Unknown capability: D-12 — flag minimum bucket "high" (configurable),
		// add unknown weight, emit verbatim evidence so reviewers can grep.
		base += rubric.UnknownCapWeight
		contributors = append(contributors, weightContrib{name: c.Name, weight: rubric.UnknownCapWeight})
		evidence = append(evidence, "unknown_capability:"+c.Name)
		forceMinHigh = true
	}

	base = clamp(base, 0, 100)

	mult, multKnown := rubric.SignatureMultipliers[sig.Status]
	if !multKnown {
		mult = 1.0
		evidence = append(evidence, "unknown signature status: "+sig.Status)
	}
	evidence = append(evidence, fmt.Sprintf("%s multiplier %.1f", sig.Status, mult))

	value := clamp(int(float64(base)*mult), 0, 100)
	level := bucketize(value, rubric.Buckets)

	if autoCritical {
		level = "critical"
	} else {
		if forceMinHigh {
			level = atLeast(level, rubric.UnknownCapBucket, rubric.Buckets)
		}
		if sig.Status == "trusted-microsoft" && rubric.TrustedMicrosoftMaxLevel != "" {
			level = capLevel(level, rubric.TrustedMicrosoftMaxLevel, rubric.Buckets)
		}

		// Per-capability level overrides (BUG-05 / D-05). Promote level
		// upward — never downgrade — when any capability in the input
		// pins a stricter floor. Applied AFTER trusted-microsoft cap so
		// silent-screen-capture caps stay critical even on Microsoft
		// Store packages.
		for _, c := range caps {
			if pin, ok := rubric.LevelOverrides[c.Name]; ok {
				promoted := atLeast(level, pin, rubric.Buckets)
				if promoted != level {
					evidence = append(evidence, "level_override:"+c.Name+"->"+pin)
					level = promoted
				}
			}
		}
	}

	evidence = append(evidence, top3WeightTrace(contributors)...)

	return uwp.Score{
		Value:      value,
		Level:      level,
		Base:       base,
		Multiplier: mult,
		Evidence:   evidence,
	}
}

// weightContrib is one capability's contribution to the weighted sum.
type weightContrib struct {
	name   string
	weight int
}

// top3WeightTrace formats the three highest-weight contributors as
// "<name> +<weight>" evidence entries.
func top3WeightTrace(c []weightContrib) []string {
	if len(c) == 0 {
		return nil
	}
	sort.SliceStable(c, func(i, j int) bool { return c[i].weight > c[j].weight })
	out := make([]string, 0, 3)
	for i := 0; i < len(c) && i < 3; i++ {
		out = append(out, fmt.Sprintf("%s +%d", c[i].name, c[i].weight))
	}
	return out
}

// bucketize returns the smallest bucket whose Max >= value. Buckets MUST be
// stored in ascending Max order in the rubric.
func bucketize(value int, buckets []uwp.Bucket) string {
	for _, b := range buckets {
		if value <= b.Max {
			return b.Name
		}
	}
	if len(buckets) > 0 {
		return buckets[len(buckets)-1].Name
	}
	return "low"
}

// rankOf returns the position of name in the bucket ladder; -1 when not present.
func rankOf(name string, buckets []uwp.Bucket) int {
	for i, b := range buckets {
		if b.Name == name {
			return i
		}
	}
	return -1
}

// atLeast returns whichever of (current, floor) ranks higher in the ladder.
// Used for unknown-capability minimum-bucket promotion (D-12).
func atLeast(current, floor string, buckets []uwp.Bucket) string {
	cr := rankOf(current, buckets)
	fr := rankOf(floor, buckets)
	if fr < 0 {
		return current
	}
	if cr < fr {
		return floor
	}
	return current
}

// capLevel returns whichever of (current, ceiling) ranks LOWER in the ladder.
// Used for trusted-microsoft bucket cap (D-13).
func capLevel(current, ceiling string, buckets []uwp.Bucket) string {
	cr := rankOf(current, buckets)
	cap := rankOf(ceiling, buckets)
	if cap < 0 {
		return current
	}
	if cr > cap {
		return ceiling
	}
	return current
}

func stringSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
