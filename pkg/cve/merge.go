/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"strings"
	"time"
)

// Merge applies the documented OSV-authoritative merge strategy (D-02).
//
// Rules:
//  1. OSV is authoritative — its vuln list is the spine.
//  2. For each OSV vuln, if NVD has the CVE-id, fold in CWE.
//  3. If GHSA has any alias matching the vuln's CVE-id, fold in withdrawn +
//     additional references.
//  4. grype entries that have no OSV counterpart are appended (offline-only).
//  5. Every contributing source is recorded in Sources[].
func Merge(osv []osvVuln, nvd map[string]*nvdRecord, ghsa map[string]*ghsaRecord, grype []grypeVuln) []Vulnerability {
	now := time.Now().UTC()
	out := make([]Vulnerability, 0, len(osv))
	osvSeen := make(map[string]struct{}, len(osv))

	for _, ov := range osv {
		v := Vulnerability{
			ID:               canonicalID(ov.ID, ov.Aliases),
			Aliases:          dedupe(append([]string{ov.ID}, ov.Aliases...)),
			Severity:         Severity{CVSSv3: ov.CVSSScore, Vector: ov.CVSSVector, Level: deriveLevel(ov)},
			CWE:              append([]string(nil), ov.CWEIDs...),
			AffectedVersions: ov.AffectedVersions,
			References:       append([]string(nil), ov.References...),
			Withdrawn:        ov.Withdrawn,
			Sources:          []SourceRef{{Name: "osv", FetchedAt: now}},
		}
		osvSeen[v.ID] = struct{}{}
		for _, alias := range v.Aliases {
			osvSeen[alias] = struct{}{}
		}

		// (2) NVD CWE fold.
		if nvd != nil {
			if rec := lookupByAliases(nvd, v.Aliases); rec != nil {
				if len(rec.CWE) > 0 {
					v.CWE = dedupe(append(v.CWE, rec.CWE...))
				}
				if v.Severity.Vector == "" && rec.CVSSv3Vector != "" {
					v.Severity.Vector = rec.CVSSv3Vector
					v.Severity.CVSSv3 = rec.CVSSv3Score
					if v.Severity.Level == "" || v.Severity.Level == "none" {
						v.Severity.Level = scoreLevel(rec.CVSSv3Score)
					}
				}
				if len(rec.References) > 0 {
					v.References = dedupe(append(v.References, rec.References...))
				}
				v.Sources = append(v.Sources, SourceRef{Name: "nvd", FetchedAt: now})
			}
		}

		// (3) GHSA fold.
		if ghsa != nil {
			if rec := lookupGHSA(ghsa, v.Aliases); rec != nil {
				if v.Withdrawn == nil && rec.WithdrawnAt != nil {
					v.Withdrawn = rec.WithdrawnAt
				}
				if len(rec.References) > 0 {
					v.References = dedupe(append(v.References, rec.References...))
				}
				if len(rec.Aliases) > 0 {
					v.Aliases = dedupe(append(v.Aliases, rec.Aliases...))
				}
				v.Sources = append(v.Sources, SourceRef{Name: "ghsa", FetchedAt: now})
			}
		}

		out = append(out, v)
	}

	// (4) Append grype-only findings.
	for _, gv := range grype {
		if _, found := osvSeen[gv.ID]; found {
			// Already covered by OSV — fold grype as another source on it.
			for i := range out {
				for _, alias := range out[i].Aliases {
					if alias == gv.ID {
						out[i].Sources = append(out[i].Sources, SourceRef{Name: "grype", FetchedAt: now, URL: gv.URL})
						break
					}
				}
			}
			continue
		}
		v := Vulnerability{
			ID:         gv.ID,
			Aliases:    []string{gv.ID},
			Severity:   Severity{Level: strings.ToLower(gv.Severity)},
			References: nil,
			Sources:    []SourceRef{{Name: "grype", FetchedAt: now, URL: gv.URL}},
		}
		out = append(out, v)
	}

	return out
}

// canonicalID prefers a CVE-XXXX-NNNN id over a GHSA-* id.
func canonicalID(primary string, aliases []string) string {
	if strings.HasPrefix(primary, "CVE-") {
		return primary
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return primary
}

func deriveLevel(ov osvVuln) string {
	if ov.Severity != "" {
		return ov.Severity
	}
	if ov.CVSSScore > 0 {
		return scoreLevel(ov.CVSSScore)
	}
	return parseCVSSv3Level(ov.CVSSVector)
}

func scoreLevel(s float64) string {
	switch {
	case s >= 9.0:
		return "critical"
	case s >= 7.0:
		return "high"
	case s >= 4.0:
		return "medium"
	case s > 0:
		return "low"
	default:
		return "none"
	}
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func lookupByAliases(m map[string]*nvdRecord, aliases []string) *nvdRecord {
	for _, a := range aliases {
		if rec, ok := m[a]; ok && rec != nil {
			return rec
		}
	}
	return nil
}

func lookupGHSA(m map[string]*ghsaRecord, aliases []string) *ghsaRecord {
	for _, a := range aliases {
		if rec, ok := m[a]; ok && rec != nil {
			return rec
		}
	}
	return nil
}
