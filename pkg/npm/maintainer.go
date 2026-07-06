package npm

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaintainerAnalysis holds security-relevant info about package maintainers.
type MaintainerAnalysis struct {
	Package          string              `json:"package"`
	Maintainers      []MaintainerInfo    `json:"maintainers"`
	RiskFactors      []string            `json:"risk_factors,omitempty"`
	OwnershipChanges []OwnershipChange   `json:"ownership_changes,omitempty"`
	PublisherHistory []PublisherSnapshot `json:"publisher_history,omitempty"`
	RiskLevel        string              `json:"risk_level"` // "low", "medium", "high", "critical"
}

// MaintainerInfo holds details about a single maintainer.
type MaintainerInfo struct {
	Name         string `json:"name"`
	Email        string `json:"email,omitempty"`
	PackageCount int    `json:"package_count,omitempty"` // populated if registry data available
}

// OwnershipChange records a change in package authorship between versions.
type OwnershipChange struct {
	Version    string   `json:"version"`
	OldAuthors []string `json:"old_authors,omitempty"`
	NewAuthors []string `json:"new_authors,omitempty"`
	Date       string   `json:"date,omitempty"`
}

// PublisherSnapshot records who published a specific version.
type PublisherSnapshot struct {
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	Date      string `json:"date,omitempty"`
}

// AnalyzeMaintainers checks for maintainer-related risk indicators using
// already-fetched registry data. No new HTTP calls are made.
func AnalyzeMaintainers(reg *RegistryPackage) *MaintainerAnalysis {
	result := &MaintainerAnalysis{
		Package: reg.Name,
	}

	// Extract maintainer list
	for _, m := range reg.Maintainers {
		result.Maintainers = append(result.Maintainers, MaintainerInfo{
			Name:  m.Name,
			Email: m.Email,
		})
	}

	// Risk: no maintainers listed
	if len(result.Maintainers) == 0 {
		result.RiskFactors = append(result.RiskFactors, "no maintainers listed in registry")
	}

	// Risk: single maintainer (bus factor)
	if len(result.Maintainers) == 1 {
		result.RiskFactors = append(result.RiskFactors,
			fmt.Sprintf("single maintainer (%s) — bus factor risk", result.Maintainers[0].Name))
	}

	// Risk: maintainer without email (harder to verify identity)
	for _, m := range result.Maintainers {
		if m.Email == "" {
			result.RiskFactors = append(result.RiskFactors,
				fmt.Sprintf("maintainer %q has no email — harder to verify identity", m.Name))
		}
	}

	// Check if the package was recently created (less than 30 days old)
	if created, ok := reg.Time["created"]; ok {
		if t, parseErr := time.Parse(time.RFC3339, created); parseErr == nil {
			age := time.Since(t)
			if age < 30*24*time.Hour {
				result.RiskFactors = append(result.RiskFactors,
					fmt.Sprintf("package created recently (%s, %d days ago)", created[:10], int(age.Hours()/24)))
			}
		}
	}

	// Check if latest version was published very recently (less than 7 days)
	if modified, ok := reg.Time["modified"]; ok {
		if t, parseErr := time.Parse(time.RFC3339, modified); parseErr == nil {
			age := time.Since(t)
			if age < 7*24*time.Hour {
				result.RiskFactors = append(result.RiskFactors,
					fmt.Sprintf("last modified very recently (%s, %d days ago)", modified[:10], int(age.Hours()/24)))
			}
		}
	}

	// Detect ownership changes across versions
	result.OwnershipChanges = detectOwnershipChanges(reg)
	if len(result.OwnershipChanges) > 0 {
		result.RiskFactors = append(result.RiskFactors,
			fmt.Sprintf("ownership changed %d time(s) across versions", len(result.OwnershipChanges)))
	}

	// Detect recently changed maintainers (changed in the last 90 days)
	recentChanges := detectRecentMaintainerChanges(reg, 90*24*time.Hour)
	if len(recentChanges) > 0 {
		for _, rc := range recentChanges {
			result.RiskFactors = append(result.RiskFactors,
				fmt.Sprintf("maintainer change detected in version %s (%s) — potential account takeover",
					rc.Version, rc.Date))
		}
	}

	// Detect publish author vs maintainer mismatch
	mismatches := detectPublisherMaintainerMismatch(reg)
	result.PublisherHistory = buildPublisherHistory(reg)
	for _, mm := range mismatches {
		result.RiskFactors = append(result.RiskFactors, mm)
	}

	// Detect maintainers that first appear in per-version data but not top-level
	unknownPublishers := detectUnknownPublishers(reg)
	for _, up := range unknownPublishers {
		result.RiskFactors = append(result.RiskFactors, up)
	}

	// Calculate overall risk level
	result.RiskLevel = classifyMaintainerRisk(result.RiskFactors)

	return result
}

// detectOwnershipChanges compares per-version maintainer lists chronologically
// to find ownership transfers.
func detectOwnershipChanges(reg *RegistryPackage) []OwnershipChange {
	sorted := sortedVersions(reg)
	if len(sorted) < 2 {
		return nil
	}

	var changes []OwnershipChange
	prevNames := versionMaintainerNames(reg, sorted[0].version)

	for i := 1; i < len(sorted); i++ {
		curNames := versionMaintainerNames(reg, sorted[i].version)
		added, removed := diffStringSlices(prevNames, curNames)

		if len(added) > 0 || len(removed) > 0 {
			change := OwnershipChange{
				Version: sorted[i].version,
				Date:    sorted[i].time.Format("2006-01-02"),
			}
			if len(removed) > 0 {
				change.OldAuthors = removed
			}
			if len(added) > 0 {
				change.NewAuthors = added
			}
			changes = append(changes, change)
		}
		prevNames = curNames
	}

	return changes
}

// detectRecentMaintainerChanges finds ownership changes that happened within
// the given duration. Recent changes are a stronger takeover indicator.
func detectRecentMaintainerChanges(reg *RegistryPackage, within time.Duration) []OwnershipChange {
	all := detectOwnershipChanges(reg)
	cutoff := time.Now().Add(-within)

	var recent []OwnershipChange
	for _, c := range all {
		if t, err := time.Parse("2006-01-02", c.Date); err == nil {
			if t.After(cutoff) {
				recent = append(recent, c)
			}
		}
	}
	return recent
}

// detectPublisherMaintainerMismatch checks if the _npmUser who published a
// version is not in the current top-level maintainer list. This can indicate
// a revoked account that previously had publish access — a takeover artifact.
func detectPublisherMaintainerMismatch(reg *RegistryPackage) []string {
	currentMaintainers := make(map[string]bool, len(reg.Maintainers))
	for _, m := range reg.Maintainers {
		currentMaintainers[strings.ToLower(m.Name)] = true
	}

	if len(currentMaintainers) == 0 {
		return nil
	}

	var mismatches []string
	seen := make(map[string]bool)

	for ver, pv := range reg.Versions {
		if pv.NpmUser == nil {
			continue
		}
		publisher := strings.ToLower(pv.NpmUser.Name)
		if publisher == "" {
			continue
		}
		if !currentMaintainers[publisher] && !seen[publisher] {
			seen[publisher] = true
			date := ""
			if ts, ok := reg.Time[ver]; ok {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					date = t.Format("2006-01-02")
				}
			}
			mismatches = append(mismatches, fmt.Sprintf(
				"user %q published version %s (%s) but is no longer a maintainer — possible revoked access or takeover",
				pv.NpmUser.Name, ver, date))
		}
	}

	return mismatches
}

// detectUnknownPublishers finds publishers (_npmUser) that appear in version
// data but have never been a per-version maintainer in earlier versions.
// This detects newly added accounts that immediately start publishing.
func detectUnknownPublishers(reg *RegistryPackage) []string {
	sorted := sortedVersions(reg)
	if len(sorted) < 2 {
		return nil
	}

	// Collect all known maintainers from the first half of versions
	midpoint := len(sorted) / 2
	knownPublishers := make(map[string]bool)
	for i := range midpoint {
		ver := sorted[i].version
		pv, ok := reg.Versions[ver]
		if !ok {
			continue
		}
		if pv.NpmUser != nil && pv.NpmUser.Name != "" {
			knownPublishers[strings.ToLower(pv.NpmUser.Name)] = true
		}
		for _, m := range pv.Maintainers {
			knownPublishers[strings.ToLower(m.Name)] = true
		}
	}

	// Check if late-version publishers are unknowns
	var warnings []string
	seen := make(map[string]bool)
	for i := midpoint; i < len(sorted); i++ {
		ver := sorted[i].version
		pv, ok := reg.Versions[ver]
		if !ok {
			continue
		}
		if pv.NpmUser == nil || pv.NpmUser.Name == "" {
			continue
		}
		publisher := strings.ToLower(pv.NpmUser.Name)
		if !knownPublishers[publisher] && !seen[publisher] {
			seen[publisher] = true
			date := ""
			if ts, okT := reg.Time[ver]; okT {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					date = t.Format("2006-01-02")
				}
			}
			warnings = append(warnings, fmt.Sprintf(
				"new publisher %q first appeared in version %s (%s) — not seen in earlier versions",
				pv.NpmUser.Name, ver, date))
		}
	}

	return warnings
}

// buildPublisherHistory returns who published each version, sorted chronologically.
func buildPublisherHistory(reg *RegistryPackage) []PublisherSnapshot {
	sorted := sortedVersions(reg)
	var history []PublisherSnapshot

	for _, vt := range sorted {
		pv, ok := reg.Versions[vt.version]
		if !ok {
			continue
		}
		publisher := ""
		if pv.NpmUser != nil {
			publisher = pv.NpmUser.Name
		}
		if publisher == "" {
			continue
		}
		history = append(history, PublisherSnapshot{
			Version:   vt.version,
			Publisher: publisher,
			Date:      vt.time.Format("2006-01-02"),
		})
	}

	return history
}

// versionMaintainerNames returns maintainer names for a specific version.
// It prefers per-version maintainer data when available, falling back to
// the top-level maintainer list.
func versionMaintainerNames(reg *RegistryPackage, version string) []string {
	if pv, ok := reg.Versions[version]; ok && len(pv.Maintainers) > 0 {
		names := make([]string, 0, len(pv.Maintainers))
		for _, m := range pv.Maintainers {
			names = append(names, m.Name)
		}
		return names
	}

	// Fall back to top-level
	names := make([]string, 0, len(reg.Maintainers))
	for _, m := range reg.Maintainers {
		names = append(names, m.Name)
	}
	return names
}

type versionTime struct {
	version string
	time    time.Time
}

// sortedVersions returns all versions sorted by publish time ascending.
func sortedVersions(reg *RegistryPackage) []versionTime {
	var vts []versionTime
	for ver := range reg.Versions {
		if ts, ok := reg.Time[ver]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				vts = append(vts, versionTime{version: ver, time: t})
			}
		}
	}
	sort.Slice(vts, func(i, j int) bool {
		return vts[i].time.Before(vts[j].time)
	})
	return vts
}

// classifyMaintainerRisk maps the number and severity of risk factors to a
// risk level string.
func classifyMaintainerRisk(factors []string) string {
	if len(factors) == 0 {
		return "low"
	}

	score := 0
	for _, f := range factors {
		switch {
		case strings.Contains(f, "account takeover"),
			strings.Contains(f, "no longer a maintainer"),
			strings.Contains(f, "new publisher"):
			score += 30
		case strings.Contains(f, "ownership changed"),
			strings.Contains(f, "single maintainer"),
			strings.Contains(f, "no maintainers"):
			score += 15
		case strings.Contains(f, "recently"),
			strings.Contains(f, "no email"):
			score += 5
		default:
			score += 5
		}
	}

	switch {
	case score >= 50:
		return "critical"
	case score >= 30:
		return "high"
	case score >= 15:
		return "medium"
	default:
		return "low"
	}
}

// diffStringSlices returns elements added to b and removed from a.
func diffStringSlices(a, b []string) (added, removed []string) {
	setA := make(map[string]bool, len(a))
	for _, s := range a {
		setA[s] = true
	}

	setB := make(map[string]bool, len(b))
	for _, s := range b {
		setB[s] = true
	}

	for s := range setB {
		if !setA[s] {
			added = append(added, s)
		}
	}

	for s := range setA {
		if !setB[s] {
			removed = append(removed, s)
		}
	}

	return added, removed
}
