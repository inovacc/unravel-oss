/*
Copyright © 2026 Security Research
*/
package gather

import (
	"os"
	"sort"

	"github.com/inovacc/unravel-oss/pkg/extension"
	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// ExtensionEntry represents a discovered extension with risk assessment.
type ExtensionEntry struct {
	Path        string `json:"path"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Browser     string `json:"browser"`
	Profile     string `json:"profile"`
	Version     string `json:"version"`
	ManifestVer int    `json:"manifest_ver"`
	RiskLevel   string `json:"risk_level"`
	RiskScore   int    `json:"risk_score"`
	Permissions int    `json:"permissions"`
	Duplicate   bool   `json:"duplicate,omitempty"`
	DupeOf      string `json:"dupe_of,omitempty"`
}

// Dependencies that can be overridden for testing.
var (
	discoverBrowsers   = extension.DiscoverBrowsers
	parseExtension     = extension.ParseExtension
	analyzePermissions = extension.AnalyzePermissions
	calculateRiskScore = extension.CalculateRiskScore
	readDir            = os.ReadDir
)

// Gather discovers all installed browser extensions across all browsers and
// profiles, returning them sorted by risk score (highest first).
func Gather(m *manifest.Manifest, browser string, verbose bool) []ExtensionEntry {
	profiles := discoverBrowsers(browser)

	var entries []ExtensionEntry

	for _, bp := range profiles {
		dirEntries, err := readDir(bp.ExtDir)
		if err != nil {
			continue
		}

		for _, e := range dirEntries {
			if !e.IsDir() || e.Name() == "Temp" {
				continue
			}

			extPath := bp.ExtDir + string(os.PathSeparator) + e.Name()

			info, err := parseExtension(extPath, e.Name(), bp.Browser, bp.Profile)
			if err != nil {
				continue
			}

			analyzePermissions(info, m.Extension.DangerousPermissions)
			calculateRiskScore(info, m.RiskScoring.Weights)

			entries = append(entries, ExtensionEntry{
				Path:        info.Path,
				ID:          info.ID,
				Name:        info.Name,
				Browser:     info.Browser,
				Profile:     info.Profile,
				Version:     info.Version,
				ManifestVer: info.ManifestVer,
				RiskLevel:   info.RiskLevel,
				RiskScore:   info.RiskScore,
				Permissions: len(info.Permissions.All),
			})
		}
	}

	// Mark cross-browser duplicates (same extension ID in different browsers/profiles).
	// The first occurrence (by insertion order) is the primary; others are marked as dupes.
	markDuplicates(entries)

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RiskScore > entries[j].RiskScore
	})

	return entries
}

// markDuplicates flags entries with the same ID as duplicates of the first occurrence.
func markDuplicates(entries []ExtensionEntry) {
	seen := make(map[string]string) // ext ID -> "browser/profile"
	for i := range entries {
		key := entries[i].ID
		if primary, exists := seen[key]; exists {
			entries[i].Duplicate = true
			entries[i].DupeOf = primary
		} else {
			seen[key] = entries[i].Browser + "/" + entries[i].Profile
		}
	}
}
