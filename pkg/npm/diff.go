package npm

import (
	"fmt"
	"os"
)

// VersionDiff compares two versions of the same package.
type VersionDiff struct {
	Package     string          `json:"package"`
	OldVersion  string          `json:"old_version"`
	NewVersion  string          `json:"new_version"`
	OldAnalysis *AnalysisResult `json:"old_analysis"`
	NewAnalysis *AnalysisResult `json:"new_analysis"`
	RiskDelta   int             `json:"risk_delta"` // new - old
	Changes     []DiffChange    `json:"changes"`
}

// DiffChange describes a single difference between two package versions.
type DiffChange struct {
	Category string `json:"category"` // "network", "exec", "secrets", "deps", "obfuscation", "supply_chain"
	Type     string `json:"type"`     // "added", "removed"
	Detail   string `json:"detail"`
}

// DiffVersions downloads, analyzes, and compares two versions of a package.
func DiffVersions(name, oldVersion, newVersion string) (*VersionDiff, error) {
	oldDir, err := os.MkdirTemp("", "unravel-npm-diff-old-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir for old version: %w", err)
	}
	defer func() { _ = os.RemoveAll(oldDir) }()

	newDir, err := os.MkdirTemp("", "unravel-npm-diff-new-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir for new version: %w", err)
	}
	defer func() { _ = os.RemoveAll(newDir) }()

	// Download and analyze old version.
	oldDL, err := Download(name, oldVersion, oldDir)
	if err != nil {
		return nil, fmt.Errorf("downloading %s@%s: %w", name, oldVersion, err)
	}

	oldAnalysis, err := Analyze(oldDir)
	if err != nil {
		return nil, fmt.Errorf("analyzing %s@%s: %w", name, oldDL.Version, err)
	}

	// Download and analyze new version.
	newDL, err := Download(name, newVersion, newDir)
	if err != nil {
		return nil, fmt.Errorf("downloading %s@%s: %w", name, newVersion, err)
	}

	newAnalysis, err := Analyze(newDir)
	if err != nil {
		return nil, fmt.Errorf("analyzing %s@%s: %w", name, newDL.Version, err)
	}

	diff := &VersionDiff{
		Package:     name,
		OldVersion:  oldDL.Version,
		NewVersion:  newDL.Version,
		OldAnalysis: oldAnalysis,
		NewAnalysis: newAnalysis,
		RiskDelta:   newAnalysis.RiskScore - oldAnalysis.RiskScore,
	}

	diff.Changes = computeChanges(oldAnalysis, newAnalysis)

	return diff, nil
}

// computeChanges builds a list of DiffChange entries by comparing findings.
func computeChanges(old, new *AnalysisResult) []DiffChange {
	var changes []DiffChange

	changes = append(changes, diffSlice("network", old.NetworkCalls, new.NetworkCalls)...)
	changes = append(changes, diffSlice("exec", old.ExecCalls, new.ExecCalls)...)
	changes = append(changes, diffSlice("secrets", old.Secrets, new.Secrets)...)
	changes = append(changes, diffSlice("obfuscation", old.ObfuscationIndicators, new.ObfuscationIndicators)...)
	changes = append(changes, diffSlice("supply_chain", old.SupplyChainRisks, new.SupplyChainRisks)...)

	// Dependency count change.
	if new.Dependencies != old.Dependencies {
		delta := new.Dependencies - old.Dependencies
		changeType := "added"
		if delta < 0 {
			changeType = "removed"
			delta = -delta
		}
		changes = append(changes, DiffChange{
			Category: "deps",
			Type:     changeType,
			Detail:   fmt.Sprintf("%d dependencies %s (was %d, now %d)", delta, changeType, old.Dependencies, new.Dependencies),
		})
	}

	// Post-install hook change.
	if !old.HasPostInstall && new.HasPostInstall {
		changes = append(changes, DiffChange{
			Category: "supply_chain",
			Type:     "added",
			Detail:   "install lifecycle hook added",
		})
	} else if old.HasPostInstall && !new.HasPostInstall {
		changes = append(changes, DiffChange{
			Category: "supply_chain",
			Type:     "removed",
			Detail:   "install lifecycle hook removed",
		})
	}

	return changes
}

// diffSlice compares two string slices as sets and returns added/removed entries.
func diffSlice(category string, old, new []string) []DiffChange {
	oldSet := make(map[string]bool, len(old))
	for _, s := range old {
		oldSet[s] = true
	}

	newSet := make(map[string]bool, len(new))
	for _, s := range new {
		newSet[s] = true
	}

	var changes []DiffChange

	for _, s := range new {
		if !oldSet[s] {
			changes = append(changes, DiffChange{
				Category: category,
				Type:     "added",
				Detail:   s,
			})
		}
	}

	for _, s := range old {
		if !newSet[s] {
			changes = append(changes, DiffChange{
				Category: category,
				Type:     "removed",
				Detail:   s,
			})
		}
	}

	return changes
}
