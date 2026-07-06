/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"time"
)

// LatestProber returns the latest stable version of a package in its
// ecosystem. Per-ecosystem packages register a concrete impl via
// RegisterLatestProber in their init().
type LatestProber interface {
	Ecosystem() Ecosystem
	Latest(ctx context.Context, pkg string) (string, error)
}

// Ecosystem is the OSV-canonical ecosystem string.
// Case-sensitive — must exactly match the OSV API expectations.
type Ecosystem string

const (
	EcosystemNPM   Ecosystem = "npm"
	EcosystemGo    Ecosystem = "Go"
	EcosystemPyPI  Ecosystem = "PyPI"
	EcosystemNuGet Ecosystem = "NuGet"
)

// DepInput is a single package the caller wants enriched.
type DepInput struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
	Private   bool // honors D-08; client skips API calls when true
}

// Severity captures CVSS data for a vulnerability.
type Severity struct {
	CVSSv3 float64 `json:"cvss_v3,omitempty"`
	Vector string  `json:"vector,omitempty"`
	Level  string  `json:"level"` // none|low|medium|high|critical
}

// SourceRef records which upstream contributed a row + when.
type SourceRef struct {
	Name      string    `json:"name"` // osv|nvd|ghsa|grype
	FetchedAt time.Time `json:"fetched_at"`
	URL       string    `json:"url,omitempty"`
}

// Vulnerability is the merged per-CVE record returned to callers.
type Vulnerability struct {
	ID               string      `json:"id"`
	Aliases          []string    `json:"aliases,omitempty"`
	Severity         Severity    `json:"severity"`
	CWE              []string    `json:"cwe,omitempty"`
	AffectedVersions string      `json:"affected_versions,omitempty"`
	References       []string    `json:"references,omitempty"`
	Withdrawn        *time.Time  `json:"withdrawn,omitempty"`
	Sources          []SourceRef `json:"sources"`
}

// VersionDelta is the gap between declared and latest.
type VersionDelta struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Patch int `json:"patch"`
}

// EnrichedDep is the canonical per-dep enrichment record (D-06).
type EnrichedDep struct {
	Ecosystem       Ecosystem       `json:"ecosystem"`
	Package         string          `json:"package"`
	VersionDeclared string          `json:"version_declared"`
	VersionLatest   string          `json:"version_latest,omitempty"`
	OutdatedBy      *VersionDelta   `json:"outdated_by,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Status          string          `json:"status"` // ok|skipped|error
	Reason          string          `json:"reason,omitempty"`
}
