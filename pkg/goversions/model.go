package goversions

import "context"

type File struct {
	Filename string `json:"filename"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Kind     string `json:"kind"`
}

type Release struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
	Files   []File `json:"files"`
}

type ReleaseMeta struct {
	Date     string
	Security string
}

type AffectedRange struct {
	Component  string
	Introduced string
	Fixed      string
}

type Vuln struct {
	ID        string
	Aliases   []string
	Summary   string
	URL       string
	Published string
	Modified  string
	Affected  []AffectedRange
}

type ExposedVuln struct {
	ID      string
	FixedIn string
	Summary string
}

type CVEPosture struct {
	Version string
	Exposed []ExposedVuln
}

type SyncReport struct {
	NewVersions []string
	NewVulns    []string
	Releases    int
	Files       int
	Vulns       int
	Errors      []string
}

type Sources interface {
	Downloads(ctx context.Context) ([]Release, error)
	ReleaseMeta(ctx context.Context) (map[string]ReleaseMeta, error)
	Vulns(ctx context.Context) ([]Vuln, error)
}
