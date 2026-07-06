/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// npmNameRe matches valid npm package names (scoped and unscoped).
// Scoped: @scope/name; unscoped: name. Both components are lowercase
// alphanumeric plus hyphen, dot, underscore, tilde.
var npmNameRe = regexp.MustCompile(`^(@[a-z0-9\-~][a-z0-9\-._~]*/)?[a-z0-9\-~][a-z0-9\-._~]*$`)

// semverRe matches a semver-ish version string: digits, dots, pre-release
// labels, build metadata. Generous enough for real-world versions.
var semverRe = regexp.MustCompile(`^[0-9a-zA-Z][0-9a-zA-Z.\-+_]*$`)

// goModPathRe matches a Go module path component: printable ASCII, no shell
// metachars, no leading dash.
var goModPathRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/\-]*$`)

// validateDepName returns an error when d.Name or d.Version look unsafe to
// embed in a grype purl positional argument.
func validateDepInput(d DepInput) error {
	if strings.HasPrefix(d.Name, "-") || strings.HasPrefix(d.Version, "-") {
		return fmt.Errorf("grype: dep name/version must not start with '-': name=%q version=%q", d.Name, d.Version)
	}
	switch d.Ecosystem {
	case EcosystemNPM:
		if !npmNameRe.MatchString(d.Name) {
			return fmt.Errorf("grype: npm package name %q contains disallowed characters", d.Name)
		}
	case EcosystemGo:
		if !goModPathRe.MatchString(d.Name) {
			return fmt.Errorf("grype: go module path %q contains disallowed characters", d.Name)
		}
	}
	if !semverRe.MatchString(d.Version) {
		return fmt.Errorf("grype: version %q contains disallowed characters", d.Version)
	}
	return nil
}

const grypeTimeout = 30 * time.Second

// grypeClient is the offline-fallback DB lookup, used only when OSV/NVD/GHSA
// are unavailable. We shell out to a locally-installed `grype` binary.
type grypeClient struct {
	grypePath string // empty = grype not installed
}

func newGrypeClient() *grypeClient {
	p, err := exec.LookPath("grype")
	if err != nil {
		return &grypeClient{}
	}
	return &grypeClient{grypePath: p}
}

// grypeVuln captures one match from grype's JSON output.
type grypeVuln struct {
	ID           string
	Severity     string
	URL          string
	PkgName      string
	PkgVersion   string
	PkgEcosystem string
}

type grypeJSONResp struct {
	Matches []struct {
		Vulnerability struct {
			ID         string `json:"id"`
			Severity   string `json:"severity"`
			DataSource string `json:"dataSource"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	} `json:"matches"`
}

// Query runs grype for one (ecosystem, package, version) tuple and returns
// any matched vulns. Returns nil cleanly when grype is missing.
func (c *grypeClient) Query(ctx context.Context, dep DepInput) ([]grypeVuln, error) {
	if c == nil || c.grypePath == "" {
		return nil, nil
	}
	// W5: validate Name/Version before building the purl target.  A crafted
	// package.json could set name="-o /tmp/evil" which grype would parse as a
	// flag rather than a positional argument.
	if err := validateDepInput(dep); err != nil {
		return nil, err
	}
	target := buildGrypeTarget(dep)
	if target == "" {
		return nil, nil
	}
	cctx, cancel := context.WithTimeout(ctx, grypeTimeout)
	defer cancel()

	// Pass "--" before the positional target so grype cannot interpret it as a
	// flag even if validation above somehow passes a leading-dash value.
	cmd := exec.CommandContext(cctx, c.grypePath, "--", target, "-o", "json")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// grype exits non-zero when matches found in some configs.
			if len(ee.Stderr) > 0 && len(out) == 0 {
				return nil, fmt.Errorf("grype: %s", strings.TrimSpace(string(ee.Stderr)))
			}
		} else {
			return nil, nil // transport-level miss → degrade silently
		}
	}

	var parsed grypeJSONResp
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("grype: decode: %w", err)
	}
	var vs []grypeVuln
	for _, m := range parsed.Matches {
		vs = append(vs, grypeVuln{
			ID:           m.Vulnerability.ID,
			Severity:     strings.ToLower(m.Vulnerability.Severity),
			URL:          m.Vulnerability.DataSource,
			PkgName:      m.Artifact.Name,
			PkgVersion:   m.Artifact.Version,
			PkgEcosystem: string(dep.Ecosystem),
		})
	}
	return vs, nil
}

// buildGrypeTarget renders a `purl`-ish target grype understands.
func buildGrypeTarget(d DepInput) string {
	if d.Name == "" || d.Version == "" {
		return ""
	}
	switch d.Ecosystem {
	case EcosystemNPM:
		return fmt.Sprintf("pkg:npm/%s@%s", d.Name, d.Version)
	case EcosystemGo:
		return fmt.Sprintf("pkg:golang/%s@%s", d.Name, d.Version)
	case EcosystemPyPI:
		return fmt.Sprintf("pkg:pypi/%s@%s", d.Name, d.Version)
	case EcosystemNuGet:
		return fmt.Sprintf("pkg:nuget/%s@%s", d.Name, d.Version)
	default:
		return ""
	}
}
