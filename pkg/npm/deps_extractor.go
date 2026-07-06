/*
Copyright (c) 2026 Security Research
*/
package npm

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// NPMExtractor implements knowledge.DepExtractor for the npm ecosystem.
//
// Detect: package.json at appDir root OR any nested node_modules/<pkg>/package.json.
// Extract: package.json (dependencies + devDependencies) merged with package-lock.json
// (v1, v2, v3) when present so transitive locked versions land in the dep list.
//
// Private-package detection (D-08):
//   - Scoped pkg (@org/x) where the lockfile resolved URL is non-public
//   - Scoped pkg with no resolved field at all
//   - Direct git+ssh://, git@, or file:/path-based source string
type NPMExtractor struct{}

// publicRegistry is the registry prefix considered "public". Anything else
// resolves a scoped package as private.
const publicRegistry = "https://registry.npmjs.org"

func (NPMExtractor) Ecosystem() cve.Ecosystem { return cve.EcosystemNPM }

// Detect returns true if package.json is present at appDir, or any nested
// node_modules/<pkg>/package.json exists. Returns true on first hit; bounded
// walk depth keeps the cost low on big trees.
func (NPMExtractor) Detect(appDir string) bool {
	if appDir == "" {
		return false
	}
	if fi, err := os.Stat(filepath.Join(appDir, "package.json")); err == nil && !fi.IsDir() {
		return true
	}
	// Look for any node_modules/<pkg>/package.json. Bound depth at 6 segments
	// from appDir to avoid pathological walks.
	found := false
	rootSeps := strings.Count(filepath.ToSlash(filepath.Clean(appDir)), "/")
	_ = filepath.WalkDir(appDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if found {
			return fs.SkipDir
		}
		if d.IsDir() {
			depth := strings.Count(filepath.ToSlash(filepath.Clean(path)), "/") - rootSeps
			if depth > 6 {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" {
			return nil
		}
		// must live under a node_modules/<pkg>/ ancestor
		rel, _ := filepath.Rel(appDir, path)
		if strings.Contains(filepath.ToSlash(rel), "node_modules/") {
			found = true
			return fs.SkipDir
		}
		return nil
	})
	return found
}

// pkgJSON is the minimal subset of package.json we need.
type pkgJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Extract walks package.json + package-lock.json (when present) and returns
// the merged dep list. Lockfile versions wins on conflict because it has the
// resolved version vs the manifest's range string.
func (NPMExtractor) Extract(appDir string) ([]cve.DepInput, error) {
	if appDir == "" {
		return nil, errors.New("NPMExtractor.Extract: appDir required")
	}

	type entry struct {
		name     string
		version  string
		resolved string // empty when only manifest had it
		scoped   bool
	}
	// keyed by name → keep the most informative entry (lockfile beats manifest)
	merged := map[string]entry{}

	// 1. package.json (range strings — kept only as fallback)
	pjPath := filepath.Join(appDir, "package.json")
	if data, err := os.ReadFile(pjPath); err == nil {
		var pj pkgJSON
		if json.Unmarshal(data, &pj) == nil {
			for name, ver := range pj.Dependencies {
				merged[name] = entry{name: name, version: ver, scoped: strings.HasPrefix(name, "@")}
			}
			for name, ver := range pj.DevDependencies {
				if _, ok := merged[name]; ok {
					continue
				}
				merged[name] = entry{name: name, version: ver, scoped: strings.HasPrefix(name, "@")}
			}
		}
	}

	// 2. package-lock.json (resolved versions — overrides ranges)
	lockPath := filepath.Join(appDir, "package-lock.json")
	if _, err := os.Stat(lockPath); err == nil {
		lr, lerr := ParseLockfile(lockPath)
		if lerr == nil && lr != nil {
			for _, ld := range lr.Dependencies {
				if ld.Name == "" || ld.Version == "" {
					continue
				}
				prev, exists := merged[ld.Name]
				// prefer lockfile entry; if duplicate (multiple depths) keep first
				if exists && prev.resolved != "" {
					continue
				}
				merged[ld.Name] = entry{
					name:     ld.Name,
					version:  ld.Version,
					resolved: ld.Resolved,
					scoped:   strings.HasPrefix(ld.Name, "@"),
				}
			}
		}
	}

	out := make([]cve.DepInput, 0, len(merged))
	for _, e := range merged {
		// version may still be a range like "^4.17.20" if no lockfile
		// hit. cve.Client.Query passes this through to OSV; OSV accepts
		// exact versions only, so range strings will report empty vulns.
		// That's acceptable — manifest-only callers see the dep listed.
		ver := strings.TrimLeft(e.version, "^~>=<v ")
		di := cve.DepInput{
			Ecosystem: cve.EcosystemNPM,
			Name:      e.name,
			Version:   ver,
		}
		if isPrivateNPM(e.name, e.scoped, e.resolved, e.version) {
			di.Private = true
		}
		out = append(out, di)
	}
	return out, nil
}

// isPrivateNPM applies the D-08 heuristic for private/internal scoped packages.
// Conservative: only flips Private when the signal is unambiguous, so we
// never silently skip a legitimately public scoped package.
func isPrivateNPM(name string, scoped bool, resolved, declared string) bool {
	// Direct git/file sources from package.json.
	switch {
	case strings.HasPrefix(declared, "git+ssh://"),
		strings.HasPrefix(declared, "git@"),
		strings.HasPrefix(declared, "ssh://"),
		strings.HasPrefix(declared, "file:"):
		return true
	}
	if !scoped {
		// Heuristic only fires for scoped packages — unscoped names from
		// arbitrary registries are too noisy.
		return false
	}
	if resolved == "" {
		// Scoped + no resolved field → likely shrinkwrapped from a
		// private registry that omits the URL.
		return true
	}
	if !strings.HasPrefix(resolved, publicRegistry) {
		return true
	}
	return false
}
