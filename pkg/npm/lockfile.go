package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// LockfileResult holds parsed dependency tree from package-lock.json.
type LockfileResult struct {
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	LockVersion  int              `json:"lock_version"` // 1, 2, or 3
	Dependencies []LockDependency `json:"dependencies"`
	TotalDeps    int              `json:"total_deps"`
	DirectDeps   int              `json:"direct_deps"`
	TransDeps    int              `json:"transitive_deps"`
	MaxDepth     int              `json:"max_depth"`
	Duplicates   int              `json:"duplicates"` // same name, different versions
}

// LockDependency represents a single resolved dependency from the lockfile.
type LockDependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved,omitempty"`  // registry URL
	Integrity string `json:"integrity,omitempty"` // sri hash
	Dev       bool   `json:"dev,omitempty"`
	Optional  bool   `json:"optional,omitempty"`
	Depth     int    `json:"depth"`
}

// rawLockfile is the top-level structure of package-lock.json.
type rawLockfile struct {
	Name            string                         `json:"name"`
	Version         string                         `json:"version"`
	LockfileVersion int                            `json:"lockfileVersion"`
	Packages        map[string]rawLockPackage      `json:"packages"`     // v2/v3
	Dependencies    map[string]rawLockDependencyV1 `json:"dependencies"` // v1
}

// rawLockPackage is a single entry in the v2/v3 "packages" map.
type rawLockPackage struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	Optional  bool   `json:"optional"`
}

// rawLockDependencyV1 is a single entry in the v1 nested "dependencies" map.
type rawLockDependencyV1 struct {
	Version      string                         `json:"version"`
	Resolved     string                         `json:"resolved"`
	Integrity    string                         `json:"integrity"`
	Dev          bool                           `json:"dev"`
	Optional     bool                           `json:"optional"`
	Dependencies map[string]rawLockDependencyV1 `json:"dependencies"`
}

// ParseLockfile parses a package-lock.json file.
func ParseLockfile(path string) (*LockfileResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	var raw rawLockfile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing lockfile: %w", err)
	}

	result := &LockfileResult{
		Name:        raw.Name,
		Version:     raw.Version,
		LockVersion: raw.LockfileVersion,
	}

	if result.LockVersion == 0 {
		// Infer version: if "packages" exists it's v2+, otherwise v1
		if len(raw.Packages) > 0 {
			result.LockVersion = 2
		} else {
			result.LockVersion = 1
		}
	}

	// Parse based on lockfile version
	if len(raw.Packages) > 0 {
		// v2/v3: flat "packages" map
		result.Dependencies = parseLockV2Packages(raw.Packages)
	} else if len(raw.Dependencies) > 0 {
		// v1: nested "dependencies" object
		result.Dependencies = parseLockV1Dependencies(raw.Dependencies, 1)
	}

	// Sort by name then depth for stable output
	sort.Slice(result.Dependencies, func(i, j int) bool {
		if result.Dependencies[i].Name != result.Dependencies[j].Name {
			return result.Dependencies[i].Name < result.Dependencies[j].Name
		}
		return result.Dependencies[i].Depth < result.Dependencies[j].Depth
	})

	// Compute stats
	result.TotalDeps = len(result.Dependencies)
	nameVersions := make(map[string]map[string]bool) // name -> set of versions
	for _, dep := range result.Dependencies {
		if dep.Depth == 1 {
			result.DirectDeps++
		} else {
			result.TransDeps++
		}
		if dep.Depth > result.MaxDepth {
			result.MaxDepth = dep.Depth
		}
		if nameVersions[dep.Name] == nil {
			nameVersions[dep.Name] = make(map[string]bool)
		}
		nameVersions[dep.Name][dep.Version] = true
	}

	// Count duplicates: packages with more than one version installed
	for _, versions := range nameVersions {
		if len(versions) > 1 {
			result.Duplicates++
		}
	}

	return result, nil
}

// parseLockV2Packages converts the v2/v3 flat "packages" map into LockDependency slices.
// Key format: "" (root), "node_modules/express", "node_modules/express/node_modules/qs"
func parseLockV2Packages(packages map[string]rawLockPackage) []LockDependency {
	var deps []LockDependency

	for key, pkg := range packages {
		if key == "" {
			// Root package entry — skip
			continue
		}

		// Derive name and depth from key path.
		// "node_modules/express" -> depth 1, name "express"
		// "node_modules/express/node_modules/qs" -> depth 2, name "qs"
		// "node_modules/@scope/pkg" -> depth 1, name "@scope/pkg"
		segments := splitNodeModulesPath(key)
		if len(segments) == 0 {
			continue
		}

		name := segments[len(segments)-1]
		depth := len(segments)

		deps = append(deps, LockDependency{
			Name:      name,
			Version:   pkg.Version,
			Resolved:  pkg.Resolved,
			Integrity: pkg.Integrity,
			Dev:       pkg.Dev,
			Optional:  pkg.Optional,
			Depth:     depth,
		})
	}

	return deps
}

// splitNodeModulesPath splits a lockfile package path into package name segments.
// "node_modules/@scope/pkg/node_modules/dep" -> ["@scope/pkg", "dep"]
func splitNodeModulesPath(key string) []string {
	var result []string
	parts := strings.Split(key, "/")

	i := 0
	for i < len(parts) {
		if parts[i] == "node_modules" {
			i++
			if i >= len(parts) {
				break
			}
			// Check for scoped package (@scope/name)
			if strings.HasPrefix(parts[i], "@") && i+1 < len(parts) {
				result = append(result, parts[i]+"/"+parts[i+1])
				i += 2
			} else {
				result = append(result, parts[i])
				i++
			}
		} else {
			i++
		}
	}

	return result
}

// parseLockV1Dependencies recursively walks the v1 nested dependencies structure.
func parseLockV1Dependencies(deps map[string]rawLockDependencyV1, depth int) []LockDependency {
	var result []LockDependency

	for name, dep := range deps {
		result = append(result, LockDependency{
			Name:      name,
			Version:   dep.Version,
			Resolved:  dep.Resolved,
			Integrity: dep.Integrity,
			Dev:       dep.Dev,
			Optional:  dep.Optional,
			Depth:     depth,
		})

		if len(dep.Dependencies) > 0 {
			result = append(result, parseLockV1Dependencies(dep.Dependencies, depth+1)...)
		}
	}

	return result
}
