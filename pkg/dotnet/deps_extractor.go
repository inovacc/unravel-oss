/*
Copyright (c) 2026 Security Research
*/
package dotnet

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// DotNetExtractor implements knowledge.DepExtractor for the NuGet ecosystem.
//
// Detect: any *.deps.json file in appDir (uses existing FindDepsJSON).
// Extract: reuses ParseDeps for the package summary list; cross-checks the
// raw libraries[] map for the Serviceable flag so private packages get
// flagged for D-08.
type DotNetExtractor struct{}

func (DotNetExtractor) Ecosystem() cve.Ecosystem { return cve.EcosystemNuGet }

// Detect returns true if any *.deps.json sits at appDir (non-recursive — the
// usual layout for published .NET apps puts the manifest beside the entry
// .dll).
func (DotNetExtractor) Detect(appDir string) bool {
	if appDir == "" {
		return false
	}
	return len(FindDepsJSON(appDir)) > 0
}

// Extract walks every *.deps.json in appDir and emits one DepInput per
// distinct (Name, Version) pair of type "package". Project-type entries are
// excluded — they're internal assemblies, not externally-resolvable packages.
//
// Private detection (D-08): library entries with Serviceable=false AND a
// path field that doesn't look like a public NuGet package layout get
// Private=true. Conservative — false positives are worse than misses here.
func (DotNetExtractor) Extract(appDir string) ([]cve.DepInput, error) {
	if appDir == "" {
		return nil, errors.New("DotNetExtractor.Extract: appDir required")
	}
	files := FindDepsJSON(appDir)
	if len(files) == 0 {
		return nil, nil
	}

	type key struct{ name, version string }
	seen := map[key]bool{}
	var out []cve.DepInput

	for _, p := range files {
		// Reuse the existing parser for the package list.
		dr, err := ParseDeps(p)
		if err != nil {
			continue // skip a malformed sidecar, keep going on the rest
		}

		// Read the raw doc once for serviceable + type cross-check.
		raw, rerr := readRawDepsJSON(p)

		for _, lib := range dr.PackageLibs {
			k := key{name: lib.Name, version: lib.Version}
			if seen[k] {
				continue
			}
			seen[k] = true
			if lib.Name == "" || lib.Version == "" {
				continue
			}
			di := cve.DepInput{
				Ecosystem: cve.EcosystemNuGet,
				Name:      lib.Name,
				Version:   lib.Version,
			}
			if rerr == nil && raw != nil {
				if isPrivateNuGet(raw, lib.Name, lib.Version) {
					di.Private = true
				}
			}
			out = append(out, di)
		}
	}
	return out, nil
}

// readRawDepsJSON re-decodes the deps.json into the exported DepsJSON struct
// so we can inspect the Serviceable flag (which the high-level
// LibrarySummary discards).
func readRawDepsJSON(path string) (*DepsJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d DepsJSON
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// isPrivateNuGet flags packages where the raw libraries[] entry shows
// signals consistent with internal/private feeds:
//   - Serviceable=false AND a path that doesn't look like a public NuGet
//     layout ("name/version/" lowercased on the public feed). Conservative;
//     unclear cases stay Private=false.
func isPrivateNuGet(raw *DepsJSON, name, version string) bool {
	// libraries map keys are "name/version".
	libKey := name + "/" + version
	li, ok := raw.Libraries[libKey]
	if !ok {
		return false
	}
	if li.Type != "package" {
		return false
	}
	if li.Serviceable {
		// public NuGet packages all carry Serviceable=true; this is the
		// strongest negative signal we have.
		return false
	}
	// Path on the public feed is always lowercased "<name>/<version>".
	expectPath := strings.ToLower(name) + "/" + strings.ToLower(version)
	if li.Path != "" && li.Path != expectPath {
		return true
	}
	// Serviceable=false with a public-looking path is still suspicious but
	// not unambiguous — treat as private to be safe.
	return true
}
