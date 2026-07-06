/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dotnet"
)

// Assembly is one decompile target enumerated by the walker.
type Assembly struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	FirstParty bool   `json:"first_party"`
}

// frameworkPrefixes lists assembly-name prefixes treated as Microsoft / runtime
// framework code. D-06: skipped from full-app mode unless IncludeFramework=true.
//
// Each entry is paired with a short rationale. Case-insensitive prefix match.
var frameworkPrefixes = []struct {
	prefix string
	reason string
}{
	{"Microsoft.", "Microsoft-published BCL/runtime/extensions namespace"},
	{"System.", "BCL / .NET runtime types"},
	{"mscorlib", "legacy .NET Framework core library"},
	{"netstandard", ".NET Standard reference assembly"},
	{"WindowsBase", "WPF base assembly shipped with .NET Framework"},
	{"PresentationCore", "WPF core, ships with framework"},
	{"PresentationFramework", "WPF top-level, ships with framework"},
	{"WindowsApp", "Windows App SDK / WindowsAppRuntime — vendor framework"},
}

// isFrameworkName reports whether the given assembly name matches a known
// framework prefix. Case-insensitive.
func isFrameworkName(name string) bool {
	lower := strings.ToLower(name)
	for _, fp := range frameworkPrefixes {
		if strings.HasPrefix(lower, strings.ToLower(fp.prefix)) {
			return true
		}
	}

	return false
}

// WalkSingle handles single-assembly mode (D-05): input is a .dll or .exe
// path; returns a one-element Assembly slice with FirstParty=true.
func WalkSingle(input string) ([]Assembly, error) {
	abs, err := sanitizeOutPath("", input)
	if err != nil {
		return nil, fmt.Errorf("walker: sanitize input: %w", err)
	}

	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("walker: stat %s: %w", abs, err)
	}

	if st.IsDir() {
		return nil, fmt.Errorf("walker: WalkSingle expects a file, got directory: %s", abs)
	}

	return []Assembly{
		{
			Name:       filepath.Base(abs),
			Path:       abs,
			FirstParty: true,
		},
	}, nil
}

// WalkFullApp handles full-app mode (D-05/D-06): input is a directory
// containing a *.deps.json. Walks library names; resolves each to
// <dir>/<name>.dll on disk; classifies framework vs first-party via
// isFrameworkName; rejects adversarial names containing ".." or path
// separators.
func WalkFullApp(dir string, includeFramework bool) ([]Assembly, error) {
	absDir, err := sanitizeOutPath("", dir)
	if err != nil {
		return nil, fmt.Errorf("walker: sanitize dir: %w", err)
	}

	st, err := os.Stat(absDir)
	if err != nil {
		return nil, fmt.Errorf("walker: stat %s: %w", absDir, err)
	}

	if !st.IsDir() {
		return nil, fmt.Errorf("walker: WalkFullApp expects a directory, got file: %s", absDir)
	}

	matches, err := filepath.Glob(filepath.Join(absDir, "*.deps.json"))
	if err != nil {
		return nil, fmt.Errorf("walker: glob deps.json: %w", err)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("walker: no *.deps.json found in %s", absDir)
	}

	deps, err := dotnet.ParseDeps(matches[0])
	if err != nil {
		return nil, fmt.Errorf("walker: parse %s: %w", matches[0], err)
	}

	seen := map[string]bool{}
	out := []Assembly{}

	addLib := func(name string, firstParty bool) {
		if name == "" {
			return
		}

		// Reject adversarial names early. Library names from deps.json are not
		// filesystem paths and must not contain separators or traversal.
		if strings.Contains(name, "..") ||
			strings.ContainsAny(name, `/\`) ||
			filepath.IsAbs(name) {
			return
		}

		dllName := name + ".dll"
		// sanitizeOutPath under the dir root catches anything that would escape.
		path, err := sanitizeOutPath(absDir, filepath.Join(absDir, dllName))
		if err != nil {
			return
		}

		if _, err := os.Stat(path); err != nil {
			// Library declared in deps.json but not on disk — skip silently.
			return
		}

		if seen[name] {
			return
		}
		seen[name] = true

		out = append(out, Assembly{
			Name:       dllName,
			Path:       path,
			FirstParty: firstParty,
		})
	}

	for _, lib := range deps.ProjectLibs {
		// project libs are always first-party.
		addLib(lib.Name, true)
	}

	for _, lib := range deps.PackageLibs {
		isFramework := isFrameworkName(lib.Name)
		if isFramework && !includeFramework {
			continue
		}

		addLib(lib.Name, !isFramework)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out, nil
}
