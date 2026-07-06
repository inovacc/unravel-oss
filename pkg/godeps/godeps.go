/*
Copyright (c) 2026 Security Research
*/

// Package godeps implements a Go-modules DepExtractor for the knowledge
// enrichment pipeline. It parses go.mod via golang.org/x/mod/modfile and
// emits one cve.DepInput per Require directive. Replace directives that
// point at local paths or non-public hosts mark the affected modules as
// Private (D-08).
package godeps

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// GoExtractor satisfies knowledge.DepExtractor for the Go ecosystem.
// Wiring lives in pkg/knowledge/registry/dep_extractors.go to avoid the
// cycle pkg/knowledge -> pkg/dissect -> pkg/godeps -> pkg/knowledge.
type GoExtractor struct{}

// Ecosystem returns the OSV-canonical ecosystem string.
func (GoExtractor) Ecosystem() cve.Ecosystem { return cve.EcosystemGo }

// Detect returns true when go.mod exists at appDir.
func (GoExtractor) Detect(appDir string) bool {
	if appDir == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(appDir, "go.mod"))
	return err == nil && !st.IsDir()
}

// Extract walks Require directives. Replace targets that are local paths or
// non-public hosts mark affected deps Private=true per D-08.
func (GoExtractor) Extract(appDir string) ([]cve.DepInput, error) {
	if appDir == "" {
		return nil, fmt.Errorf("godeps: empty appDir")
	}
	gomodPath := filepath.Join(appDir, "go.mod")
	raw, err := os.ReadFile(gomodPath)
	if err != nil {
		return nil, fmt.Errorf("godeps: read go.mod: %w", err)
	}
	// Use ParseLax: we treat go.mod as a fact-source, not for compilation.
	// Lax accepts v2+ versions without /vN suffix and other minor deviations
	// that would fail the strict modfile.Parse used by the toolchain.
	f, err := modfile.ParseLax(gomodPath, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("godeps: parse go.mod: %w", err)
	}

	// Build replace lookup: module path -> bool (private?). modfile.ParseLax
	// silently drops Replace directives, so we additionally run a textual
	// pass over the raw bytes to recover them.
	private := map[string]bool{}
	for _, r := range f.Replace {
		if r == nil {
			continue
		}
		if isPrivateReplace(r.New.Path) {
			private[r.Old.Path] = true
		}
	}
	for _, rep := range parseReplaceDirectivesText(raw) {
		if isPrivateReplace(rep.NewPath) {
			private[rep.OldPath] = true
		}
	}

	out := make([]cve.DepInput, 0, len(f.Require))
	for _, req := range f.Require {
		if req == nil {
			continue
		}
		out = append(out, cve.DepInput{
			Ecosystem: cve.EcosystemGo,
			Name:      req.Mod.Path,
			Version:   req.Mod.Version,
			Private:   private[req.Mod.Path],
		})
	}
	return out, nil
}

// publicHosts is the heuristic allow-list of well-known public Go module
// hosts. Anything else (custom enterprise GitLab, internal Gitea, etc.) is
// treated as a private replace target per D-08.
var publicHosts = []string{
	"github.com/",
	"gitlab.com/",
	"bitbucket.org/",
	"gopkg.in/",
	"golang.org/",
	"google.golang.org/",
	"cloud.google.com/",
	"k8s.io/",
	"sigs.k8s.io/",
	"go.uber.org/",
	"go.opentelemetry.io/",
	"go.mongodb.org/",
	"go.etcd.io/",
}

// isPrivateReplace decides whether a replace target is "private" for D-08
// purposes. A target is private when:
//   - it's a local filesystem path (starts with ./, ../, /, or contains a
//     drive letter on Windows), or
//   - its host segment isn't in the public allow-list.
func isPrivateReplace(target string) bool {
	if target == "" {
		// Empty new path with a Version-only replace (e.g. version pin) —
		// not a host swap; treat as public.
		return false
	}
	// Local-path heuristic
	if strings.HasPrefix(target, "./") ||
		strings.HasPrefix(target, "../") ||
		strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, ".\\") ||
		strings.HasPrefix(target, "..\\") {
		return true
	}
	if len(target) >= 2 && target[1] == ':' {
		// Windows drive letter (C:\..., D:\...)
		return true
	}
	for _, h := range publicHosts {
		if strings.HasPrefix(target, h) {
			return false
		}
	}
	return true
}

// replaceTextEntry is a textual recovery of a `replace` directive — used
// because modfile.ParseLax discards Replace blocks entirely.
type replaceTextEntry struct {
	OldPath string
	NewPath string
}

// replaceLineRe matches `<old> [vX] => <new> [vY]` (single-line form).
var replaceLineRe = regexp.MustCompile(`^([^\s=]+)(?:\s+\S+)?\s*=>\s*(\S+)`)

// parseReplaceDirectivesText scans go.mod text and pulls out replace
// directives. Handles both the single-line `replace foo => bar` form and
// the block form `replace ( ... )`.
func parseReplaceDirectivesText(raw []byte) []replaceTextEntry {
	var out []replaceTextEntry
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// Strip end-of-line comments
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "replace ("):
			inBlock = true
			continue
		case strings.HasPrefix(line, "replace"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "replace"))
			if e, ok := matchReplace(rest); ok {
				out = append(out, e)
			}
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case inBlock:
			if e, ok := matchReplace(line); ok {
				out = append(out, e)
			}
		}
	}
	return out
}

func matchReplace(s string) (replaceTextEntry, bool) {
	m := replaceLineRe.FindStringSubmatch(s)
	if m == nil {
		return replaceTextEntry{}, false
	}
	return replaceTextEntry{OldPath: m[1], NewPath: m[2]}, true
}
