/*
Copyright (c) 2026 Security Research
*/

// Package pydeps implements a PyPI DepExtractor. It parses requirements.txt
// (PEP 508) plus pyproject.toml in 4 dialects: Poetry, PEP 621, Hatch, pdm.
// Deps with explicit URL/git sources are tagged Private=true per D-08.
package pydeps

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

type PyExtractor struct{}

func (PyExtractor) Ecosystem() cve.Ecosystem { return cve.EcosystemPyPI }

// Detect: any of requirements.txt, pyproject.toml, setup.py at appDir.
func (PyExtractor) Detect(appDir string) bool {
	if appDir == "" {
		return false
	}
	for _, name := range []string{"requirements.txt", "pyproject.toml", "setup.py"} {
		if st, err := os.Stat(filepath.Join(appDir, name)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// Extract walks all known sources and merges (later parses overwrite version
// for same package — first-seen wins for stability).
func (PyExtractor) Extract(appDir string) ([]cve.DepInput, error) {
	if appDir == "" {
		return nil, fmt.Errorf("pydeps: empty appDir")
	}

	seen := map[string]int{} // package name (case-insensitive) -> index in out
	var out []cve.DepInput

	add := func(d cve.DepInput) {
		key := strings.ToLower(d.Name)
		if key == "" {
			return
		}
		if idx, ok := seen[key]; ok {
			// First-seen wins, but escalate Private flag if any source flags it.
			if d.Private {
				out[idx].Private = true
			}
			return
		}
		seen[key] = len(out)
		out = append(out, d)
	}

	// requirements.txt (with one-level recursive include)
	reqPath := filepath.Join(appDir, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		deps, err := parseRequirementsFile(reqPath, appDir, true)
		if err != nil {
			return nil, err
		}
		for _, d := range deps {
			add(d)
		}
	}

	// pyproject.toml
	pyprojPath := filepath.Join(appDir, "pyproject.toml")
	if data, err := os.ReadFile(pyprojPath); err == nil {
		deps, err := parsePyproject(string(data))
		if err != nil {
			return nil, fmt.Errorf("pydeps: parse pyproject.toml: %w", err)
		}
		for _, d := range deps {
			add(d)
		}
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// requirements.txt parser (PEP 508 lite)
// ---------------------------------------------------------------------------

// parseRequirementsFile parses a requirements.txt. If allowInclude is true,
// `-r other.txt` lines are followed one level (no further nesting).
func parseRequirementsFile(path, baseDir string, allowInclude bool) ([]cve.DepInput, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pydeps: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var out []cve.DepInput
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Recursive include
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "--requirement ") {
			if !allowInclude {
				continue
			}
			rel := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "-r"), "--requirement"))
			if rel == "" {
				continue
			}
			child := rel
			if !filepath.IsAbs(child) {
				child = filepath.Join(baseDir, rel)
			}
			deps, err := parseRequirementsFile(child, filepath.Dir(child), false)
			if err != nil {
				// Soft-fail nested includes; skip if missing.
				continue
			}
			out = append(out, deps...)
			continue
		}
		// Skip other directives
		if strings.HasPrefix(line, "-") {
			continue
		}
		dep, ok := parsePEP508Line(line)
		if !ok {
			continue
		}
		out = append(out, dep)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("pydeps: scan %s: %w", path, err)
	}
	return out, nil
}

// pep508URLPattern: `name @ <url>` form (PEP 440 direct URL).
var pep508URLPattern = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*@\s*(.+)$`)

// pep508SpecPattern: `name[extra] OP version[, OP version]...`
var pep508SpecPattern = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(.*)$`)

// versionOpPattern matches a single specifier `OP V`.
var versionOpPattern = regexp.MustCompile(`(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9_.\-+*]+)`)

// parsePEP508Line parses a single dep line. Returns ok=false for blank /
// unparseable input. Multi-version specs return the lower bound (>=, ==, ~=).
func parsePEP508Line(line string) (cve.DepInput, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return cve.DepInput{}, false
	}
	// Split off environment markers `; python_version >= "3.8"` — ignore.
	if i := strings.Index(line, ";"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	// Strip extras `[foo,bar]` from the version-detection step but keep name.
	if m := pep508URLPattern.FindStringSubmatch(line); m != nil {
		name := strings.TrimSpace(m[1])
		url := strings.TrimSpace(m[2])
		return cve.DepInput{
			Ecosystem: cve.EcosystemPyPI,
			Name:      name,
			Version:   "",
			Private:   isPrivatePyURL(url),
		}, true
	}
	m := pep508SpecPattern.FindStringSubmatch(line)
	if m == nil {
		return cve.DepInput{}, false
	}
	name := strings.TrimSpace(m[1])
	rest := strings.TrimSpace(m[2])

	var version string
	if rest != "" {
		// Find lower bound: prefer ==, then >=, then ~=, else first match.
		matches := versionOpPattern.FindAllStringSubmatch(rest, -1)
		var eq, gte, twi, fallback string
		for _, mm := range matches {
			op, v := mm[1], mm[2]
			switch op {
			case "==":
				if eq == "" {
					eq = v
				}
			case ">=":
				if gte == "" {
					gte = v
				}
			case "~=":
				if twi == "" {
					twi = v
				}
			default:
				if fallback == "" {
					fallback = v
				}
			}
		}
		switch {
		case eq != "":
			version = eq
		case gte != "":
			version = gte
		case twi != "":
			version = twi
		default:
			version = fallback
		}
	}
	return cve.DepInput{
		Ecosystem: cve.EcosystemPyPI,
		Name:      name,
		Version:   version,
	}, true
}

// isPrivatePyURL returns true for non-PyPI direct URLs per D-08.
func isPrivatePyURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" {
		return false
	}
	if strings.HasPrefix(u, "git+") ||
		strings.HasPrefix(u, "file://") ||
		strings.HasPrefix(u, "ssh://") ||
		strings.HasPrefix(u, "./") ||
		strings.HasPrefix(u, "../") ||
		strings.HasPrefix(u, "/") {
		return true
	}
	// Any direct URL that isn't pypi.org is suspicious.
	if strings.Contains(u, "://") && !strings.Contains(u, "pypi.org") &&
		!strings.Contains(u, "files.pythonhosted.org") {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// pyproject.toml parser (targeted, no third-party dep)
// ---------------------------------------------------------------------------

// parsePyproject parses a pyproject.toml string and returns deps from any
// recognized dialect. We only walk the tables we care about; full TOML
// fidelity is not required because dep tables follow a narrow shape.
func parsePyproject(content string) ([]cve.DepInput, error) {
	tables := splitTOMLTables(content)
	var out []cve.DepInput

	// PEP 621: [project] dependencies = ["foo>=1", "bar==2.0", ...]
	if body, ok := tables["project"]; ok {
		if arr, ok := readArray(body, "dependencies"); ok {
			for _, item := range arr {
				if dep, ok := parsePEP508Line(item); ok {
					out = append(out, dep)
				}
			}
		}
	}

	// Poetry: [tool.poetry.dependencies] foo = "^1.0"
	if body, ok := tables["tool.poetry.dependencies"]; ok {
		out = append(out, parsePoetryTable(body)...)
	}

	// Hatch: [tool.hatch.envs.default.dependencies] (rare; usually array form)
	for tableName, body := range tables {
		if strings.HasPrefix(tableName, "tool.hatch.envs.") &&
			strings.HasSuffix(tableName, ".dependencies") {
			// Hatch can be either array or table; try array first.
			if arr, ok := readArrayFromTableBody(body); ok {
				for _, item := range arr {
					if dep, ok := parsePEP508Line(item); ok {
						out = append(out, dep)
					}
				}
			}
		}
	}

	// pdm: [tool.pdm.dependencies] (table-of-strings or array — handle both)
	if body, ok := tables["tool.pdm.dependencies"]; ok {
		out = append(out, parsePoetryTable(body)...)
	}

	return out, nil
}

// splitTOMLTables breaks a TOML doc into (table-name -> body-text). Body
// text contains every non-table line until the next [header]. No recursion.
func splitTOMLTables(content string) map[string]string {
	out := map[string]string{
		"": "", // root scope (rarely used here)
	}
	cur := ""
	var buf strings.Builder
	flush := func() {
		out[cur] += buf.String()
		buf.Reset()
	}
	headerRe := regexp.MustCompile(`^\[([A-Za-z0-9_.\-]+)\]\s*$`)
	for line := range strings.SplitSeq(content, "\n") {
		trim := strings.TrimSpace(line)
		// Inline-array element of `[[arrayOfTables]]` pattern — ignore (treat
		// as plain text in current scope).
		if m := headerRe.FindStringSubmatch(trim); m != nil {
			flush()
			cur = m[1]
			if _, ok := out[cur]; !ok {
				out[cur] = ""
			}
			continue
		}
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	flush()
	return out
}

// readArray finds `key = [ ... ]` (possibly multi-line) inside body and
// returns the string-literal elements.
func readArray(body, key string) ([]string, bool) {
	// Match key = [ ... ]
	pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*\[`)
	loc := pattern.FindStringIndex(body)
	if loc == nil {
		return nil, false
	}
	rest := body[loc[1]:]
	// Find matching close bracket
	depth := 1
	end := -1
	for i, r := range rest {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil, false
	}
	inside := rest[:end]
	return parseStringArrayElements(inside), true
}

// readArrayFromTableBody: when an entire table body is itself meant to be a
// dependencies array, find its first `*= [...]` literal.
func readArrayFromTableBody(body string) ([]string, bool) {
	// Try common keys.
	for _, k := range []string{"dependencies", "dev-dependencies"} {
		if arr, ok := readArray(body, k); ok {
			return arr, true
		}
	}
	return nil, false
}

// parseStringArrayElements pulls "..." or '...' literals out of an inline
// TOML array body. Comments + commas + whitespace are stripped.
var stringElemRe = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'([^']*)'`)

func parseStringArrayElements(body string) []string {
	var out []string
	for _, m := range stringElemRe.FindAllStringSubmatch(body, -1) {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		out = append(out, s)
	}
	return out
}

// parsePoetryTable parses lines of the form:
//
//	foo = "^1.0"
//	bar = { version = "^2", git = "https://internal/..." }
//	python = "^3.10"   (skipped — Poetry's runtime spec)
var poetryEntryRe = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.\-]+)\s*=\s*(.+?)\s*$`)

func parsePoetryTable(body string) []cve.DepInput {
	var out []cve.DepInput
	for _, m := range poetryEntryRe.FindAllStringSubmatch(body, -1) {
		name, rhs := m[1], strings.TrimSpace(m[2])
		if strings.EqualFold(name, "python") {
			continue
		}
		// Strip trailing commas (table-inline split)
		rhs = strings.TrimRight(rhs, ",")
		dep := cve.DepInput{
			Ecosystem: cve.EcosystemPyPI,
			Name:      name,
		}
		if strings.HasPrefix(rhs, "{") {
			// Inline table — search for version, git, url, path keys.
			if v, ok := extractInlineKey(rhs, "version"); ok {
				dep.Version = stripPoetryRange(v)
			}
			for _, k := range []string{"git", "url", "path"} {
				if v, ok := extractInlineKey(rhs, k); ok {
					if isPrivatePyURL(v) || k == "path" {
						dep.Private = true
					}
				}
			}
		} else if strings.HasPrefix(rhs, `"`) || strings.HasPrefix(rhs, `'`) {
			if elems := parseStringArrayElements(rhs); len(elems) > 0 {
				dep.Version = stripPoetryRange(elems[0])
			}
		} else if strings.HasPrefix(rhs, "[") {
			// Multi-constraint array — take the first version literal.
			if elems := parseStringArrayElements(rhs); len(elems) > 0 {
				dep.Version = stripPoetryRange(elems[0])
			}
		}
		out = append(out, dep)
	}
	return out
}

func extractInlineKey(inlineTable, key string) (string, bool) {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(key) + `\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	m := re.FindStringSubmatch(inlineTable)
	if m == nil {
		return "", false
	}
	if m[1] != "" {
		return m[1], true
	}
	return m[2], true
}

// stripPoetryRange normalizes Poetry's `^1.2`, `~1.2`, `>=1.0,<2.0`,
// `*`, `1.2.3` -> a bare lower-bound version string.
func stripPoetryRange(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return ""
	}
	if strings.HasPrefix(s, "^") || strings.HasPrefix(s, "~") {
		return strings.TrimSpace(s[1:])
	}
	// Take the first version literal we can find.
	m := versionOpPattern.FindStringSubmatch(s)
	if m != nil {
		return m[2]
	}
	// Bare version like "1.2.3"
	if regexp.MustCompile(`^[0-9].*`).MatchString(s) {
		return s
	}
	return ""
}
