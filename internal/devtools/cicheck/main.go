/*
Copyright (c) 2026 Security Research

cicheck is the CI guard tool that enforces CICA-06: the tracked v2.6/v2.7
KB-capture CI scaffolding (.github/workflows/kb-capture-ci.yml + the five
.github/scripts/*.sh) must remain syntactically/structurally valid, and the
report-emitting path must still produce a non-empty scorecard for a synthetic
binary. It is a Windows-doable, re-runnable regression guard.

It NEVER executes the five mutating scripts (bash -n parse-check only) and
NEVER triggers kb-capture-ci.yml (read + yaml.Unmarshal only).

Usage:

	go run ./internal/devtools/cicheck [root]

If `root` is omitted, the current working directory is used.

Exit codes:

	0 — all clauses pass OR skipped-with-rationale
	1 — at least one validation failure (bash -n / YAML / pwsh / smoke), printed to stderr
	2 — invocation / I/O failure (printed to stderr)
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// D-01 canonical validation target: the explicit five tracked CI scripts.
// We iterate this list literally — never a repo-wide glob — so the harness
// cannot accidentally widen its scope or execute the scripts' side effects.
var d01Scripts = []string{
	"flip-v2-6-reqs",
	"provision-fixtures",
	"reconcile-target-phase",
	"retag-v2-6-1",
	"run-reconciliation-chain",
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cicheck: resolve root: %v\n", err)
		os.Exit(2)
	}

	violations, ioErr := run(abs)
	if ioErr != nil {
		fmt.Fprintf(os.Stderr, "cicheck: %v\n", ioErr)
		os.Exit(2)
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Fprintf(os.Stderr, "cicheck: %s\n", v)
		}
		fmt.Fprintf(os.Stderr, "cicheck: %d violation(s)\n", len(violations))
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "cicheck: all clauses pass (D-03a bash -n, D-03b YAML, D-04 pwsh-AST, D-05 smoke)")
}

// run executes every CICA-06 clause against root and returns the accumulated
// validation violations. ioErr is non-nil only for an invocation/I-O failure
// that maps to exit 2. This seam exists so tests can assert exit semantics
// without calling os.Exit.
func run(abs string) (violations []string, ioErr error) {
	violations = append(violations, clauseBashN(abs)...)
	violations = append(violations, clauseYAML(abs)...)
	violations = append(violations, clausePwshAST(abs)...)
	violations = append(violations, clauseSmoke(abs)...)
	return violations, nil
}

// clauseBashN (D-03a) parse-checks the five tracked scripts with `bash -n`.
// The scripts mutate REQUIREMENTS.md/STATE.md and create git tags if run, so
// only `-n` (no-exec syntax check) is ever used.
func clauseBashN(abs string) []string {
	var v []string
	for _, f := range d01Scripts {
		// Pass a repo-relative, forward-slash path and run bash with cwd at the
		// repo root. Handing bash an absolute Windows backslash path
		// (filepath.Abs → C:\...\.github\scripts\x.sh) makes Git-Bash/WSL fail
		// with "No such file or directory" on native Windows, which silently
		// broke the "Windows-doable" goal (GAP-71-01). A forward-slash relative
		// path resolves identically on Git-Bash (Windows) and the Linux CI runner.
		rel := ".github/scripts/" + f + ".sh"
		cmd := exec.Command("bash", "-n", rel)
		cmd.Dir = abs
		out, err := cmd.CombinedOutput()
		if err != nil {
			v = append(v, fmt.Sprintf("bash -n FAIL %s: %s", rel, strings.TrimSpace(string(out))))
		}
	}
	return v
}

// clauseYAML (D-03b) structurally validates kb-capture-ci.yml. yaml.v3 keys
// the `on:` block as the literal boolean true (YAML 1.1 truthy), so we tolerate
// any shape for `on` and only fail when name or a non-empty jobs map is absent.
func clauseYAML(abs string) []string {
	var v []string
	p := filepath.Join(abs, ".github", "workflows", "kb-capture-ci.yml")
	b, err := os.ReadFile(p)
	if err != nil {
		return append(v, fmt.Sprintf("YAML read FAIL %s: %v", p, err))
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return append(v, fmt.Sprintf("YAML unmarshal FAIL %s: %v", p, err))
	}
	// Second decode with `any` keys: yaml.v3 normalises the YAML 1.1 truthy
	// `on:` key to the bool true, which a string-keyed map silently drops.
	var anyDoc map[any]any
	_ = yaml.Unmarshal(b, &anyDoc)
	if doc["name"] == nil {
		v = append(v, fmt.Sprintf("YAML %s: missing top-level `name`", p))
	}
	if !hasWorkflowDispatch(doc, anyDoc) {
		v = append(v, fmt.Sprintf("YAML %s: missing `on.workflow_dispatch`", p))
	}
	jobs, ok := doc["jobs"].(map[string]any)
	if !ok || len(jobs) == 0 {
		v = append(v, fmt.Sprintf("YAML %s: `jobs` missing or empty", p))
	}
	return v
}

// hasWorkflowDispatch tolerates yaml.v3's truthy-key normalisation of `on:`.
// `on` may decode under the string key "on", the bool key true, or as a bare
// scalar/sequence; we accept any presence of a workflow_dispatch trigger.
func hasWorkflowDispatch(doc map[string]any, anyDoc map[any]any) bool {
	candidates := []any{doc["on"], anyDoc["on"], anyDoc[true]}
	for _, on := range candidates {
		switch t := on.(type) {
		case map[string]any:
			if _, ok := t["workflow_dispatch"]; ok {
				return true
			}
		case map[any]any:
			if _, ok := t["workflow_dispatch"]; ok {
				return true
			}
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok && s == "workflow_dispatch" {
					return true
				}
			}
		case string:
			if t == "workflow_dispatch" {
				return true
			}
		}
	}
	return false
}

// clausePwshAST (D-04) runs the pwsh ParseFile AST check ONLY over .ps1 found
// in .github/scripts/ — never repo-wide (the tracked .scripts/ tree holds 54
// unrelated .ps1 corpus scripts, out of the D-01 scope). Zero .ps1 in scope is
// the expected steady state: log "N/A by construction" and never invoke pwsh.
func clausePwshAST(abs string) []string {
	var v []string
	glob, _ := filepath.Glob(filepath.Join(abs, ".github", "scripts", "*.ps1"))
	if len(glob) == 0 {
		fmt.Fprintln(os.Stderr, "cicheck: pwsh-AST clause N/A by construction (zero .ps1 in validation target .github/scripts/)")
		return v
	}
	for _, p := range glob {
		snippet := fmt.Sprintf(
			"$e=$null;$t=$null;$null=[System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$t,[ref]$e);if($e -and $e.Count -gt 0){exit 1}",
			p,
		)
		out, err := exec.Command("pwsh", "-NoProfile", "-Command", snippet).CombinedOutput()
		if err != nil {
			v = append(v, fmt.Sprintf("pwsh-AST FAIL %s: %s", p, strings.TrimSpace(string(out))))
		}
	}
	return v
}

// clauseSmoke (D-05) drives the committed 1024-byte synthetic PE fixture
// through `go run . app dissect` and asserts the output dir contains at least one
// non-empty report artifact — proving the user-facing report-emitting path.
// The committed fixture is reused verbatim; gen_synthetic_pe is never invoked.
func clauseSmoke(abs string) []string {
	var v []string
	fixture := filepath.Join(abs, "pkg", "knowledge", "scorecard", "testdata", "synthetic_pe.bin")
	if _, err := os.Stat(fixture); err != nil {
		return append(v, fmt.Sprintf("D-05 smoke: fixture missing %s: %v", fixture, err))
	}
	tmpDir, err := os.MkdirTemp("", "cicheck-smoke-")
	if err != nil {
		return append(v, fmt.Sprintf("D-05 smoke: mkdtemp: %v", err))
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cmd := exec.Command("go", "run", ".", "app", "dissect", fixture, "-o", tmpDir)
	cmd.Dir = abs
	if out, err := cmd.CombinedOutput(); err != nil {
		return append(v, fmt.Sprintf("D-05 smoke: dissect failed: %v: %s", err, strings.TrimSpace(string(out))))
	}

	nonEmpty := false
	_ = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.Mode().IsRegular() && info.Size() > 0 {
			nonEmpty = true
		}
		return nil
	})
	if !nonEmpty {
		v = append(v, "D-05 smoke: dissect produced no non-empty report")
	}
	return v
}
