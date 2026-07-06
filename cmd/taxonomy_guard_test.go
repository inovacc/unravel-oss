package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// guardedExtensions holds the file extensions grepFound scans for retired
// command paths / MCP tool names.
var guardedExtensions = map[string]bool{
	".go":   true,
	".md":   true,
	".yaml": true,
	".yml":  true,
	".txt":  true,
}

// TODO(taxonomy-guard): consider a word-boundary matcher (treat a hit as valid
// only when the chars flanking the needle are non-identifier, i.e. not
// [A-Za-z0-9_]). That would let us also ban the pre-grouping leaf names that are
// literal prefixes of their surviving grouped siblings — unravel_kb_gaps,
// unravel_kb_diff, and the bare unravel_android_tools — without false-positiving
// unravel_kb_gaps_list, unravel_kb_transfer_diff*, or unravel_android_tools_status.
// Not done here (LOW-RISK-ONLY): a uniform word-boundary rule would silently
// break the intentional PREFIX bans that end in "_" (notably "unravel_knowledge_",
// which must match unravel_knowledge_<anything>), so it needs a prefix special-case
// plus per-name verification that no live tool equals the bare prefix. Left as
// substring matching to keep the guard green and simple.
//
// grepFound reports whether needle appears anywhere in the contents of root.
// If root is a regular file, only that file is scanned. If root is a
// directory, it is walked recursively and every regular file whose extension
// is in guardedExtensions is scanned, except: cmd/taxonomy_guard_test.go
// itself (so the banned literals inside this file don't self-trigger), any
// path containing "testdata/help" (golden snapshots), and any ".git"
// directory.
func grepFound(t *testing.T, root, needle string) bool {
	t.Helper()

	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat %s: %v", root, err)
	}

	if !info.IsDir() {
		return fileContains(t, root, needle)
	}

	found := false
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		normalized := filepath.ToSlash(path)
		// Skip this guard file itself so the banned literals declared inside
		// it don't self-trigger. Match on the basename because the scan roots
		// include "." (the cmd/ package dir), where this file's walked path is
		// just "taxonomy_guard_test.go" (no "cmd/" prefix).
		if strings.HasSuffix(normalized, "taxonomy_guard_test.go") {
			return nil
		}
		if strings.Contains(normalized, "testdata/help") {
			return nil
		}
		// The taxonomy meta-docs (audit, spec, plan, mapping tables, and the
		// generated migration table) intentionally record the OLD names as a
		// historical/mapping reference, so they must not trip the guard.
		// docs/COMMAND-TAXONOMY.md itself uses the same "(←`old_name`)"
		// footnote convention in §4 to document the app-domain rename lineage,
		// so it is excluded for the same reason.
		// docs/releases/ holds dated point-in-time release notes that name
		// tools as they were called at ship time; rewriting them would falsify
		// the historical record, so they are excluded like the other meta-docs.
		if strings.Contains(normalized, "docs/superpowers/") ||
			strings.Contains(normalized, "docs/releases/") ||
			strings.HasSuffix(normalized, "docs/command-taxonomy-audit.md") ||
			strings.HasSuffix(normalized, "docs/MIGRATION-command-taxonomy.md") ||
			strings.HasSuffix(normalized, "docs/COMMAND-TAXONOMY.md") {
			return nil
		}
		if !guardedExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}

		if fileContains(t, path, needle) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	return found
}

// fileContains reads path and reports whether needle is a substring of its
// contents.
func fileContains(t *testing.T, path, needle string) bool {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return strings.Contains(string(data), needle)
}

// TestNoRetiredCommandNames is a regression net proving no retired command
// paths / MCP tool names remain anywhere in-scope. It is kept GREEN by
// construction: the banned list starts EMPTY, and later tasks append a name
// only in the same commit that removes its last real occurrence.
func TestNoRetiredCommandNames(t *testing.T) {
	// banned holds command paths / MCP tool names retired by SHIPPED tasks of the
	// taxonomy refactor. A name is added here ONLY in the same commit that removes
	// its last real occurrence, so this test stays green. See
	// docs/superpowers/plans/2026-07-01-command-taxonomy-redesign.md.
	banned := []string{
		"knowledgeCmd",
		"\"knowledge <path>\"",
		"list-apps",
		// Retired standalone `setup` command (PR3): `setup kb` folded into
		// `db setup` (dbSetupCmd), and the top-level setup umbrella removed.
		// These exact declaration/registration literals are gone from source;
		// banning them proves the standalone command cannot silently return.
		"var setupCmd",
		"rootCmd.AddCommand(setupCmd)",
		// Entire retired MCP tool prefix (Task 1.6): every unravel_knowledge_*
		// tool was renamed to unravel_kb_<group>_* or removed outright.
		"unravel_knowledge_",
		// Retired pre-grouping unravel_kb_<verb> exact names (Task 1.6).
		// These are NOT substrings of their new grouped names (e.g.
		// unravel_kb_search vs unravel_kb_catalog_search), so banning the
		// exact old string is safe. unravel_kb_gaps and unravel_kb_diff are
		// deliberately excluded: they ARE prefixes of their own new siblings
		// (unravel_kb_gaps_list/_pull/_push_answer, unravel_kb_transfer_diff*)
		// and would false-positive against those.
		"unravel_kb_search",
		"unravel_kb_apps",
		"unravel_kb_stats",
		"unravel_kb_doctor",
		"unravel_kb_timeline",
		"unravel_kb_export",
		"unravel_kb_import",
		"unravel_kb_dump",
		"unravel_kb_facts",
		"unravel_kb_pending_enrich",
		"unravel_kb_write_enrichment",
		"unravel_kb_finding_record",
		"unravel_kb_finding_iteration",
		"unravel_kb_finding_resolve",
		"unravel_kb_finding_list",
		"unravel_kb_finding_summary",
		"unravel_kb_diff_apps",
		"unravel_kb_cost_report",
		// Retired Android MCP tool names (Task 2.2/2.4): unravel_android_<verb>
		// was regrouped into unravel_android_static_<verb> (static-analysis
		// verbs) or unravel_android_tools_<verb> (RE-tool wrappers). None of
		// these exact old strings is a substring of its new grouped sibling
		// (the "_static_"/"_tools_" infix breaks contiguity), so banning the
		// exact literal is safe. unravel_android_extract and
		// unravel_android_info are unaffected and NOT banned. The bare old
		// status tool "unravel_android_tools" (no verb) is deliberately NOT
		// banned: it is a literal prefix of the surviving
		// "unravel_android_tools_status" (and of any future
		// unravel_android_tools_<verb> sibling), so banning it would
		// false-positive the same way unravel_kb_gaps/unravel_kb_diff would.
		"unravel_android_decompile",
		"unravel_android_dex",
		"unravel_android_dex2jar",
		"unravel_android_dex2java",
		"unravel_android_smali",
		"unravel_android_kotlin",
		"unravel_android_native",
		"unravel_android_resources",
		"unravel_android_manifest",
		"unravel_android_protobuf",
		"unravel_android_obfuscation",
		"unravel_android_secrets",
		"unravel_android_framework",
		"unravel_android_telemetry",
		"unravel_android_network",
		"unravel_android_cert",
		"unravel_android_verify",
		"unravel_android_adb",
		"unravel_android_apktool",
		"unravel_android_bundletool",
		"unravel_android_jadx",
		"unravel_android_retdec",
		// Retired `app` domain MCP tool names (Task 2.3/2.4): each root-level
		// tool below was renamed to its unravel_app_<verb> sibling. None of
		// these exact old strings is a substring of its new name (the "app_"
		// infix breaks contiguity), so banning the exact literal is safe.
		// unravel_bundle_reconstruct is unaffected and NOT banned (`bundle
		// reconstruct` stays its own root command, distinct from `app
		// reconstruct` — see docs/COMMAND-TAXONOMY.md §4).
		"unravel_analyze",
		"unravel_dissect",
		"unravel_detect",
		"unravel_heuristic",
		"unravel_schema",
		"unravel_reconstruct",
		"unravel_inject",
		"unravel_inject_scan",
		"unravel_forensic",
		"unravel_forensic_app",
		"unravel_dissect_directory",
		"unravel_disasm",
	}
	roots := []string{".", "../pkg/mcp/tools", "../pkg/aihost", "../docs", "../README.md"}

	for _, needle := range banned {
		for _, root := range roots {
			if grepFound(t, root, needle) {
				t.Errorf("retired name %q still found under %q", needle, root)
			}
		}
	}
}
