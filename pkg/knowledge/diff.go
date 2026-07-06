/*
Copyright (c) 2026 Security Research

diff.go — 4-dimension semantic diff with regression classification (D-09/10/11).

Dimensions:
 1. Permissions       (Android perms, AppX caps, Chrome ext perms)
 2. Security config   (CSP, webPreferences, cert pinning)
 3. Structural        (telemetry SDKs, API endpoints, modules)
 4. Text equivalence  (canonicalized JS source modules)

Output: typed DiffResult with []Regression severity-classified by
pkg/knowledge/regressions. The legacy Added/Removed/Changed slices are
preserved for back-compat with pre-Phase-7 consumers.
*/
package knowledge

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	visualdiff "github.com/inovacc/unravel-oss/pkg/capture/diff"
	"github.com/inovacc/unravel-oss/pkg/knowledge/regressions"
)

// DiffSchemaVersion is bumped to 2 for the Phase-7 4-dim shape. Pre-Phase-7
// consumers that read Added/Removed/Changed continue to work unchanged.
const DiffSchemaVersion = 2

// errPathTraversalDiff is returned when oldDir or newDir contains ".." segments.
var errPathTraversalDiff = errors.New("knowledge: diff path traversal rejected")

// DiffResult compares two knowledge directories.
type DiffResult struct {
	OldPath         string                       `json:"old_path"`
	NewPath         string                       `json:"new_path"`
	SchemaVersion   int                          `json:"schema_version"`
	Permissions     *regressions.Permissions     `json:"permissions,omitempty"`
	SecurityConfig  *regressions.SecurityConfig  `json:"security_config,omitempty"`
	Structural      *regressions.Structural      `json:"structural_delta,omitempty"`
	TextEquivalence *regressions.TextEquivalence `json:"text_equivalence,omitempty"`
	Regressions     []regressions.Regression     `json:"regressions"`

	// Visual is the Phase 8 additive section. Nil when neither side has
	// <kb>/visual/. D-13: hook-only — Phase 7's existing 4-dim engine is
	// untouched.
	Visual *visualdiff.VisualResult `json:"visual,omitempty"`

	// Back-compat (pre-Phase-7).
	Added   []DiffEntry  `json:"added,omitempty"`
	Removed []DiffEntry  `json:"removed,omitempty"`
	Changed []DiffChange `json:"changed,omitempty"`
	Summary string       `json:"summary"`
}

// DiffEntry represents a key that was added or removed.
type DiffEntry struct {
	Section string `json:"section"`
	Key     string `json:"key"`
	Value   string `json:"value,omitempty"`
}

// DiffChange represents a key whose value changed between versions.
type DiffChange struct {
	Section  string `json:"section"`
	Key      string `json:"key"`
	OldValue string `json:"old_value"`
	NewValue string `json:"new_value"`
}

// Snapshot returns the typed snapshot consumed by regressions.Classify.
func (d *DiffResult) Snapshot() regressions.Snapshot {
	return regressions.Snapshot{
		Permissions:     d.Permissions,
		SecurityConfig:  d.SecurityConfig,
		Structural:      d.Structural,
		TextEquivalence: d.TextEquivalence,
	}
}

// Diff compares two knowledge directories with the 4-dim comparator, then
// classifies regressions using DefaultRules.
func Diff(oldDir, newDir string) (*DiffResult, error) {
	return DiffWith(oldDir, newDir, regressions.DefaultRules())
}

// DiffWith is like Diff but accepts a custom rule set (e.g. from
// regressions.LoadRubric).
func DiffWith(oldDir, newDir string, rules []regressions.Rule) (*DiffResult, error) {
	if err := rejectTraversal(oldDir); err != nil {
		return nil, err
	}
	if err := rejectTraversal(newDir); err != nil {
		return nil, err
	}

	result := &DiffResult{
		OldPath:       oldDir,
		NewPath:       newDir,
		SchemaVersion: DiffSchemaVersion,
	}

	oldFiles, err := collectJSONFiles(oldDir)
	if err != nil {
		return nil, fmt.Errorf("read old dir: %w", err)
	}
	newFiles, err := collectJSONFiles(newDir)
	if err != nil {
		return nil, fmt.Errorf("read new dir: %w", err)
	}

	allPaths := pathUnion(oldFiles, newFiles)

	// Track which paths typed comparators consumed; the rest fall through
	// to the legacy generic comparator for back-compat (Pitfall 3).
	consumed := make(map[string]bool)

	for _, relPath := range allPaths {
		switch relPath {
		case "android/manifest.json":
			comparePermissions(oldFiles[relPath], newFiles[relPath], result)
			consumed[relPath] = true
		case "security/config.json":
			compareSecurityConfig(oldFiles[relPath], newFiles[relPath], result)
			consumed[relPath] = true
		case "telemetry/services.json", "communication/endpoints.json":
			compareStructural(relPath, oldFiles[relPath], newFiles[relPath], result)
			consumed[relPath] = true
		case "android/network_security_config.json":
			compareNetworkSecurityConfig(oldFiles[relPath], newFiles[relPath], result)
			consumed[relPath] = true
		}
	}

	// Text equivalence: walk JS/TS modules under sources/.
	compareTextSources(oldDir, newDir, result)

	// Legacy fallback: anything not consumed by typed comparators feeds
	// the pre-Phase-7 Added/Removed/Changed slices.
	for _, relPath := range allPaths {
		if consumed[relPath] {
			continue
		}
		section := sectionName(relPath)
		oldData, inOld := oldFiles[relPath]
		newData, inNew := newFiles[relPath]
		if inOld && !inNew {
			result.Removed = append(result.Removed, DiffEntry{Section: section, Key: relPath, Value: "(file removed)"})
			continue
		}
		if !inOld && inNew {
			result.Added = append(result.Added, DiffEntry{Section: section, Key: relPath, Value: "(file added)"})
			continue
		}
		compareJSON(section, oldData, newData, result)
	}

	// Classify regressions.
	result.Regressions = regressions.Classify(result.Snapshot(), rules)

	// Phase 8 additive hook (D-13). Runs only when at least one side has
	// <kb>/visual/ data. Wrapped in defer/recover so a visual-diff panic
	// does NOT corrupt Phase 7's 4-dim result.
	func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("visual diff panic recovered", "err", r)
			}
		}()
		if !hasVisualData(oldDir) && !hasVisualData(newDir) {
			return
		}
		oldRun := latestVisualRun(oldDir)
		newRun := latestVisualRun(newDir)
		if vr, err := visualdiff.CompareVisual(oldRun, newRun); err == nil {
			result.Visual = vr
		} else {
			slog.Warn("visual diff failed", "err", err)
		}
	}()

	result.Summary = buildSummary(result)
	return result, nil
}

// hasVisualData reports whether <kbDir>/visual/ is a directory.
func hasVisualData(kbDir string) bool {
	if kbDir == "" {
		return false
	}
	st, err := os.Stat(filepath.Join(kbDir, "visual"))
	if err != nil {
		return false
	}
	return st.IsDir()
}

// latestVisualRun returns the absolute path to the most-recent visual run dir.
// Resolution order:
//  1. <kbDir>/visual/latest (symlink) — Lstat-checked
//  2. <kbDir>/visual/latest.txt — file containing run-id
//  3. lexicographically last <kbDir>/visual/<run-id>/ subdir
//
// Returns "" if no run dir is found.
func latestVisualRun(kbDir string) string {
	if kbDir == "" {
		return ""
	}
	root := filepath.Join(kbDir, "visual")

	// 1. symlink
	if linkInfo, err := os.Lstat(filepath.Join(root, "latest")); err == nil {
		if linkInfo.Mode()&os.ModeSymlink != 0 {
			if target, err := os.Readlink(filepath.Join(root, "latest")); err == nil {
				if !filepath.IsAbs(target) {
					target = filepath.Join(root, target)
				}
				if st, err := os.Stat(target); err == nil && st.IsDir() {
					return filepath.Clean(target)
				}
			}
		}
	}

	// 2. latest.txt
	if data, err := os.ReadFile(filepath.Join(root, "latest.txt")); err == nil {
		runID := strings.TrimSpace(string(data))
		if runID != "" && !strings.Contains(runID, "..") {
			candidate := filepath.Join(root, runID)
			if st, err := os.Stat(candidate); err == nil && st.IsDir() {
				return candidate
			}
		}
	}

	// 3. lexicographic fallback
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) == 0 {
		return ""
	}
	sort.Strings(dirs)
	return filepath.Join(root, dirs[len(dirs)-1])
}

func rejectTraversal(p string) error {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return errPathTraversalDiff
		}
	}
	return nil
}

func pathUnion(a, b map[string]map[string]any) []string {
	all := make(map[string]bool, len(a)+len(b))
	for k := range a {
		all[k] = true
	}
	for k := range b {
		all[k] = true
	}
	out := make([]string, 0, len(all))
	for k := range all {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func buildSummary(d *DiffResult) string {
	var blocks, flags, passes int
	for _, r := range d.Regressions {
		switch r.Severity {
		case regressions.SeverityBlock:
			blocks++
		case regressions.SeverityFlag:
			flags++
		case regressions.SeverityPass:
			passes++
		}
	}
	return fmt.Sprintf("%d BLOCK, %d FLAG, %d PASS — %d added, %d removed, %d changed (legacy)",
		blocks, flags, passes,
		len(d.Added), len(d.Removed), len(d.Changed))
}

// ----------------------------------------------------------------------------
// Typed comparators
// ----------------------------------------------------------------------------

func comparePermissions(oldM, newM map[string]any, result *DiffResult) {
	oldPerms := extractAndroidPerms(oldM)
	newPerms := extractAndroidPerms(newM)

	oldSet := make(map[string]regressions.AndroidPermission)
	for _, p := range oldPerms {
		oldSet[p.Name] = p
	}
	newSet := make(map[string]regressions.AndroidPermission)
	for _, p := range newPerms {
		newSet[p.Name] = p
	}

	pd := &regressions.Permissions{}
	for name, p := range newSet {
		if _, ok := oldSet[name]; !ok {
			pd.AndroidAdded = append(pd.AndroidAdded, p)
		}
	}
	for name, p := range oldSet {
		if _, ok := newSet[name]; !ok {
			pd.AndroidRemoved = append(pd.AndroidRemoved, p)
		}
	}
	sort.Slice(pd.AndroidAdded, func(i, j int) bool { return pd.AndroidAdded[i].Name < pd.AndroidAdded[j].Name })
	sort.Slice(pd.AndroidRemoved, func(i, j int) bool { return pd.AndroidRemoved[i].Name < pd.AndroidRemoved[j].Name })

	if len(pd.AndroidAdded) > 0 || len(pd.AndroidRemoved) > 0 {
		result.Permissions = pd
	}
}

func extractAndroidPerms(m map[string]any) []regressions.AndroidPermission {
	if m == nil {
		return nil
	}
	raw, ok := m["permissions"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]regressions.AndroidPermission, 0, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		dang, _ := obj["dangerous"].(bool)
		out = append(out, regressions.AndroidPermission{Name: name, Dangerous: dang})
	}
	return out
}

func compareSecurityConfig(oldM, newM map[string]any, result *DiffResult) {
	sc := &regressions.SecurityConfig{}
	hadChange := false

	oldCSP, _ := oldM["csp"].(string)
	newCSP, _ := newM["csp"].(string)
	if oldCSP != newCSP {
		oldTokens := tokenizeCSP(oldCSP)
		newTokens := tokenizeCSP(newCSP)
		oldSet := make(map[string]bool, len(oldTokens))
		for _, t := range oldTokens {
			oldSet[t] = true
		}
		newSet := make(map[string]bool, len(newTokens))
		for _, t := range newTokens {
			newSet[t] = true
		}
		for t := range newSet {
			if !oldSet[t] {
				sc.CSPAdditions = append(sc.CSPAdditions, t)
				hadChange = true
			}
		}
		for t := range oldSet {
			if !newSet[t] {
				sc.CSPRemovals = append(sc.CSPRemovals, t)
				hadChange = true
			}
		}
		sort.Strings(sc.CSPAdditions)
		sort.Strings(sc.CSPRemovals)
	}

	oldPrefs, _ := oldM["webPreferences"].(map[string]any)
	newPrefs, _ := newM["webPreferences"].(map[string]any)
	prefKeys := map[string]bool{}
	for k := range oldPrefs {
		prefKeys[k] = true
	}
	for k := range newPrefs {
		prefKeys[k] = true
	}
	for k := range prefKeys {
		ov := oldPrefs[k]
		nv := newPrefs[k]
		if !equalJSON(ov, nv) {
			if sc.WebPrefsChanged == nil {
				sc.WebPrefsChanged = make(map[string]regressions.ValueChange)
			}
			sc.WebPrefsChanged[k] = regressions.ValueChange{Old: ov, New: nv}
			hadChange = true
		}
	}

	if hadChange {
		result.SecurityConfig = sc
	}
}

func compareNetworkSecurityConfig(oldM, newM map[string]any, result *DiffResult) {
	_, hadOld := oldM["pin_set"]
	_, hadNew := newM["pin_set"]
	if hadOld && !hadNew {
		if result.SecurityConfig == nil {
			result.SecurityConfig = &regressions.SecurityConfig{}
		}
		result.SecurityConfig.CertPinningRemoved = true
	}
}

func compareStructural(relPath string, oldM, newM map[string]any, result *DiffResult) {
	if result.Structural == nil {
		result.Structural = &regressions.Structural{}
	}
	oldArr := extractArray(oldM)
	newArr := extractArray(newM)

	switch relPath {
	case "telemetry/services.json":
		result.Structural.TelemetryCountOld = len(oldArr)
		result.Structural.TelemetryCountNew = len(newArr)
		result.Structural.TelemetryAdded = append(result.Structural.TelemetryAdded, namedDelta(oldArr, newArr)...)
	case "communication/endpoints.json":
		result.Structural.EndpointsCountOld = len(oldArr)
		result.Structural.EndpointsCountNew = len(newArr)
		result.Structural.EndpointsAdded = append(result.Structural.EndpointsAdded, namedDelta(oldArr, newArr)...)
	}
}

// extractArray pulls the array payload out of a parsed JSON file. The diff
// loader wraps top-level arrays as {_data: ...}; handle both shapes.
func extractArray(m map[string]any) []any {
	if m == nil {
		return nil
	}
	if raw, ok := m["_data"]; ok {
		if arr, ok := raw.([]any); ok {
			return arr
		}
	}
	if raw, ok := m["services"]; ok {
		if arr, ok := raw.([]any); ok {
			return arr
		}
	}
	if raw, ok := m["endpoints"]; ok {
		if arr, ok := raw.([]any); ok {
			return arr
		}
	}
	return nil
}

func namedDelta(oldArr, newArr []any) []string {
	oldNames := arrayToNameSet(oldArr)
	var added []string
	for _, item := range newArr {
		name := nameField(item)
		if name == "" {
			continue
		}
		if !oldNames[name] {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	return added
}

func arrayToNameSet(arr []any) map[string]bool {
	out := make(map[string]bool, len(arr))
	for _, item := range arr {
		if n := nameField(item); n != "" {
			out[n] = true
		}
	}
	return out
}

func nameField(v any) string {
	if obj, ok := v.(map[string]any); ok {
		if name, ok := obj["name"].(string); ok {
			return name
		}
		if name, ok := obj["url"].(string); ok {
			return name
		}
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func tokenizeCSP(csp string) []string {
	if csp == "" {
		return nil
	}
	parts := strings.FieldsFunc(csp, func(r rune) bool {
		return r == ' ' || r == ';' || r == ','
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func equalJSON(a, b any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// ----------------------------------------------------------------------------
// Text equivalence
// ----------------------------------------------------------------------------

func compareTextSources(oldDir, newDir string, result *DiffResult) {
	oldMods := collectJSModules(oldDir)
	newMods := collectJSModules(newDir)
	if len(oldMods) == 0 && len(newMods) == 0 {
		return
	}

	te := &regressions.TextEquivalence{}
	all := make(map[string]bool)
	for k := range oldMods {
		all[k] = true
	}
	for k := range newMods {
		all[k] = true
	}
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		oldData, hadOld := oldMods[k]
		newData, hadNew := newMods[k]
		if !hadOld || !hadNew {
			te.ModulesChanged = append(te.ModulesChanged, k)
			continue
		}
		oldHash, oldBypassed := Canonicalize(oldData)
		newHash, newBypassed := Canonicalize(newData)
		if oldBypassed || newBypassed {
			te.Bypassed = append(te.Bypassed, k)
		}
		if oldHash == newHash {
			te.ModulesEquivalent = append(te.ModulesEquivalent, k)
		} else {
			te.ModulesChanged = append(te.ModulesChanged, k)
		}
	}

	if len(te.ModulesEquivalent) > 0 || len(te.ModulesChanged) > 0 || len(te.Bypassed) > 0 {
		result.TextEquivalence = te
	}
}

func collectJSModules(dir string) map[string][]byte {
	out := make(map[string][]byte)
	root := filepath.Join(dir, "sources")
	if _, err := os.Stat(root); err != nil {
		return out
	}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".js" && ext != ".ts" && ext != ".mjs" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		out[filepath.ToSlash(rel)] = data
		return nil
	})
	return out
}

// ----------------------------------------------------------------------------
// Legacy generic comparator (back-compat for non-typed paths)
// ----------------------------------------------------------------------------

// collectJSONFiles walks a directory and reads all .json files into generic maps.
func collectJSONFiles(dir string) (map[string]map[string]any, error) {
	files := make(map[string]map[string]any)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", relPath, err)
		}

		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			var raw any
			if err2 := json.Unmarshal(data, &raw); err2 != nil {
				return nil
			}
			parsed = map[string]any{"_data": raw}
		}

		files[relPath] = parsed
		return nil
	})

	return files, err
}

// sectionName derives a section name from a relative JSON file path.
func sectionName(relPath string) string {
	dir := filepath.Dir(relPath)
	if dir == "." {
		return strings.TrimSuffix(filepath.Base(relPath), ".json")
	}
	return filepath.ToSlash(dir)
}

// compareJSON is the pre-Phase-7 generic comparator used as a fallback.
func compareJSON(section string, oldMap, newMap map[string]any, result *DiffResult) {
	allKeys := make(map[string]bool)
	for k := range oldMap {
		allKeys[k] = true
	}
	for k := range newMap {
		allKeys[k] = true
	}
	sorted := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, key := range sorted {
		oldVal, inOld := oldMap[key]
		newVal, inNew := newMap[key]

		oldStr := jsonString(oldVal)
		newStr := jsonString(newVal)

		if inOld && !inNew {
			result.Removed = append(result.Removed, DiffEntry{Section: section, Key: key, Value: truncate(oldStr, 200)})
			continue
		}
		if !inOld && inNew {
			result.Added = append(result.Added, DiffEntry{Section: section, Key: key, Value: truncate(newStr, 200)})
			continue
		}
		if oldStr != newStr {
			result.Changed = append(result.Changed, DiffChange{Section: section, Key: key, OldValue: truncate(oldStr, 200), NewValue: truncate(newStr, 200)})
		}
	}
}

func jsonString(v any) string {
	if v == nil {
		return "null"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
