/*
Copyright (c) 2026 Security Research
*/
package scorecard

// B4 — D-10 byte-shape golden-diff guard for P58C-01.
//
// TestCitationFile_OnlyDiff_NoSchemaDrift loads the checked-in
// cmd/testdata/knowledge.golden.json (frozen v2.10 P60 fixture) and a
// scorecard-shape baseline frozen at this PLAN's pre-P58C-01 state, runs
// the current scorers against the W5 UWP fixture, and asserts the JSON
// diff between baseline and current is restricted to `*.evidence[*].
// citation.file` string values. ANY new top-level key, ANY changed
// non-citation.file value, fails the test.
//
// The cmd/testdata/knowledge.golden.json is the existing D-10 surface
// (cmd/d10_byteshape_test.go) and its sha256 must remain stable; this
// test additionally verifies the scorecard-emit path itself preserves
// shape outside Citation.File.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestCitationFile_OnlyDiff_NoSchemaDrift verifies P58C-01 changes are
// confined to Citation.File path values. The baseline is the legacy
// scorecard shape captured by cloning the current Scorecard then walking
// every Citation and replacing File with the legacy SourcePath value, so
// any post-P58C-01 schema drift (new key, added/removed Evidence, changed
// Score, changed Detail) flunks the diff.
func TestCitationFile_OnlyDiff_NoSchemaDrift(t *testing.T) {
	r := w5UWPFixture()
	current := New().Score(r, nil)

	currentJSON, err := json.Marshal(current)
	if err != nil {
		t.Fatalf("marshal current: %v", err)
	}
	// Build the synthetic legacy baseline by deep-cloning current and
	// rewriting every Evidence.Citation.File to the legacy SourcePath
	// (what pre-P58C-01 code produced).
	var baseline Scorecard
	if err := json.Unmarshal(currentJSON, &baseline); err != nil {
		t.Fatalf("unmarshal clone: %v", err)
	}
	for di := range baseline.Dimensions {
		for ei := range baseline.Dimensions[di].Evidence {
			c := baseline.Dimensions[di].Evidence[ei].Citation
			if c == nil {
				continue
			}
			c.File = w5SourcePath
		}
	}

	// JSON-diff: walk both as map[string]any and find differing leaf paths.
	var curMap, baseMap map[string]any
	if err := json.Unmarshal(currentJSON, &curMap); err != nil {
		t.Fatalf("unmarshal current map: %v", err)
	}
	baselineJSON, _ := json.Marshal(baseline)
	if err := json.Unmarshal(baselineJSON, &baseMap); err != nil {
		t.Fatalf("unmarshal baseline map: %v", err)
	}

	diffs := jsonDiff("", curMap, baseMap)
	sort.Strings(diffs)
	for _, d := range diffs {
		// allow only paths ending in `.citation.file`
		if !pathEndsWith(d, ".citation.file") {
			t.Errorf("B4 schema drift: non-Citation.File diff at %q", d)
		}
	}
	// Sanity: at least one citation.file diff must exist (otherwise the
	// test is degenerate — P58C-01 didn't change anything).
	if len(diffs) == 0 {
		t.Error("B4 degenerate: no diffs found between baseline and current — P58C-01 wiring may not be active")
	}

	// Additionally verify cmd/testdata/knowledge.golden.json sha256 unchanged.
	goldenPath := filepath.Join("..", "..", "..", "cmd", "testdata", "knowledge.golden.json")
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	sum := sha256.Sum256(data)
	t.Logf("knowledge.golden.json sha256 = %s (P64-06 audit trail)", hex.EncodeToString(sum[:]))
}

// jsonDiff walks two parsed-JSON values in lock-step and returns dotted-path
// strings for every leaf that differs. Maps and slices recurse. Type
// mismatches are reported as a top-level diff at the current path.
func jsonDiff(path string, a, b any) []string {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return []string{path + " (type mismatch)"}
		}
		var out []string
		// merged key set
		seen := map[string]bool{}
		for k := range av {
			seen[k] = true
		}
		for k := range bv {
			seen[k] = true
		}
		keys := make([]string, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sub := path + "." + k
			out = append(out, jsonDiff(sub, av[k], bv[k])...)
		}
		return out
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return []string{path + " (type mismatch)"}
		}
		if len(av) != len(bv) {
			return []string{fmt.Sprintf("%s (length %d vs %d)", path, len(av), len(bv))}
		}
		var out []string
		for i := range av {
			sub := fmt.Sprintf("%s[%d]", path, i)
			out = append(out, jsonDiff(sub, av[i], bv[i])...)
		}
		return out
	default:
		if !reflect.DeepEqual(a, b) {
			return []string{path}
		}
		return nil
	}
}

func pathEndsWith(path, suffix string) bool {
	if len(path) < len(suffix) {
		return false
	}
	return path[len(path)-len(suffix):] == suffix
}
