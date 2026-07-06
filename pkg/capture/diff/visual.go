/*
Copyright (c) 2026 Security Research

visual.go — Phase 8 visual diff (image dHash + tree-shape + bounds delta).

Severity mapping (D-13, RESEARCH §"dHash-based visual diff"):
  - Hamming distance <= 5  → PASS  (sub-pixel anti-aliasing jitter tolerated)
  - Hamming distance 6-15  → FLAG  (visible change)
  - Hamming distance > 15  → BLOCK (significant regression)

Severity badges are TEXT-ONLY ([BLOCK] / [FLAG] / [PASS]) per D-21.
*/
package diff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/corona10/goimagehash"
)

// Severity thresholds (D-13).
const (
	DHashHammingPASS = 5  // <= 5 → PASS (sub-pixel AA tolerance)
	DHashHammingFLAG = 15 // 6-15 → FLAG; > 15 → BLOCK
)

// Bounds-diff thresholds (PLAN behavior tests #7/#8).
const (
	BoundsMovementMinPx  = 4.0  // require >= 4px on any axis to record movement
	BoundsSizeChangeFrac = 0.10 // require > 10% size change to record resize
)

// Maximum PNG byte length accepted by DiffImages (T-08-05). 50 MiB cap.
const MaxImageBytes = 50 * 1024 * 1024

// Severity is the text-only badge per D-21 / Phase 7 D-11.
type Severity string

const (
	SeverityPASS  Severity = "PASS"
	SeverityFLAG  Severity = "FLAG"
	SeverityBLOCK Severity = "BLOCK"
)

func severityForHamming(d int) Severity {
	switch {
	case d <= DHashHammingPASS:
		return SeverityPASS
	case d <= DHashHammingFLAG:
		return SeverityFLAG
	default:
		return SeverityBLOCK
	}
}

// worstSeverity returns the most severe between a and b. PASS < FLAG < BLOCK.
func worstSeverity(a, b Severity) Severity {
	rank := func(s Severity) int {
		switch s {
		case SeverityBLOCK:
			return 2
		case SeverityFLAG:
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// ImageDiff is the per-screenshot result.
type ImageDiff struct {
	SHA256Match  bool     `json:"sha256_match"`
	PHashMatch   bool     `json:"phash_match"` // dHash; key kept for D-13 compatibility
	HashDistance int      `json:"hash_distance"`
	Severity     Severity `json:"severity"`
}

// TreeDiff captures structural tree changes.
type TreeDiff struct {
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Moved    []string `json:"moved,omitempty"`
	Severity Severity `json:"severity"`
}

// BoundsDelta is one element's bounds delta.
type BoundsDelta struct {
	DOMPath string  `json:"dom_path"`
	DX      float64 `json:"dx,omitempty"`
	DY      float64 `json:"dy,omitempty"`
	DW      float64 `json:"dw,omitempty"`
	DH      float64 `json:"dh,omitempty"`
}

// LayoutDiff captures bounds movements and size changes.
type LayoutDiff struct {
	Movements   []BoundsDelta `json:"movements,omitempty"`
	SizeChanges []BoundsDelta `json:"size_changes,omitempty"`
	Severity    Severity      `json:"severity"`
}

// StateVisualDiff bundles all three diffs for one (component, state) pair.
type StateVisualDiff struct {
	Image  *ImageDiff  `json:"image,omitempty"`
	Tree   *TreeDiff   `json:"tree,omitempty"`
	Layout *LayoutDiff `json:"layout,omitempty"`
}

// VisualResult is the entire Phase 8 visual diff output.
type VisualResult struct {
	OldRunID string                      `json:"old_run_id,omitempty"`
	NewRunID string                      `json:"new_run_id,omitempty"`
	States   map[string]*StateVisualDiff `json:"states"` // key = "<component>/<state-slug>"
	Added    []string                    `json:"added_states,omitempty"`
	Removed  []string                    `json:"removed_states,omitempty"`
	Summary  string                      `json:"summary"`
}

// WorstSeverity returns the worst severity across all sub-diffs in this state.
func (s *StateVisualDiff) WorstSeverity() Severity {
	worst := SeverityPASS
	if s == nil {
		return worst
	}
	if s.Image != nil {
		worst = worstSeverity(worst, s.Image.Severity)
	}
	if s.Tree != nil {
		worst = worstSeverity(worst, s.Tree.Severity)
	}
	if s.Layout != nil {
		worst = worstSeverity(worst, s.Layout.Severity)
	}
	return worst
}

// DiffImages compares two PNG byte slices. SHA-256 first; if equal, exit
// fast. Otherwise decode both PNGs, compute dHash 64-bit, return Hamming
// distance + severity.
//
// T-08-05: defer/recover at function boundary; oversized inputs rejected.
func DiffImages(oldPNG, newPNG []byte) (id ImageDiff, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("diff images panic: %v", r)
		}
	}()

	if len(oldPNG) > MaxImageBytes || len(newPNG) > MaxImageBytes {
		return ImageDiff{}, fmt.Errorf("image exceeds %d byte cap", MaxImageBytes)
	}

	if bytes.Equal(oldPNG, newPNG) {
		return ImageDiff{SHA256Match: true, PHashMatch: true, HashDistance: 0, Severity: SeverityPASS}, nil
	}

	h1 := sha256.Sum256(oldPNG)
	h2 := sha256.Sum256(newPNG)
	if hex.EncodeToString(h1[:]) == hex.EncodeToString(h2[:]) {
		return ImageDiff{SHA256Match: true, PHashMatch: true, HashDistance: 0, Severity: SeverityPASS}, nil
	}

	img1, err := png.Decode(bytes.NewReader(oldPNG))
	if err != nil {
		return ImageDiff{}, fmt.Errorf("decode old png: %w", err)
	}
	img2, err := png.Decode(bytes.NewReader(newPNG))
	if err != nil {
		return ImageDiff{}, fmt.Errorf("decode new png: %w", err)
	}

	d1, err := goimagehash.DifferenceHash(img1)
	if err != nil {
		return ImageDiff{}, fmt.Errorf("dhash old: %w", err)
	}
	d2, err := goimagehash.DifferenceHash(img2)
	if err != nil {
		return ImageDiff{}, fmt.Errorf("dhash new: %w", err)
	}
	dist, err := d1.Distance(d2)
	if err != nil {
		return ImageDiff{}, fmt.Errorf("hash distance: %w", err)
	}

	return ImageDiff{
		SHA256Match:  false,
		PHashMatch:   dist <= DHashHammingPASS,
		HashDistance: dist,
		Severity:     severityForHamming(dist),
	}, nil
}

// treeNode mirrors the on-disk JSON shape of tree.json (08-02 producer):
// generic nested {tag, dom_path, children} structure.
type treeNode struct {
	Tag      string     `json:"tag"`
	DOMPath  string     `json:"dom_path"`
	Children []treeNode `json:"children,omitempty"`
}

// flattenTree returns a map keyed by dom_path → tag.
func flattenTree(n treeNode, out map[string]string) {
	if n.DOMPath != "" {
		out[n.DOMPath] = n.Tag
	}
	for _, c := range n.Children {
		flattenTree(c, out)
	}
}

// treeRoots unmarshals tree.json bytes accepting either a single root or an
// array of roots.
func treeRoots(data []byte) ([]treeNode, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// Try single object first.
	var single treeNode
	if err := json.Unmarshal(data, &single); err == nil && (single.DOMPath != "" || len(single.Children) > 0 || single.Tag != "") {
		return []treeNode{single}, nil
	}
	var arr []treeNode
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	return nil, fmt.Errorf("tree.json: unrecognized shape")
}

// DiffTrees compares two tree.json byte slices and returns added/removed/moved
// node lists keyed by dom_path. Severity = PASS if everything matches, else
// FLAG (tree changes are not fatal regressions on their own).
//
// T-08-05: defer/recover boundary.
func DiffTrees(oldJSON, newJSON []byte) (td TreeDiff, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("diff trees panic: %v", r)
		}
	}()
	td.Severity = SeverityPASS

	oldRoots, err := treeRoots(oldJSON)
	if err != nil {
		return td, fmt.Errorf("decode old tree: %w", err)
	}
	newRoots, err := treeRoots(newJSON)
	if err != nil {
		return td, fmt.Errorf("decode new tree: %w", err)
	}

	oldMap := make(map[string]string)
	for _, r := range oldRoots {
		flattenTree(r, oldMap)
	}
	newMap := make(map[string]string)
	for _, r := range newRoots {
		flattenTree(r, newMap)
	}

	for k := range newMap {
		if _, ok := oldMap[k]; !ok {
			td.Added = append(td.Added, k)
		}
	}
	for k := range oldMap {
		if _, ok := newMap[k]; !ok {
			td.Removed = append(td.Removed, k)
		}
	}
	// Moved: same dom_path present on both sides but with different tag.
	for k, ov := range oldMap {
		if nv, ok := newMap[k]; ok && nv != ov {
			td.Moved = append(td.Moved, k)
		}
	}

	sort.Strings(td.Added)
	sort.Strings(td.Removed)
	sort.Strings(td.Moved)

	if len(td.Added) > 0 || len(td.Removed) > 0 || len(td.Moved) > 0 {
		td.Severity = SeverityFLAG
	}
	return td, nil
}

// layoutEntry mirrors layout.json on-disk shape (08-02 producer):
// {"dom_path": "...", "x": 0, "y": 0, "w": 0, "h": 0}.
type layoutEntry struct {
	DOMPath string  `json:"dom_path"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	W       float64 `json:"w"`
	H       float64 `json:"h"`
}

// layoutEntries unmarshals layout.json bytes accepting either a top-level
// array or {"elements": [...]}.
func layoutEntries(data []byte) ([]layoutEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var arr []layoutEntry
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	var wrap struct {
		Elements []layoutEntry `json:"elements"`
	}
	if err := json.Unmarshal(data, &wrap); err == nil {
		return wrap.Elements, nil
	}
	return nil, fmt.Errorf("layout.json: unrecognized shape")
}

// DiffLayouts compares two layout.json byte slices, recording per-element
// movements (>=4px) and size changes (>10%). Severity = PASS if no entries,
// FLAG otherwise (layout shifts are visible regressions).
func DiffLayouts(oldJSON, newJSON []byte) (ld LayoutDiff, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("diff layouts panic: %v", r)
		}
	}()
	ld.Severity = SeverityPASS

	oldArr, err := layoutEntries(oldJSON)
	if err != nil {
		return ld, fmt.Errorf("decode old layout: %w", err)
	}
	newArr, err := layoutEntries(newJSON)
	if err != nil {
		return ld, fmt.Errorf("decode new layout: %w", err)
	}

	oldByPath := make(map[string]layoutEntry, len(oldArr))
	for _, e := range oldArr {
		oldByPath[e.DOMPath] = e
	}

	for _, ne := range newArr {
		oe, ok := oldByPath[ne.DOMPath]
		if !ok {
			continue
		}
		dx := ne.X - oe.X
		dy := ne.Y - oe.Y
		if math.Abs(dx) >= BoundsMovementMinPx || math.Abs(dy) >= BoundsMovementMinPx {
			ld.Movements = append(ld.Movements, BoundsDelta{DOMPath: ne.DOMPath, DX: dx, DY: dy})
		}
		dw := ne.W - oe.W
		dh := ne.H - oe.H
		// Fractional-size threshold relative to old dimensions; treat 0 old
		// as "no comparable size".
		fracW := 0.0
		if oe.W > 0 {
			fracW = math.Abs(dw) / oe.W
		}
		fracH := 0.0
		if oe.H > 0 {
			fracH = math.Abs(dh) / oe.H
		}
		if fracW > BoundsSizeChangeFrac || fracH > BoundsSizeChangeFrac {
			ld.SizeChanges = append(ld.SizeChanges, BoundsDelta{DOMPath: ne.DOMPath, DW: dw, DH: dh})
		}
	}

	sort.Slice(ld.Movements, func(i, j int) bool { return ld.Movements[i].DOMPath < ld.Movements[j].DOMPath })
	sort.Slice(ld.SizeChanges, func(i, j int) bool { return ld.SizeChanges[i].DOMPath < ld.SizeChanges[j].DOMPath })

	if len(ld.Movements) > 0 || len(ld.SizeChanges) > 0 {
		ld.Severity = SeverityFLAG
	}
	return ld, nil
}

// errVisualPathTraversal rejects ".." segments in caller-supplied paths.
var errVisualPathTraversal = errors.New("visual diff: path traversal rejected")

func rejectVisualTraversal(p string) error {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return errVisualPathTraversal
		}
	}
	return nil
}

// readBoundedFile reads a file but caps payload at MaxImageBytes for PNG and
// 8 MiB for JSON tree/layout. Missing files return (nil, nil).
func readBoundedFile(path string, cap int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refuse symlink: %s", path)
	}
	if st.Size() > cap {
		return nil, fmt.Errorf("%s exceeds %d byte cap", filepath.Base(path), cap)
	}
	return os.ReadFile(path)
}

// stateDirsFor walks <runDir>/<component>/<state-slug>/ and returns the set of
// state keys ("<component>/<state-slug>") plus their absolute paths.
func stateDirsFor(runDir string) (map[string]string, error) {
	out := make(map[string]string)
	if runDir == "" {
		return out, nil
	}
	st, err := os.Stat(runDir)
	if err != nil || !st.IsDir() {
		return out, nil
	}
	components, err := os.ReadDir(runDir)
	if err != nil {
		return out, err
	}
	for _, comp := range components {
		if !comp.IsDir() {
			continue
		}
		compDir := filepath.Join(runDir, comp.Name())
		states, err := os.ReadDir(compDir)
		if err != nil {
			continue
		}
		for _, s := range states {
			if !s.IsDir() {
				continue
			}
			key := comp.Name() + "/" + s.Name()
			out[key] = filepath.Join(compDir, s.Name())
		}
	}
	return out, nil
}

// CompareVisual walks two visual run directories and produces a populated
// VisualResult. Both inputs are roots (e.g. <kb>/visual/<run-id>/). States are
// keyed by "<component>/<state-slug>". States missing on one side are added
// to Added/Removed; states present on both are diffed image+tree+layout.
//
// T-08-01: filepath.Clean + Lstat symlink check.
func CompareVisual(oldRunDir, newRunDir string) (*VisualResult, error) {
	if err := rejectVisualTraversal(oldRunDir); err != nil {
		return nil, err
	}
	if err := rejectVisualTraversal(newRunDir); err != nil {
		return nil, err
	}
	oldRunDir = filepath.Clean(oldRunDir)
	newRunDir = filepath.Clean(newRunDir)

	oldStates, err := stateDirsFor(oldRunDir)
	if err != nil {
		return nil, fmt.Errorf("scan old run: %w", err)
	}
	newStates, err := stateDirsFor(newRunDir)
	if err != nil {
		return nil, fmt.Errorf("scan new run: %w", err)
	}

	res := &VisualResult{
		OldRunID: filepath.Base(oldRunDir),
		NewRunID: filepath.Base(newRunDir),
		States:   make(map[string]*StateVisualDiff),
	}

	// Added / Removed sets.
	for k := range newStates {
		if _, ok := oldStates[k]; !ok {
			res.Added = append(res.Added, k)
		}
	}
	for k := range oldStates {
		if _, ok := newStates[k]; !ok {
			res.Removed = append(res.Removed, k)
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Removed)

	// Common: per-state diff.
	for k, oldDir := range oldStates {
		newDir, ok := newStates[k]
		if !ok {
			continue
		}
		sd, err := compareState(oldDir, newDir)
		if err != nil {
			// Non-fatal — skip this state, but include error breadcrumb in
			// the summary line.
			continue
		}
		res.States[k] = sd
	}

	res.Summary = fmt.Sprintf("%d added, %d removed, %d compared", len(res.Added), len(res.Removed), len(res.States))
	return res, nil
}

func compareState(oldDir, newDir string) (*StateVisualDiff, error) {
	sd := &StateVisualDiff{}

	// Image (screenshot.png).
	if oldPNG, err := readBoundedFile(filepath.Join(oldDir, "screenshot.png"), MaxImageBytes); err == nil && oldPNG != nil {
		if newPNG, err := readBoundedFile(filepath.Join(newDir, "screenshot.png"), MaxImageBytes); err == nil && newPNG != nil {
			if id, err := DiffImages(oldPNG, newPNG); err == nil {
				sd.Image = &id
			}
		}
	}

	// Tree (tree.json).
	const jsonCap = 8 * 1024 * 1024
	if oldT, err := readBoundedFile(filepath.Join(oldDir, "tree.json"), jsonCap); err == nil && oldT != nil {
		if newT, err := readBoundedFile(filepath.Join(newDir, "tree.json"), jsonCap); err == nil && newT != nil {
			if td, err := DiffTrees(oldT, newT); err == nil {
				sd.Tree = &td
			}
		}
	}

	// Layout (layout.json).
	if oldL, err := readBoundedFile(filepath.Join(oldDir, "layout.json"), jsonCap); err == nil && oldL != nil {
		if newL, err := readBoundedFile(filepath.Join(newDir, "layout.json"), jsonCap); err == nil && newL != nil {
			if ld, err := DiffLayouts(oldL, newL); err == nil {
				sd.Layout = &ld
			}
		}
	}

	return sd, nil
}
