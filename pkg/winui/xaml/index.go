/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"sort"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// AppendEntry appends e to idx in O(1).
func AppendEntry(idx *winui.XAMLIndex, e winui.XAMLEntry) {
	if idx == nil {
		return
	}
	idx.Entries = append(idx.Entries, e)
}

// MergeIndexes returns a new index whose entries are deduped by Path,
// preserving the first-seen Kind/ResourceKeys/ControlTypes/Bindings. On
// collision, the second entry's Errors are appended to the first entry's
// audit trail. Top-level Errors from both inputs are concatenated.
func MergeIndexes(dst, src *winui.XAMLIndex) *winui.XAMLIndex {
	out := &winui.XAMLIndex{Entries: []winui.XAMLEntry{}}
	pos := map[string]int{}
	add := func(e winui.XAMLEntry) {
		if i, ok := pos[e.Path]; ok {
			out.Entries[i].Errors = append(out.Entries[i].Errors, e.Errors...)
			return
		}
		pos[e.Path] = len(out.Entries)
		out.Entries = append(out.Entries, e)
	}
	if dst != nil {
		for _, e := range dst.Entries {
			add(e)
		}
		out.Errors = append(out.Errors, dst.Errors...)
	}
	if src != nil {
		for _, e := range src.Entries {
			add(e)
		}
		out.Errors = append(out.Errors, src.Errors...)
	}
	return out
}

// DistinctKinds returns the sorted set of Kind values present in idx.
func DistinctKinds(idx *winui.XAMLIndex) []string {
	if idx == nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, e := range idx.Entries {
		if e.Kind != "" {
			seen[e.Kind] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
