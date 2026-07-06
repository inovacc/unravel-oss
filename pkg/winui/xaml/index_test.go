/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

func TestAppendEntry(t *testing.T) {
	idx := &winui.XAMLIndex{}
	AppendEntry(idx, winui.XAMLEntry{Path: "a.xaml", Kind: "raw"})
	AppendEntry(idx, winui.XAMLEntry{Path: "b.xbf", Kind: "xbf"})
	if len(idx.Entries) != 2 {
		t.Fatalf("want 2 entries got %d", len(idx.Entries))
	}
	AppendEntry(nil, winui.XAMLEntry{}) // nil-safe
}

func TestMergeIndexes(t *testing.T) {
	a := &winui.XAMLIndex{
		Entries: []winui.XAMLEntry{
			{Path: "p1.xaml", Kind: "raw", ResourceKeys: []string{"K1"}},
			{Path: "p2.xaml", Kind: "raw"},
		},
		Errors: []string{"a-warn"},
	}
	b := &winui.XAMLIndex{
		Entries: []winui.XAMLEntry{
			{Path: "p1.xaml", Kind: "raw", Errors: []string{"second-pass error"}},
			{Path: "p3.xaml", Kind: "raw"},
		},
		Errors: []string{"b-warn"},
	}
	out := MergeIndexes(a, b)
	if len(out.Entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(out.Entries))
	}
	// p1 first-seen Kind/ResourceKeys preserved; collision Errors appended.
	for _, e := range out.Entries {
		if e.Path == "p1.xaml" {
			if len(e.ResourceKeys) != 1 || e.ResourceKeys[0] != "K1" {
				t.Fatalf("first-seen ResourceKeys lost: %+v", e)
			}
			if len(e.Errors) != 1 || !strings.Contains(e.Errors[0], "second-pass") {
				t.Fatalf("collision errors not appended: %+v", e.Errors)
			}
		}
	}
	if len(out.Errors) != 2 {
		t.Fatalf("want top-level errors concatenated; got %v", out.Errors)
	}
}

func TestDistinctKinds(t *testing.T) {
	idx := &winui.XAMLIndex{Entries: []winui.XAMLEntry{
		{Kind: "raw"}, {Kind: "xbf"}, {Kind: "raw"}, {Kind: "pe-embedded"},
	}}
	got := DistinctKinds(idx)
	if strings.Join(got, ",") != "pe-embedded,raw,xbf" {
		t.Fatalf("want pe-embedded,raw,xbf got %v", got)
	}
}
