package rearm

import (
	"strings"
	"testing"
)

func TestRankAndBound(t *testing.T) {
	in := []Candidate{
		{ModuleRef: "a", Signal: 50, Size: 100},
		{ModuleRef: "b", Signal: 90, Size: 100},
		{ModuleRef: "big", Signal: 99, Size: 999999},
		{ModuleRef: "c", Signal: 70, Size: 100},
	}
	b := Bounds{MaxModules: 2, MaxModuleBytes: 1000, MaxTotalTokens: 1_000_000}
	got := RankAndBound(in, b)
	if len(got) != 2 || got[0].ModuleRef != "b" || got[1].ModuleRef != "c" {
		t.Fatalf("want [b,c] (oversize 'big' dropped, top-2 by signal), got %+v", got)
	}
}

func TestRankAndBound_TokenCap(t *testing.T) {
	in := []Candidate{
		{ModuleRef: "x", Signal: 90, Size: 4000, Source: strings.Repeat("x", 4000)},
		{ModuleRef: "y", Signal: 80, Size: 4000, Source: strings.Repeat("y", 4000)},
	}
	got := RankAndBound(in, Bounds{MaxModules: 10, MaxModuleBytes: 1 << 20, MaxTotalTokens: 1000})
	if len(got) != 1 || got[0].ModuleRef != "x" {
		t.Fatalf("token cap must stop after first, got %+v", got)
	}
}
