/*
Copyright (c) 2026 Security Research

Tests for the --classifier mode selector. Phase 45 / LLMC-02.
D-45-CLASSIFY-FALLBACK-ORDER is the load-bearing decision under test.
*/
package classify

import (
	"context"
	"testing"
)

func TestSelect_Modes(t *testing.T) {
	type tc struct {
		mode     string
		hasCap   bool
		wantName string
		wantErr  bool
	}
	cases := []tc{
		{"rule", false, "rule", false},
		{"rule", true, "rule", false},
		{"mcp", false, "mcp", false}, // explicit: no fallback even when no capability
		{"mcp", true, "mcp", false},
		{"", false, "rule", false},     // auto + no cap → rule
		{"auto", false, "rule", false}, // auto + no cap → rule
		{"auto", true, "mcp", false},   // auto + cap → composite (Name() == primary "mcp")
		{"bogus", false, "", true},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			opts := SelectOptions{
				Mode:        c.mode,
				HasSampling: func(context.Context) bool { return c.hasCap },
				MCPClient:   func() ClassifyMCPClient { return NilClassifyMCPClient() },
			}
			clf, _, err := Select(context.Background(), opts)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for mode %q", c.mode)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if clf.Name() != c.wantName {
				t.Fatalf("Name = %q; want %q", clf.Name(), c.wantName)
			}
		})
	}
}

// TestSelect_AutoSourceTagging verifies the source string for one-shot logs.
func TestSelect_AutoSourceTagging(t *testing.T) {
	_, src, err := Select(context.Background(), SelectOptions{Mode: "auto"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if src != "auto" {
		t.Fatalf("src = %q; want auto", src)
	}
	_, src, err = Select(context.Background(), SelectOptions{Mode: "rule"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if src != "flag" {
		t.Fatalf("src = %q; want flag", src)
	}
}
