/*
Copyright (c) 2026 Security Research
*/
package pipeline

import "testing"

func TestBuildCFG_Empty(t *testing.T) {
	nodes, err := BuildCFG(nil)
	if err != nil {
		t.Fatalf("BuildCFG(nil): %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("nil input: got %d nodes, want 0", len(nodes))
	}
}

func TestFindReachable_Empty(t *testing.T) {
	got := FindReachable(nil)
	if len(got) != 0 {
		t.Errorf("nil input: got %d, want 0", len(got))
	}
}

func TestLinkUnlink(t *testing.T) {
	a := NewInstrNode(0, nil)
	b := NewInstrNode(1, nil)
	if a == nil || b == nil {
		t.Fatal("NewInstrNode returned nil")
	}
	Link(a, b)
	Unlink(a, b)
}
