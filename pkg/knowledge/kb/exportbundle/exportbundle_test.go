package exportbundle

import "testing"

func TestBodyPath(t *testing.T) {
	got := BodyPath("deadbeefcafef00d")
	if got != "bodies/de/deadbeefcafef00d.txt" {
		t.Fatalf("BodyPath = %q", got)
	}
	if BodyPath("ab") != "bodies/ab/ab.txt" {
		t.Fatalf("short sha path = %q", BodyPath("ab"))
	}
	if BodyPath("") != "" {
		t.Fatalf("empty sha must yield empty path")
	}
	if BodyPath("deadbeef") != BodyPath("deadbeef") {
		t.Fatal("not deterministic")
	}
}

func TestBudget(t *testing.T) {
	b := &Budget{Limit: 2, MaxBytes: 100}
	if !b.Add(40) || b.Truncated {
		t.Fatal("first add within budget")
	}
	if !b.Add(40) || b.Truncated {
		t.Fatal("second add within budget (count=2, bytes=80)")
	}
	if b.Add(40) || !b.Truncated { // 3rd exceeds Limit=2
		t.Fatal("limit exceeded must return false + Truncated")
	}
	b2 := &Budget{Limit: 0, MaxBytes: 50} // Limit 0 = unlimited count
	if !b2.Add(50) || b2.Truncated {
		t.Fatal("exactly MaxBytes ok")
	}
	if b2.Add(1) || !b2.Truncated {
		t.Fatal("over MaxBytes must truncate")
	}
}
