package cmd

import "testing"

func TestSelectGCEmptyQuery(t *testing.T) {
	// The empty-only selector must restrict to sources with no module refs
	// and (when --app set) to a single kb_id. Assert the SQL shape so a future
	// edit can't silently widen the blast radius to non-empty epochs.
	q := buildEmptyGCQuery("linkedin")
	for _, must := range []string{
		"knowledge_sources",
		"NOT EXISTS",
		"module_app_refs",
		"kb_id = $1",
	} {
		if !contains(q, must) {
			t.Fatalf("empty-gc query missing %q:\n%s", must, q)
		}
	}
	// Must NOT contain an unbounded delete.
	if contains(q, "DELETE FROM knowledge_sources\n") && !contains(q, "WHERE") {
		t.Fatal("empty-gc query is unbounded")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
