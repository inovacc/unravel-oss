package cmd

import (
	"strings"
	"testing"
)

// DB-free guards on the backfill query builders: Postgres $N placeholders
// (never SQLite ?), correct app-filter placement, and the key clauses that
// make the backfill safe (only pending, non-human-flagged, non-empty-sha rows;
// representative is an enriched sibling).
func TestBuildBackfillCountQuery(t *testing.T) {
	q, args := buildBackfillCountQuery("")
	if len(args) != 0 {
		t.Errorf("no-app: want 0 args, got %v", args)
	}
	for _, sub := range []string{"p.summary IS NULL", "p.body_sha256 <> ''", "e.summary IS NOT NULL", "e.id <> p.id"} {
		if !strings.Contains(q, sub) {
			t.Errorf("count query missing %q: %q", sub, q)
		}
	}
	if strings.Contains(q, "?") {
		t.Errorf("count query must not contain SQLite '?': %q", q)
	}

	q2, args2 := buildBackfillCountQuery("teams")
	if len(args2) != 1 || args2[0] != "teams" {
		t.Errorf("app filter: want [teams], got %v", args2)
	}
	if !strings.Contains(q2, "p.app = $1") {
		t.Errorf("app filter must bind $1: %q", q2)
	}
}

func TestBuildBackfillEnrichInsert(t *testing.T) {
	q, args := buildBackfillEnrichInsert("", 123)
	if len(args) != 1 || args[0].(int64) != 123 {
		t.Errorf("ts must bind as $1, got %v", args)
	}
	for _, sub := range []string{"$1", "ON CONFLICT(module_id) DO NOTHING", "NOT EXISTS", "p.summary IS NULL", "DISTINCT ON (m.body_sha256)"} {
		if !strings.Contains(q, sub) {
			t.Errorf("enrich insert missing %q", sub)
		}
	}
	if strings.Contains(q, "?") {
		t.Errorf("enrich insert must not contain '?': %q", q)
	}

	q2, args2 := buildBackfillEnrichInsert("teams", 123)
	if len(args2) != 2 || args2[1] != "teams" {
		t.Errorf("app filter: want [123 teams], got %v", args2)
	}
	if !strings.Contains(q2, "p.app = $2") {
		t.Errorf("app filter must bind $2 (after ts=$1): %q", q2)
	}
}

func TestBuildBackfillSummaryUpdate(t *testing.T) {
	q, args := buildBackfillSummaryUpdate("")
	if len(args) != 0 {
		t.Errorf("no-app: want 0 args, got %v", args)
	}
	for _, sub := range []string{"UPDATE modules p SET summary = rep.summary, tags = rep.tags", "p.summary IS NULL", "p.body_sha256 <> ''"} {
		if !strings.Contains(q, sub) {
			t.Errorf("summary update missing %q", sub)
		}
	}

	q2, args2 := buildBackfillSummaryUpdate("wa")
	if len(args2) != 1 || args2[0] != "wa" {
		t.Errorf("app filter: want [wa], got %v", args2)
	}
	if !strings.Contains(q2, "p.app = $1") {
		t.Errorf("app filter must bind $1: %q", q2)
	}
}
