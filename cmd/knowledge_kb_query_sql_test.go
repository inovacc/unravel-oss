package cmd

import (
	"strings"
	"testing"
)

// T0.1 regression: the KB runs on Postgres (pgx). SQLite-style "?" placeholders
// are invalid there ("?" is a JSON operator token), so a filtered facts/gaps
// query produced SQLSTATE 42601 "syntax error at/near ORDER". These tests pin
// the query builders to positional "$N" placeholders and guard against "?"
// ever returning, and confirm WHERE fragments precede ORDER BY.
func TestBuildFactsQuery(t *testing.T) {
	tests := []struct {
		name      string
		app, cat  string
		wantArgs  []any
		wantSubs  []string // ordered substrings that must appear in this order
		wantNoSub []string
	}{
		{
			name:      "no filter",
			wantArgs:  nil,
			wantSubs:  []string{"WHERE value IS NOT NULL", "ORDER BY app, category, key"},
			wantNoSub: []string{"?", "$1"},
		},
		{
			name:     "app only",
			app:      "cluely",
			wantArgs: []any{"cluely"},
			wantSubs: []string{"AND app = $1", "ORDER BY app, category, key"},
		},
		{
			name:     "category only",
			cat:      "network",
			wantArgs: []any{"network"},
			wantSubs: []string{"AND category = $1", "ORDER BY app, category, key"},
		},
		{
			name:     "app and category",
			app:      "cluely",
			cat:      "network",
			wantArgs: []any{"cluely", "network"},
			wantSubs: []string{"AND app = $1", "AND category = $2", "ORDER BY app, category, key"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, args := buildFactsQuery(tt.app, tt.cat)
			assertQuery(t, q, args, tt.wantArgs, tt.wantSubs, tt.wantNoSub)
			assertWhereBeforeOrder(t, q)
		})
	}
}

func TestBuildGapsQuery(t *testing.T) {
	tests := []struct {
		name     string
		app, cat string
		wantArgs []any
		wantSubs []string
	}{
		{"no filter", "", "", nil, []string{"WHERE value IS NULL", "ORDER BY app, category, key"}},
		{"app only", "teams", "", []any{"teams"}, []string{"AND app = $1"}},
		{"app and category", "teams", "auth", []any{"teams", "auth"}, []string{"AND app = $1", "AND category = $2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, args := buildGapsQuery(tt.app, tt.cat)
			assertQuery(t, q, args, tt.wantArgs, tt.wantSubs, nil)
			assertWhereBeforeOrder(t, q)
			if strings.Contains(q, "?") {
				t.Errorf("gaps query must not contain SQLite '?' placeholder: %q", q)
			}
		})
	}
}

func assertQuery(t *testing.T, q string, gotArgs, wantArgs []any, wantSubs, wantNoSub []string) {
	t.Helper()
	if strings.Contains(q, "?") {
		t.Errorf("query must not contain SQLite '?' placeholder (Postgres uses $N): %q", q)
	}
	if len(gotArgs) != len(wantArgs) {
		t.Fatalf("arg count: got %d (%v), want %d (%v)", len(gotArgs), gotArgs, len(wantArgs), wantArgs)
	}
	for i := range wantArgs {
		if gotArgs[i] != wantArgs[i] {
			t.Errorf("arg[%d]: got %v, want %v", i, gotArgs[i], wantArgs[i])
		}
	}
	prev := -1
	for _, sub := range wantSubs {
		idx := strings.Index(q, sub)
		if idx < 0 {
			t.Errorf("query missing %q: %q", sub, q)
			continue
		}
		if idx < prev {
			t.Errorf("substring %q appears out of expected order in %q", sub, q)
		}
		prev = idx
	}
	for _, sub := range wantNoSub {
		if strings.Contains(q, sub) {
			t.Errorf("query unexpectedly contains %q: %q", sub, q)
		}
	}
}

func assertWhereBeforeOrder(t *testing.T, q string) {
	t.Helper()
	w := strings.Index(q, "WHERE")
	o := strings.Index(q, "ORDER BY")
	if w < 0 || o < 0 || w > o {
		t.Errorf("WHERE must precede ORDER BY: %q", q)
	}
}
