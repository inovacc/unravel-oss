//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package kbenrich_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// TestPendingModulesNamedOnlyHonorsSyntheticName is the T0.3 convergence proof:
// the MCP PendingModules named-only filter must reach PARITY with the CLI's
// eligibleNameSQL (enrich.go:90-93) — a placeholder name (teams_module_NNN)
// with a backfilled synthetic_name is ELIGIBLE (rescued by `knowledge
// synth-names`), while a placeholder without one stays excluded. Pre-fix this
// FAILED because external.go hand-rolled only the four semantic-name
// predicates and never referenced synthetic_name, so synth-names rescued
// placeholders on the CLI path but not on the MCP/supervisor path.
func TestPendingModulesNamedOnlyHonorsSyntheticName(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	const app = "synthtest"

	seed := func(name string, synth any) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO modules (app, name, body_excerpt, body_sha256, synthetic_name)
			VALUES ($1, $2, 'function x(){}', $3, $4)`,
			app, name, "sha-"+name, synth); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	seed("RealService", nil)                     // semantic name → eligible
	seed("teams_module_1", nil)                  // bare placeholder → excluded
	seed("teams_module_2", "DerivedChatService") // placeholder RESCUED by synth name

	ctx := context.Background()

	got, err := kbenrich.PendingModules(ctx, db, app, 10, true /*namedOnly*/, false)
	if err != nil {
		t.Fatalf("PendingModules namedOnly: %v", err)
	}
	names := map[string]bool{}
	for _, m := range got {
		names[m.Name] = true
	}
	if !names["RealService"] {
		t.Errorf("named-only must include semantic name RealService; got %v", t03Keys(names))
	}
	if !names["teams_module_2"] {
		t.Errorf("named-only must RESCUE synth-named placeholder teams_module_2 "+
			"(parity with CLI eligibleNameSQL); got %v", t03Keys(names))
	}
	if names["teams_module_1"] {
		t.Errorf("named-only must EXCLUDE bare placeholder teams_module_1; got %v", t03Keys(names))
	}

	all, err := kbenrich.PendingModules(ctx, db, app, 10, false /*namedOnly*/, false)
	if err != nil {
		t.Fatalf("PendingModules all: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("named_only=false must return all 3 modules, got %d (%v)", len(all), namesOf(all))
	}
}

func t03Keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func namesOf(ms []kbenrich.PendingModule) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}
