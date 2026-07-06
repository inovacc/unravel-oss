//go:build integration

/*
Copyright (c) 2026 Security Research

Shared integration-test helpers for the kbstore package. Consolidated here
to avoid duplicate declarations across export_test.go, timeline_test.go,
and loop_test.go. Each helper inserts a single row in a deterministic
shape consumed by multiple TestXxx functions.

Two variants are intentionally distinct (different schemas / different
return types), and are exposed under explicit names:

  - seedKBApp        — rich kb_apps row (canonical/display/platform).
  - seedKBAppMinimal — minimal kb_apps row keyed by kb_id only, used by
                       Timeline tests that don't care about identity.
  - seedAppFact      — app_facts row with plain string value, no return.
  - seedAppFactGap   — app_facts row with gap_prompt, returns the new id,
                       used by PullGap/PushAnswer loop tests.
*/

package store_test

import (
	"database/sql"
	"testing"
)

// seedKBApp inserts a rich kb_apps row (used by Export tests).
func seedKBApp(t *testing.T, db *sql.DB, kbID, canonical, displayName, platform string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform,
		                       first_seen_at, last_seen_at, tags, metadata)
		 VALUES ($1, $2, $3, $4, 0, 0, ARRAY[]::text[], '{}'::jsonb)`,
		kbID, canonical, displayName, platform,
	)
	if err != nil {
		t.Fatalf("seed kb_app %q: %v", kbID, err)
	}
}

// seedKBAppMinimal inserts a kb_apps row keyed by kb_id only (used by
// Timeline tests that only need the row to exist).
func seedKBAppMinimal(t *testing.T, db *sql.DB, kbID string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform,
		                       app_count, source_count, aliases, metadata)
		 VALUES ($1, $1, $1, 'android', 0, 0, ARRAY[]::text[], '{}'::jsonb)
		 ON CONFLICT DO NOTHING`,
		kbID,
	)
	if err != nil {
		t.Fatalf("seed kb_app %q: %v", kbID, err)
	}
}

// seedAppFact inserts an app_facts row with a plain string value (used by
// Export tests).
func seedAppFact(t *testing.T, db *sql.DB, app, category, key, value string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO app_facts (app, category, key, value, source_step)
		 VALUES ($1, $2, $3, NULLIF($4,''), 'test')`,
		app, category, key, value,
	)
	if err != nil {
		t.Fatalf("seed app_fact %s/%s/%s: %v", app, category, key, err)
	}
}

// seedAppFactGap inserts an app_facts row with optional value + gap_prompt
// (used by PullGap/PushAnswer loop tests) and returns the new row id.
func seedAppFactGap(t *testing.T, db *sql.DB, app, category, key string, value, gapPrompt sql.NullString) int64 {
	t.Helper()
	var id int64
	err := db.QueryRow(
		`INSERT INTO app_facts (app, category, key, value, gap_prompt, candidates_q)
		 VALUES ($1, $2, $3, $4, $5, '')
		 RETURNING id`,
		app, category, key, value, gapPrompt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed app_facts %s/%s/%s: %v", app, category, key, err)
	}
	return id
}
