//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for `unravel kb merge`. Boots a Postgres testcontainer
via pkg/knowledge/kb/dbtest with all migrations applied, seeds kb_apps +
knowledge_sources rows, then executes the CLI through rootCmd. Covers:

  - Happy path: merge succeeds, alias row inserted, knowledge_sources
    rewritten, loser kb_apps deleted.
  - Alias-chain rejection: winner that is itself a stale alias is refused.
  - Unknown-loser rejection: merge against a non-existent loser fails.

Default `go test ./cmd/...` skips this file via the `integration` build tag.
*/

package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// seedKBApp inserts a minimal kb_apps row. Mirrors the helper in the
// identity integration test suite.
func seedKBApp(t *testing.T, db *sql.DB, kbID, displayName string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform,
		                      first_seen_at, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		kbID, strings.ToLower(displayName), displayName, "windows-msix",
		time.Now().Unix(), time.Now().Unix(),
	)
	if err != nil {
		t.Fatalf("seed kb_apps %s: %v", kbID, err)
	}
}

// seedKnowledgeSource inserts a knowledge_sources row tied to kb_id.
func seedKnowledgeSource(t *testing.T, db *sql.DB, kbID, ksID string, epoch int64) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO knowledge_sources
		   (app, source_path, source_kind, captured_at, app_version, epoch, kb_id, ks_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		"app-"+kbID, "/tmp/seed/"+ksID, "other",
		time.Now().UnixMilli(), "v1", epoch, kbID, ksID,
	)
	if err != nil {
		t.Fatalf("seed knowledge_sources %s/%s: %v", kbID, ksID, err)
	}
}

// resetKbMergeFlags clears package-global flag state between subtests so
// rootCmd doesn't leak --reason / --by / --dry-run from a previous invocation.
func resetKbMergeFlags() {
	kbMergeBy = ""
	kbMergeReason = ""
	kbMergeDryRun = false
}

// runRoot executes rootCmd with the given argv, capturing stdout/stderr.
func runRoot(t *testing.T, argv ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(argv)
	err := rootCmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestKbMerge_HappyPath(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	ctx := context.Background()

	loser := "aaaa1111aaaa1111"
	winner := "bbbb2222bbbb2222"
	seedKBApp(t, db, loser, "Loser App")
	seedKBApp(t, db, winner, "Winner App")
	seedKnowledgeSource(t, db, loser, "ks-1", 1)
	seedKnowledgeSource(t, db, loser, "ks-2", 2)
	seedKnowledgeSource(t, db, loser, "ks-3", 3)

	resetKbMergeFlags()
	pinDSNViaConfig(t, dsn)
	stdout, stderr, err := runRoot(t,
		"kb", "ops", "merge", loser, winner,
		"--by", "analyst",
		"--reason", "cert rotation",
	)
	if err != nil {
		t.Fatalf("execute: %v\nstdout=%q\nstderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "merged:") {
		t.Errorf("stdout missing 'merged:': %q", stdout)
	}
	if !strings.Contains(stdout, "updated=3") {
		t.Errorf("stdout missing 'updated=3': %q", stdout)
	}

	// kb_aliases row present.
	var aliasCanonical, aliasReason, aliasBy string
	if err := db.QueryRowContext(ctx,
		`SELECT canonical_kb_id, reason, merged_by FROM kb_aliases WHERE alias_kb_id = $1`,
		loser,
	).Scan(&aliasCanonical, &aliasReason, &aliasBy); err != nil {
		t.Fatalf("select kb_aliases: %v", err)
	}
	if aliasCanonical != winner {
		t.Errorf("kb_aliases.canonical_kb_id = %q want %q", aliasCanonical, winner)
	}
	if aliasReason != "cert rotation" {
		t.Errorf("kb_aliases.reason = %q want 'cert rotation'", aliasReason)
	}
	if aliasBy != "analyst" {
		t.Errorf("kb_aliases.merged_by = %q want 'analyst'", aliasBy)
	}

	// knowledge_sources rewritten to winner.
	var ksWinner int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM knowledge_sources WHERE kb_id = $1`, winner,
	).Scan(&ksWinner); err != nil {
		t.Fatalf("count knowledge_sources(winner): %v", err)
	}
	if ksWinner != 3 {
		t.Errorf("knowledge_sources(winner) = %d want 3", ksWinner)
	}

	// Loser kb_apps row deleted.
	var loserKBApps int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM kb_apps WHERE kb_id = $1`, loser,
	).Scan(&loserKBApps); err != nil {
		t.Fatalf("count kb_apps(loser): %v", err)
	}
	if loserKBApps != 0 {
		t.Errorf("kb_apps(loser) = %d want 0", loserKBApps)
	}
}

func TestKbMerge_AliasChainRejected(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	ctx := context.Background()

	loser := "cccc1111cccc1111"
	winner := "dddd2222dddd2222"    // already a stale alias
	canonical := "eeee3333eeee3333" // the real canonical

	seedKBApp(t, db, loser, "Loser")
	seedKBApp(t, db, canonical, "Canonical")
	// winner is NOT inserted into kb_apps because the merge that turned it
	// into an alias would have deleted it. We only need the alias row.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO kb_aliases (alias_kb_id, canonical_kb_id, merged_at, merged_by, reason)
		 VALUES ($1, $2, $3, $4, $5)`,
		winner, canonical, time.Now().Unix(), "prior-analyst", "earlier merge",
	); err != nil {
		t.Fatalf("seed kb_aliases: %v", err)
	}

	resetKbMergeFlags()
	pinDSNViaConfig(t, dsn)
	stdout, stderr, err := runRoot(t,
		"kb", "ops", "merge", loser, winner,
		"--by", "analyst",
	)
	if err == nil {
		t.Fatalf("expected error, got nil\nstdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "winner is itself a stale alias") {
		t.Fatalf("unexpected error: %v", err)
	}

	// DB unchanged: no new kb_aliases row for loser.
	var loserAliases int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM kb_aliases WHERE alias_kb_id = $1`, loser,
	).Scan(&loserAliases); err != nil {
		t.Fatalf("count kb_aliases(loser): %v", err)
	}
	if loserAliases != 0 {
		t.Errorf("kb_aliases(loser) = %d want 0", loserAliases)
	}
}

func TestKbMerge_UnknownLoser(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	ctx := context.Background()

	winner := "ffff2222ffff2222"
	seedKBApp(t, db, winner, "Winner")

	resetKbMergeFlags()
	pinDSNViaConfig(t, dsn)
	stdout, stderr, err := runRoot(t,
		"kb", "ops", "merge", "ghost-loser-id", winner,
		"--by", "analyst",
	)
	if err == nil {
		t.Fatalf("expected error, got nil\nstdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(err.Error(), "loser kb_id not found") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Winner still present; no aliases inserted.
	var winnerCount, aliasCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM kb_apps WHERE kb_id = $1`, winner,
	).Scan(&winnerCount); err != nil {
		t.Fatalf("count kb_apps(winner): %v", err)
	}
	if winnerCount != 1 {
		t.Errorf("kb_apps(winner) = %d want 1", winnerCount)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM kb_aliases`,
	).Scan(&aliasCount); err != nil {
		t.Fatalf("count kb_aliases: %v", err)
	}
	if aliasCount != 0 {
		t.Errorf("kb_aliases = %d want 0", aliasCount)
	}
}
