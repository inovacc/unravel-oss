//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for the identity merge primitive and parallel-safe epoch
allocator. Boots a Postgres testcontainer via pkg/knowledge/kb/dbtest with
all migrations (000001..000005) applied, then exercises:

  - MergeIDs happy path (kb_aliases insert, knowledge_sources rewrite,
    kb_apps loser delete, returned rowsUpdated).
  - MergeIDs no-chain rejection (winner cannot itself be an alias).
  - ResolveAlias coalesce semantics.
  - 10x parallel AllocateEpoch yields epochs {1..10} with no duplicates
    (PITFALLS-CRIT-4 mitigation).

Default `go test ./...` skips this file via the `integration` build tag.
*/

package identity_test

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

// seedKBApp inserts a minimal kb_apps row with the provided kb_id. Other
// columns get fixed values; tests don't read them back.
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

// seedKnowledgeSource inserts a knowledge_sources row tied to kb_id. Returns
// nothing — tests query by predicate.
func seedKnowledgeSource(t *testing.T, db *sql.DB, kbID, ksID string, epoch int64) {
	t.Helper()
	// knowledge_sources columns from migrations 000002 + 000004:
	//   id (PK, identity), app, captured_at, app_version, epoch, kb_id, ks_id, ...
	// We insert the minimum required.
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

// seedKnowledgeSourceReturningID inserts a knowledge_sources row tied to kb_id
// and returns its surrogate id (needed for kb_scorecards.source_id FK).
func seedKnowledgeSourceReturningID(t *testing.T, db *sql.DB, kbID, ksID string, epoch int64) int64 {
	t.Helper()
	var id int64
	err := db.QueryRow(
		`INSERT INTO knowledge_sources
		   (app, source_path, source_kind, captured_at, app_version, epoch, kb_id, ks_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id`,
		"app-"+kbID, "/tmp/seed/"+ksID, "other",
		time.Now().UnixMilli(), "v1", epoch, kbID, ksID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed knowledge_sources %s/%s: %v", kbID, ksID, err)
	}
	return id
}

// seedScorecard inserts a minimal kb_scorecards row for (kbID, sourceID).
func seedScorecard(t *testing.T, db *sql.DB, kbID string, sourceID int64) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO kb_scorecards
		   (kb_id, source_id, mean_score, dims_at_80, dims_at_50, dims_at_20,
		    loop_exit, citations_ok, iterations, scorecard_json)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		kbID, sourceID, 700, 5, 8, 10, true, true, 3, []byte(`{}`),
	)
	if err != nil {
		t.Fatalf("seed kb_scorecards %s/%d: %v", kbID, sourceID, err)
	}
}

// TestMergeIDsEpochOverlapAndScorecards exercises the identity-fork case: a
// loser whose knowledge_sources epochs (1,2,3) overlap the winner's existing
// epochs (1,2), plus a kb_scorecards row pinned to the loser kb_id. The
// pre-fix MergeIDs blindly rewrote kb_id without re-sequencing epoch (23505 on
// knowledge_sources_kb_epoch_uq) and never repointed kb_scorecards (FK RESTRICT
// on the loser kb_apps delete). Post-fix: loser epochs are offset past the
// winner's max, scorecards follow the kb_id, and the loser kb_apps row is gone.
func TestMergeIDsEpochOverlapAndScorecards(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	loser := "ffff5555ffff5555"
	winner := "eeee4444eeee4444"
	seedKBApp(t, db, loser, "Forked App")
	seedKBApp(t, db, winner, "Forked App")

	// Winner already has epochs 1,2 (the current fork lineage).
	seedKnowledgeSource(t, db, winner, winner+":v1:1", 1)
	seedKnowledgeSource(t, db, winner, winner+":v1:2", 2)

	// Loser has epochs 1,2,3 (legacy lineage) — overlaps winner's 1,2.
	loserKS1 := seedKnowledgeSourceReturningID(t, db, loser, loser+":v1:1", 1)
	seedKnowledgeSource(t, db, loser, loser+":v1:2", 2)
	seedKnowledgeSource(t, db, loser, loser+":v1:3", 3)

	// A scorecard pinned to the loser kb_id (would FK-block the loser delete).
	seedScorecard(t, db, loser, loserKS1)

	rowsUpdated, err := identity.MergeIDs(ctx, db, loser, winner, "tester", "fork collapse")
	if err != nil {
		t.Fatalf("MergeIDs (epoch overlap + scorecard): %v", err)
	}
	if rowsUpdated != 3 {
		t.Fatalf("rowsUpdated = %d want 3", rowsUpdated)
	}

	// Winner now owns all 5 knowledge_sources with a contiguous epoch set
	// {1,2,3,4,5}: its own 1,2 plus the loser's 1,2,3 offset by maxWinner(=2).
	rows, err := db.Query(
		`SELECT epoch FROM knowledge_sources WHERE kb_id = $1 ORDER BY epoch`, winner)
	if err != nil {
		t.Fatalf("query winner epochs: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var got []int64
	for rows.Next() {
		var e int64
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	want := []int64{1, 2, 3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("winner epochs = %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("winner epochs = %v want %v", got, want)
		}
	}

	// Scorecard followed the kb_id rewrite.
	var scKBID string
	if err := db.QueryRow(
		`SELECT kb_id FROM kb_scorecards WHERE source_id = $1`, loserKS1).
		Scan(&scKBID); err != nil {
		t.Fatalf("scorecard lookup: %v", err)
	}
	if scKBID != winner {
		t.Fatalf("kb_scorecards.kb_id = %s want %s", scKBID, winner)
	}

	// Loser kb_apps row deleted (FK no longer blocked).
	var loserKBApps int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM kb_apps WHERE kb_id = $1`, loser).
		Scan(&loserKBApps); err != nil {
		t.Fatalf("count kb_apps loser: %v", err)
	}
	if loserKBApps != 0 {
		t.Fatalf("kb_apps(loser) = %d want 0", loserKBApps)
	}
}

func TestMergeIDsHappyPath(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	loser := "aaaa1111aaaa1111"
	winner := "bbbb2222bbbb2222"
	seedKBApp(t, db, loser, "Loser App")
	seedKBApp(t, db, winner, "Winner App")
	seedKnowledgeSource(t, db, loser, loser+":v1:1", 1)
	seedKnowledgeSource(t, db, loser, loser+":v1:2", 2)

	rowsUpdated, err := identity.MergeIDs(ctx, db, loser, winner, "tester", "dup detected")
	if err != nil {
		t.Fatalf("MergeIDs: %v", err)
	}
	if rowsUpdated != 2 {
		t.Fatalf("rowsUpdated = %d want 2", rowsUpdated)
	}

	// kb_aliases row exists.
	var canonical, mergedBy, reason string
	if err := db.QueryRow(
		`SELECT canonical_kb_id, merged_by, reason FROM kb_aliases WHERE alias_kb_id = $1`,
		loser).Scan(&canonical, &mergedBy, &reason); err != nil {
		t.Fatalf("alias lookup: %v", err)
	}
	if canonical != winner || mergedBy != "tester" || reason != "dup detected" {
		t.Fatalf("alias row mismatch: canonical=%s mergedBy=%s reason=%s",
			canonical, mergedBy, reason)
	}

	// knowledge_sources rows now point at winner.
	var ksCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM knowledge_sources WHERE kb_id = $1`, winner).
		Scan(&ksCount); err != nil {
		t.Fatalf("count ks winner: %v", err)
	}
	if ksCount != 2 {
		t.Fatalf("knowledge_sources(winner) = %d want 2", ksCount)
	}

	// Loser kb_apps row gone.
	var loserKBApps int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM kb_apps WHERE kb_id = $1`, loser).
		Scan(&loserKBApps); err != nil {
		t.Fatalf("count kb_apps loser: %v", err)
	}
	if loserKBApps != 0 {
		t.Fatalf("kb_apps(loser) = %d want 0", loserKBApps)
	}
}

func TestMergeIDsRejectsChain(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	first := "1111111111111111"
	second := "2222222222222222"
	third := "3333333333333333"
	seedKBApp(t, db, first, "First")
	seedKBApp(t, db, second, "Second")
	seedKBApp(t, db, third, "Third")

	// First merge: first → second (legitimate).
	if _, err := identity.MergeIDs(ctx, db, first, second, "u", ""); err != nil {
		t.Fatalf("first merge: %v", err)
	}

	// Second merge attempts to use `first` (now a stale alias) as winner.
	_, err := identity.MergeIDs(ctx, db, third, first, "u", "")
	if err == nil {
		t.Fatalf("expected stale-alias rejection, got nil")
	}
	if !strings.Contains(err.Error(), "winner is a stale alias") {
		t.Fatalf("unexpected error: %v", err)
	}

	// No new alias row created; third still has its kb_apps row.
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM kb_aliases WHERE alias_kb_id = $1`, third).Scan(&n); err != nil {
		t.Fatalf("alias count: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected no alias row for third, got %d", n)
	}
}

func TestResolveAlias(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	loser := "aaaa0000aaaa0000"
	winner := "bbbb0000bbbb0000"
	seedKBApp(t, db, loser, "L")
	seedKBApp(t, db, winner, "W")
	if _, err := identity.MergeIDs(ctx, db, loser, winner, "", ""); err != nil {
		t.Fatalf("merge: %v", err)
	}

	got, err := identity.ResolveAlias(ctx, db, loser)
	if err != nil {
		t.Fatalf("ResolveAlias loser: %v", err)
	}
	if got != winner {
		t.Fatalf("ResolveAlias(loser) = %s want %s", got, winner)
	}

	got, err = identity.ResolveAlias(ctx, db, "nonexistent-id")
	if err != nil {
		t.Fatalf("ResolveAlias nonexistent: %v", err)
	}
	if got != "nonexistent-id" {
		t.Fatalf("ResolveAlias passthrough mismatch: %s", got)
	}
}

func TestAllocateEpochParallel(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	kbID := "cccc3333cccc3333"
	seedKBApp(t, db, kbID, "Parallel App")

	const N = 10
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if err != nil {
				errs <- err
				return
			}
			epoch, err := identity.AllocateEpoch(ctx, tx, kbID)
			if err != nil {
				_ = tx.Rollback()
				errs <- err
				return
			}
			ksID := kbID + ":v1:" + intToStr(epoch)
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO knowledge_sources
				   (app, source_path, source_kind, captured_at, app_version, epoch, kb_id, ks_id)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				"app-parallel", "/tmp/parallel/"+ksID, "other",
				time.Now().UnixMilli()+int64(i), "v1", epoch, kbID, ksID); err != nil {
				_ = tx.Rollback()
				errs <- err
				return
			}
			if err := tx.Commit(); err != nil {
				errs <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("goroutine err: %v", e)
		}
	}

	// Read back epochs and assert {1..10} exact.
	rows, err := db.Query(
		`SELECT epoch FROM knowledge_sources WHERE kb_id = $1 ORDER BY epoch`, kbID)
	if err != nil {
		t.Fatalf("query epochs: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var got []int64
	for rows.Next() {
		var e int64
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	if len(got) != N {
		t.Fatalf("epoch row count = %d want %d", len(got), N)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	for i, e := range got {
		if e != int64(i+1) {
			t.Fatalf("epoch[%d] = %d want %d (full set: %v)", i, e, i+1, got)
		}
	}
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
