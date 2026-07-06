//go:build integration

package backfill_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/backfill"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestBackfill_LinksToExistingKBIDByCanonicalName(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	const dissectKBID = "519eea5f2ea18485"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform, package_id, first_seen_at, last_seen_at)
		VALUES ($1, 'cluely', 'Cluely', 'win32', 'com.cluely.app', 0, 0)`, dissectKBID); err != nil {
		t.Fatalf("seed kb_apps: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO knowledge_sources (app, epoch, source_path, source_kind, captured_at)
		VALUES ('cluely', 1, '/cache', 'cache', 0)`); err != nil {
		t.Fatalf("seed knowledge_sources: %v", err)
	}

	if _, err := backfill.Run(ctx, db, backfill.Options{}); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	var got string
	if err := db.QueryRowContext(ctx,
		`SELECT kb_id FROM knowledge_sources WHERE app='cluely' AND epoch=1`).Scan(&got); err != nil {
		t.Fatalf("read kb_id: %v", err)
	}
	if got != dissectKBID {
		t.Fatalf("want linked kb_id %s, got minted %s", dissectKBID, got)
	}

	var apps int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM kb_apps WHERE canonical_name='cluely'`).Scan(&apps); err != nil {
		t.Fatalf("count apps: %v", err)
	}
	if apps != 1 {
		t.Fatalf("want exactly 1 cluely kb_app (linked), got %d", apps)
	}
}

func TestBackfill_MintsWhenNoMatch(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO knowledge_sources (app, epoch, source_path, source_kind, captured_at)
		VALUES ('orphan', 1, '/c', 'cache', 0)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := backfill.Run(ctx, db, backfill.Options{}); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var apps int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM kb_apps WHERE canonical_name='orphan'`).Scan(&apps); err != nil {
		t.Fatalf("count: %v", err)
	}
	if apps != 1 {
		t.Fatalf("want 1 minted orphan kb_app, got %d", apps)
	}
}
