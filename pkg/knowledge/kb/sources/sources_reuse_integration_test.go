//go:build integration

package sources_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/sources"
)

func TestBegin_ReuseEpoch_GetOrCreate(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	first, err := sources.Begin(ctx, db, sources.Source{App: "demo", SourcePath: "/dir1", Kind: sources.KindCache})
	if err != nil {
		t.Fatalf("first begin: %v", err)
	}
	if first.Epoch != 1 {
		t.Fatalf("want epoch 1, got %d", first.Epoch)
	}

	second, err := sources.Begin(ctx, db, sources.Source{App: "demo", SourcePath: "/dir2", Kind: sources.KindCache, ReuseEpoch: 1})
	if err != nil {
		t.Fatalf("reuse begin: %v", err)
	}
	if second.Epoch != 1 {
		t.Fatalf("reuse: want epoch 1, got %d", second.Epoch)
	}
	if second.ID != first.ID {
		t.Fatalf("reuse: want same source id %d, got %d", first.ID, second.ID)
	}

	third, err := sources.Begin(ctx, db, sources.Source{App: "demo", SourcePath: "/dir3", Kind: sources.KindCache})
	if err != nil {
		t.Fatalf("third begin: %v", err)
	}
	if third.Epoch != 2 {
		t.Fatalf("want epoch 2, got %d", third.Epoch)
	}
}

func TestAddCounts_Accumulates(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	src, err := sources.Begin(ctx, db, sources.Source{App: "demo", SourcePath: "/d1", Kind: sources.KindCache})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := sources.AddCounts(ctx, db, src.ID, 100, 90); err != nil {
		t.Fatalf("add 1: %v", err)
	}
	if err := sources.AddCounts(ctx, db, src.ID, 56, 50); err != nil {
		t.Fatalf("add 2: %v", err)
	}
	var mods, bodies int64
	if err := db.QueryRowContext(ctx,
		`SELECT modules_indexed, bodies_indexed FROM knowledge_sources WHERE id = $1`, src.ID,
	).Scan(&mods, &bodies); err != nil {
		t.Fatalf("read counts: %v", err)
	}
	if mods != 156 || bodies != 140 {
		t.Fatalf("want modules=156 bodies=140, got modules=%d bodies=%d", mods, bodies)
	}
}
