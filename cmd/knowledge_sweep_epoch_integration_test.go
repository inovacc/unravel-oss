//go:build integration

package cmd

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/sources"
)

// Simulates the sweep's per-app reuse handshake: dir1 fresh, dir2/dir3 reuse.
func TestSweepReuse_SingleEpochPerApp(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	reuse := 0
	beginOne := func(path string) *sources.Source {
		s, err := sources.Begin(ctx, db, sources.Source{App: "cluely", SourcePath: path, Kind: sources.KindCache, ReuseEpoch: reuse})
		if err != nil {
			t.Fatalf("begin %s: %v", path, err)
		}
		reuse = s.Epoch // pin after first
		return s
	}
	a := beginOne("/dist")
	b := beginOne("/dist-electron")
	c := beginOne("/asar")

	if a.Epoch != 1 || b.Epoch != 1 || c.Epoch != 1 {
		t.Fatalf("want all epoch 1, got %d/%d/%d", a.Epoch, b.Epoch, c.Epoch)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM knowledge_sources WHERE app='cluely'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 knowledge_sources row for the build, got %d", n)
	}
}
