//go:build integration

package classify_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestLoadCumulativeModules_UnionsAcrossEpochs(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	const kbID = "cafe0000cafe0000"
	seedKBApp(t, db, kbID)

	s1 := seedSource(t, db, "demo", kbID, 1)
	s2 := seedSource(t, db, "demo", kbID, 2)

	_ = seedModule(t, db, "demo", "modA", "sha-aa", "{}", s1)
	_ = seedModule(t, db, "demo", "modB", "sha-bb", "{}", s2)

	got, err := classify.LoadCumulativeModules(ctx, db, kbID)
	if err != nil {
		t.Fatalf("cumulative: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 modules across epochs, got %d", len(got))
	}
}
