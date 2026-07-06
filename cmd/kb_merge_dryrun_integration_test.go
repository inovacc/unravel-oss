//go:build integration

package cmd

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestKbMerge_DryRun_NoMutation(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at) VALUES
		('aaaa1111aaaa1111','loser','Loser','win32',0,0),
		('bbbb2222bbbb2222','winner','Winner','win32',0,0)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	pinDSNViaConfig(t, dsn)
	stdout, _, err := runRoot(t, "kb", "ops", "merge", "aaaa1111aaaa1111", "bbbb2222bbbb2222", "--dry-run", "--by", "tester", "--reason", "test")
	if err != nil {
		t.Fatalf("dry-run merge: %v", err)
	}
	if !strings.Contains(stdout, "dry-run") {
		t.Fatalf("want dry-run banner, got: %s", stdout)
	}

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM kb_apps WHERE kb_id='aaaa1111aaaa1111'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("dry-run must not delete loser; got count=%d", n)
	}
}
