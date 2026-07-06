//go:build integration

package cmd

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestKbShow_CumulativeModuleCount(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })

	const kbID = "feed0000feed0000"
	if _, err := db.Exec(`INSERT INTO kb_apps (kb_id,canonical_name,display_name,platform,first_seen_at,last_seen_at) VALUES ($1,'demo','Demo','win32',0,0)`, kbID); err != nil {
		t.Fatalf("kb_apps: %v", err)
	}
	var s1, s2 int64
	if err := db.QueryRow(`INSERT INTO knowledge_sources (app,epoch,source_path,source_kind,captured_at,kb_id,ks_id,modules_indexed) VALUES ('demo',1,'/a','cache',0,$1,'ks-1',1) RETURNING id`, kbID).Scan(&s1); err != nil {
		t.Fatalf("src1: %v", err)
	}
	if err := db.QueryRow(`INSERT INTO knowledge_sources (app,epoch,source_path,source_kind,captured_at,kb_id,ks_id,modules_indexed) VALUES ('demo',2,'/b','cache',0,$1,'ks-2',1) RETURNING id`, kbID).Scan(&s2); err != nil {
		t.Fatalf("src2: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO modules (app,name,body_sha256,body_size,first_seen_at,last_seen_at,first_source_id,last_source_id) VALUES
		('demo','modA','aa',10,0,0,$1,$1),('demo','modB','bb',10,0,0,$2,$2)`, s1, s2); err != nil {
		t.Fatalf("modules: %v", err)
	}

	pinDSNViaConfig(t, dsn)
	stdout, _, err := runRoot(t, "kb", "show", kbID)
	if err != nil {
		t.Fatalf("kb show: %v", err)
	}
	if !strings.Contains(stdout, "cumulative") {
		t.Fatalf("want a cumulative count line, got: %s", stdout)
	}
}
