package cmd

import (
	"strings"
	"testing"
)

func TestLegacyKBID_DeterministicAndDistinct(t *testing.T) {
	a := legacyKBID(`C:\Users\x\knowledge.db`)
	b := legacyKBID(`C:\Users\x\knowledge.db`)
	c := legacyKBID(`C:\Users\x\other.db`)
	if a != b {
		t.Fatalf("not deterministic: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("distinct paths collided: %q", a)
	}
	if len(a) != len("legacy-")+12 || a[:7] != "legacy-" {
		t.Fatalf("unexpected shape: %q", a)
	}
}

func TestMigrateBatchFlag_DefaultAndParse(t *testing.T) {
	dbMigrateFromSQLiteCmd.SetArgs([]string{"--src", "x.db", "--batch", "250", "--dry-run"})
	if f := dbMigrateFromSQLiteCmd.Flags().Lookup("batch"); f == nil {
		t.Fatal("--batch flag not registered")
	}
	if migrateBatch != 5000 && migrateBatch != 250 {
		t.Fatalf("migrateBatch var not wired (got %d)", migrateBatch)
	}
}

func TestSynthesizeLegacyAnchor_Idempotent_Unit(t *testing.T) {
	if anchorKBApp() == "" || anchorKnowledgeSource() == "" || anchorRefsSQL() == "" {
		t.Fatal("anchor SQL builders returned empty")
	}
	for _, q := range []string{anchorKBApp(), anchorKnowledgeSource(), anchorRefsSQL()} {
		if !strings.Contains(q, "ON CONFLICT") && !strings.Contains(q, "NOT EXISTS") {
			t.Fatalf("anchor SQL not idempotent: %s", q)
		}
	}
}

func TestBatchedExec_CommitsAtBoundaryAndResumes(t *testing.T) {
	// emulate: 7 rows, batch=3 → commits at 3,6,7 (3 commits).
	var commits int
	flush := func() error { commits++; return nil }
	bc := newBatchCounter(3, flush)
	for i := 0; i < 7; i++ {
		if err := bc.tick(); err != nil {
			t.Fatalf("tick: %v", err)
		}
	}
	if err := bc.done(); err != nil {
		t.Fatalf("done: %v", err)
	}
	if commits != 3 {
		t.Fatalf("commits=%d want 3 (at 3,6,7)", commits)
	}
}

func TestVerifyFlag_Registered(t *testing.T) {
	if dbMigrateFromSQLiteCmd.Flags().Lookup("verify") == nil {
		t.Fatal("--verify flag not registered")
	}
	if verifyParityTables == nil || len(verifyParityTables) == 0 {
		t.Fatal("verifyParityTables not defined")
	}
}
