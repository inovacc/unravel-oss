//go:build integration

package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"
)

// TestBuild_LoneArtifact_CreatesKBApp proves that the fingerprint a lone
// artifact synthesizes (platform derived from filename, DisplayName = base,
// empty PackageID) flows through the real ingest writer to a kb_apps row.
func TestBuild_LoneArtifact_CreatesKBApp(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	ctx := context.Background()

	// A minimal ks_dir: ingest walks it for bodies; an empty dir still upserts
	// kb_apps and indexes zero modules.
	ksDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(ksDir, "placeholder.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	name := "service.jar"
	in := identity.FingerprintInputs{
		Platform:    identity.PlatformForArtifact(name), // "other"
		DisplayName: name,
	}
	kbID, ksID, err := identity.Fingerprint(in)
	if err != nil {
		t.Fatalf("fingerprint synthesized inputs: %v", err)
	}

	res, err := ingest.Run(ctx, db, kbID, ksID, ksDir, ingest.Options{
		ResolveAlias:  true,
		AllowedRoots:  []string{ksDir},
		Platform:      in.Platform,
		DisplayName:   in.DisplayName,
		CanonicalName: identity.CanonicalName(in.DisplayName),
	})
	if err != nil {
		t.Fatalf("ingest.Run: %v", err)
	}
	if res.KBID != kbID {
		t.Errorf("res.KBID = %q, want %q", res.KBID, kbID)
	}
	wantApp := identity.CanonicalName(name)
	if res.App != wantApp {
		t.Errorf("res.App = %q, want %q", res.App, wantApp)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kb_apps WHERE kb_id = $1`, kbID).Scan(&count); err != nil {
		t.Fatalf("query kb_apps: %v", err)
	}
	if count != 1 {
		t.Fatalf("kb_apps rows for %q = %d, want 1", kbID, count)
	}
}
