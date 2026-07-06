//go:build integration

package goversions_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/goversions"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

type fakeSources struct {
	rels  []goversions.Release
	meta  map[string]goversions.ReleaseMeta
	vulns []goversions.Vuln
}

func (f fakeSources) Downloads(_ context.Context) ([]goversions.Release, error) {
	return f.rels, nil
}
func (f fakeSources) ReleaseMeta(_ context.Context) (map[string]goversions.ReleaseMeta, error) {
	return f.meta, nil
}
func (f fakeSources) Vulns(_ context.Context) ([]goversions.Vuln, error) {
	return f.vulns, nil
}

func TestSyncAndQuery(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t) // applies embedded migrations incl. 000020
	ctx := context.Background()
	src := fakeSources{
		rels: []goversions.Release{{Version: "go1.20.3", Stable: true, Files: []goversions.File{
			{Filename: "go1.20.3.src.tar.gz", Kind: "source", SHA256: "deadbeef", Size: 100, Version: "go1.20.3"},
		}}},
		meta:  map[string]goversions.ReleaseMeta{"go1.20.3": {Date: "2023-04-04", Security: "sec"}},
		vulns: []goversions.Vuln{{ID: "GO-2023-1878", Summary: "x", Affected: []goversions.AffectedRange{{Component: "stdlib", Introduced: "0", Fixed: "1.20.6"}}}},
	}

	rep, err := goversions.Sync(ctx, db, src, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NewVersions) != 1 || rep.Files != 1 || rep.Vulns != 1 {
		t.Fatalf("report = %+v", rep)
	}

	// idempotent: second sync adds nothing new
	rep2, _ := goversions.Sync(ctx, db, src, 2000)
	if len(rep2.NewVersions) != 0 {
		t.Errorf("second sync new versions = %v", rep2.NewVersions)
	}

	// verify by checksum
	ver, file, ok, _ := goversions.VerifyArtifact(db, "deadbeef")
	if !ok || ver != "go1.20.3" || file != "go1.20.3.src.tar.gz" {
		t.Errorf("verify = %q %q %v", ver, file, ok)
	}

	// CVE posture
	p, _ := goversions.CVEPostureFor(db, "go1.20.3")
	if len(p.Exposed) != 1 || p.Exposed[0].ID != "GO-2023-1878" {
		t.Errorf("posture = %+v", p.Exposed)
	}
}
