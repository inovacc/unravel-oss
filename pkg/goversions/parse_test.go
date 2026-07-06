package goversions

import (
	"os"
	"strings"
	"testing"
)

func TestParseDownloads(t *testing.T) {
	b, err := os.ReadFile("testdata/dl.json")
	if err != nil {
		t.Fatal(err)
	}
	rels, err := ParseDownloads(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 {
		t.Fatalf("got %d releases, want 2", len(rels))
	}
	if rels[0].Version != "go1.22.5" || !rels[0].Stable || len(rels[0].Files) != 2 {
		t.Errorf("bad first release: %+v", rels[0])
	}
	if rels[0].Files[0].Kind != "source" || rels[0].Files[0].SHA256 != "aaa" {
		t.Errorf("bad first file: %+v", rels[0].Files[0])
	}
	if rels[1].Stable {
		t.Errorf("go1.21rc1 should be unstable")
	}
}

func TestParseOSV(t *testing.T) {
	b, err := os.ReadFile("testdata/osv.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseOSV(b)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "GO-2023-1878" {
		t.Errorf("id = %q", v.ID)
	}
	if len(v.Aliases) != 2 || v.Aliases[0] != "CVE-2023-29406" {
		t.Errorf("aliases = %v", v.Aliases)
	}
	if len(v.Affected) != 2 {
		t.Fatalf("affected = %d want 2", len(v.Affected))
	}
	if v.Affected[0].Component != "stdlib" || v.Affected[0].Introduced != "0" || v.Affected[0].Fixed != "1.20.6" {
		t.Errorf("affected[0] = %+v", v.Affected[0])
	}
}

func TestParseReleaseHistory(t *testing.T) {
	b, err := os.ReadFile("testdata/release-history.html")
	if err != nil {
		t.Fatal(err)
	}
	m := ParseReleaseHistory(b)
	got, ok := m["go1.22.5"]
	if !ok {
		t.Fatalf("go1.22.5 missing; got %v", m)
	}
	if got.Date != "2024-07-02" {
		t.Errorf("date = %q", got.Date)
	}
	if !strings.Contains(got.Security, "security") {
		t.Errorf("security = %q", got.Security)
	}
}
