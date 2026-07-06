/*
Copyright (c) 2026 Security Research

Wave 0 unit tests for the kb_export package — D-43-BUNDLE-SCHEMA-V1
schema-shape, deterministic marshaling (mitigates T-43-04), missing-kb_id
error path, Pack tarball validity, and full directory-tree shape.

Tests use fakeLoader (in-memory Loader implementation) to avoid a live
Postgres dependency.
*/
package export

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExport_BundleSchemaShape — D-43-BUNDLE-SCHEMA-V1 envelope shape.
func TestExport_BundleSchemaShape(t *testing.T) {
	m := &BundleManifest{
		BundleSchemaVersion: BundleSchemaVersion,
		KbID:                "test-kb",
		PackageID:           "com.example.app",
		Platform:            "android",
		ExportedAt:          time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		ExportedBy:          "github.com/inovacc/unravel-oss/dev",
		Counts:              Counts{KnowledgeSources: 2, AppFacts: 5, KbDiffs: 1},
		Checksum:            strings.Repeat("a", 64),
	}
	b, err := MarshalManifest(m)
	if err != nil {
		t.Fatalf("MarshalManifest: %v", err)
	}
	got := map[string]any{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, _ := got["bundle_schema_version"].(float64); int(v) != 2 {
		t.Fatalf("bundle_schema_version = %v, want 2 (D-43 V2 default per ADR-0007)", got["bundle_schema_version"])
	}
	for _, key := range []string{"kb_id", "package_id", "platform", "exported_at",
		"exported_by", "counts", "checksum",
		// V2 advisory fields per ADR-0007.
		"signature_algorithm", "manifest_digest_alg"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing required key %q in manifest", key)
		}
	}
	parsed, err := UnmarshalManifest(b)
	if err != nil {
		t.Fatalf("UnmarshalManifest: %v", err)
	}
	if parsed.KbID != m.KbID || parsed.Counts.AppFacts != 5 {
		t.Fatalf("round-trip mismatch: %+v", parsed)
	}
}

// TestExport_DeterministicMarshalManifest — same input → byte-identical
// across runs (mitigates T-43-04).
func TestExport_DeterministicMarshalManifest(t *testing.T) {
	m := &BundleManifest{
		BundleSchemaVersion: BundleSchemaVersion,
		KbID:                "kb",
		PackageID:           "pkg",
		Platform:            "android",
		ExportedAt:          time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		ExportedBy:          "github.com/inovacc/unravel-oss/dev",
		Counts:              Counts{KnowledgeSources: 3, AppFacts: 4, KbDiffs: 2},
		Checksum:            strings.Repeat("b", 64),
	}
	a, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic marshal:\nA: %s\nB: %s", a, b)
	}
	idxBSV := bytes.Index(a, []byte(`"bundle_schema_version"`))
	idxCS := bytes.Index(a, []byte(`"checksum"`))
	if idxBSV < 0 || idxCS < 0 || idxBSV >= idxCS {
		t.Fatalf("keys not in sorted order: bundle_schema_version=%d checksum=%d", idxBSV, idxCS)
	}
}

// TestExport_MissingKbID — kb_id row not found returns descriptive error and
// writes no partial bundle.
func TestExport_MissingKbID(t *testing.T) {
	tmp := t.TempDir()
	ld := &fakeLoader{} // no rows
	_, err := ExportWithLoader(context.Background(), ld, "ghost-kb", tmp)
	if err == nil {
		t.Fatal("expected error for missing kb_id")
	}
	if !strings.Contains(err.Error(), "ghost-kb") {
		t.Fatalf("error must mention kb_id; got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(tmp, "ghost-kb.kbb")); statErr == nil {
		t.Fatal("partial bundle was written despite error")
	}
	if _, err := ExportWithLoader(context.Background(), ld, "", tmp); err == nil {
		t.Fatal("expected error for empty kb_id")
	}
}

// TestExport_PackProducesTarball — Pack creates a valid tar.gz; entry count
// matches dir tree contents.
func TestExport_PackProducesTarball(t *testing.T) {
	tmp := t.TempDir()
	ld := newFixtureLoader()
	manifest, err := ExportWithLoader(context.Background(), ld, "test-kb", tmp)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if manifest.Counts.KnowledgeSources != 2 {
		t.Fatalf("counts.knowledge_sources = %d, want 2", manifest.Counts.KnowledgeSources)
	}
	tarPath, err := Pack(tmp, "test-kb")
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if !strings.HasSuffix(tarPath, ".kbb.tar.gz") {
		t.Fatalf("tarball path %q lacks .kbb.tar.gz suffix", tarPath)
	}

	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gr)
	var entries []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		entries = append(entries, hdr.Name)
		_, _ = io.Copy(io.Discard, tr)
	}

	bundleRoot := filepath.Join(tmp, "test-kb.kbb")
	var diskFiles int
	_ = filepath.WalkDir(bundleRoot, func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			diskFiles++
		}
		return nil
	})
	if len(entries) != diskFiles {
		t.Fatalf("tar entries=%d, disk files=%d; entries=%v", len(entries), diskFiles, entries)
	}
	if _, err := os.Stat(filepath.Join(bundleRoot, "bundle.json")); err != nil {
		t.Fatalf("bundle.json missing: %v", err)
	}
}

// TestExport_DirectoryStructure — exports synthetic data; assert exact
// paths created and checksum integrity.
func TestExport_DirectoryStructure(t *testing.T) {
	tmp := t.TempDir()
	ld := newFixtureLoader()
	manifest, err := ExportWithLoader(context.Background(), ld, "test-kb", tmp)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	root := filepath.Join(tmp, "test-kb.kbb")
	for _, rel := range []string{
		"bundle.json", "knowledge.json", "knowledge_sources",
		"app_facts", "kb_diffs",
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("expected %s missing: %v", rel, err)
		}
	}
	for _, ep := range []string{"1.jsonl", "2.jsonl"} {
		if _, err := os.Stat(filepath.Join(root, "app_facts", ep)); err != nil {
			t.Fatalf("expected app_facts/%s missing: %v", ep, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "kb_diffs", "1-2.json")); err != nil {
		t.Fatalf("expected kb_diffs/1-2.json missing: %v", err)
	}

	kBytes, err := os.ReadFile(filepath.Join(root, "knowledge.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(kBytes)
	if want := hex.EncodeToString(sum[:]); manifest.Checksum != want {
		t.Fatalf("checksum mismatch: manifest=%s want=%s", manifest.Checksum, want)
	}
}

// TestExport_BadManifestRejected — UnmarshalManifest enforces strict schema.
func TestExport_BadManifestRejected(t *testing.T) {
	cases := map[string][]byte{
		"wrong schema_version": []byte(`{"bundle_schema_version":99,"kb_id":"k","package_id":"","platform":"","exported_at":"2026-05-05T12:00:00Z","exported_by":"","counts":{"knowledge_sources":0,"app_facts":0,"kb_diffs":0},"checksum":""}`),
		"missing kb_id":        []byte(`{"bundle_schema_version":1,"kb_id":"","package_id":"","platform":"","exported_at":"2026-05-05T12:00:00Z","exported_by":"","counts":{"knowledge_sources":0,"app_facts":0,"kb_diffs":0},"checksum":""}`),
		"bad checksum length":  []byte(`{"bundle_schema_version":1,"kb_id":"k","package_id":"","platform":"","exported_at":"2026-05-05T12:00:00Z","exported_by":"","counts":{"knowledge_sources":0,"app_facts":0,"kb_diffs":0},"checksum":"deadbeef"}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalManifest(body); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// fakeLoader — in-memory Loader for unit tests.
// ---------------------------------------------------------------------------

type fakeLoader struct {
	app     *KbApp
	sources []Source
	facts   []Fact
	diffs   []Diff
}

func newFixtureLoader() *fakeLoader {
	return &fakeLoader{
		app: &KbApp{KbID: "test-kb", Platform: "android", PackageID: "com.example.test"},
		sources: []Source{
			{Epoch: 1, SourceSHA256: strings.Repeat("a", 64), JSON: json.RawMessage(`{"epoch":1,"name":"v1"}`)},
			{Epoch: 2, SourceSHA256: strings.Repeat("b", 64), JSON: json.RawMessage(`{"epoch":2,"name":"v2"}`)},
		},
		facts: []Fact{
			{Epoch: 1, Category: "comm", Key: "transport", Value: "https"},
			{Epoch: 1, Category: "auth", Key: "scheme", Value: "oauth2"},
			{Epoch: 2, Category: "ipc", Key: "channel", Value: "mojo"},
		},
		diffs: []Diff{
			{FromEpoch: 1, ToEpoch: 2, Payload: json.RawMessage(`{"changed":["auth.scheme"]}`)},
		},
	}
}

func (f *fakeLoader) LoadApp(_ context.Context, kbID string) (*KbApp, error) {
	if f.app == nil || f.app.KbID != kbID {
		return nil, fmt.Errorf("kb_export: kb_id %q not found", kbID)
	}
	return f.app, nil
}

func (f *fakeLoader) LoadSources(_ context.Context, _ string) ([]Source, error) {
	return f.sources, nil
}
func (f *fakeLoader) LoadFacts(_ context.Context, _ string) ([]Fact, error) { return f.facts, nil }
func (f *fakeLoader) LoadDiffs(_ context.Context, _ string) ([]Diff, error) { return f.diffs, nil }

// Compile-time interface check.
var _ Loader = (*fakeLoader)(nil)
var _ = errors.New
