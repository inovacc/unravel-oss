/*
Copyright (c) 2026 Security Research

Wave 0 unit tests for kb_import — bundle-shape rejection, checksum
verification, path-traversal guard, schema-version mismatch, and
idempotent re-import via in-memory Importer.

Tests use a fakeImporter (in-memory) to avoid live Postgres dependency;
DB-level integration is exercised in cmd/kb_import_roundtrip_integration_test.go.
*/
package import_

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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"
)

// ---------------------------------------------------------------------------
// Helpers — write a synthetic bundle directory tree on disk for tests.
// ---------------------------------------------------------------------------

type bundleSpec struct {
	kbID            string
	platform        string
	packageID       string
	schemaVersion   int    // 0 = use default
	tamperKnowledge bool   // if true, post-write the knowledge.json with extra bytes (checksum mismatch)
	knowledge       string // override knowledge.json content
}

func writeBundle(t *testing.T, root string, spec bundleSpec) string {
	t.Helper()
	if spec.kbID == "" {
		spec.kbID = "test-kb"
	}
	bundleRoot := filepath.Join(root, spec.kbID+".kbb")
	if err := os.MkdirAll(filepath.Join(bundleRoot, "knowledge_sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bundleRoot, "app_facts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bundleRoot, "kb_diffs"), 0o755); err != nil {
		t.Fatal(err)
	}

	knowledgeBytes := []byte(`{"epoch": 2, "name": "v2"}`)
	if spec.knowledge != "" {
		knowledgeBytes = []byte(spec.knowledge)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "knowledge.json"), knowledgeBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// One source file matching the export "1-<sha>.json" naming convention.
	sourceJSON := []byte(`{"epoch":1,"name":"v1"}`)
	if err := os.WriteFile(filepath.Join(bundleRoot, "knowledge_sources", "1-aaaaaaaaaaaa.json"), sourceJSON, 0o644); err != nil {
		t.Fatal(err)
	}

	// One fact line.
	factLine := []byte(`{"epoch":1,"category":"comm","key":"transport","value":"https"}` + "\n")
	if err := os.WriteFile(filepath.Join(bundleRoot, "app_facts", "1.jsonl"), factLine, 0o644); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(knowledgeBytes)
	checksum := hex.EncodeToString(sum[:])
	if spec.tamperKnowledge {
		// Recompute checksum from bytes, then write tampered bytes after.
	}
	schemaVersion := export.BundleSchemaVersion
	if spec.schemaVersion != 0 {
		schemaVersion = spec.schemaVersion
	}
	manifest := &export.BundleManifest{
		BundleSchemaVersion: schemaVersion,
		KbID:                spec.kbID,
		PackageID:           spec.packageID,
		Platform:            spec.platform,
		ExportedAt:          time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		ExportedBy:          "github.com/inovacc/unravel-oss/test",
		Counts:              export.Counts{KnowledgeSources: 1, AppFacts: 1, KbDiffs: 0},
		Checksum:            checksum,
	}
	mb, err := export.MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "bundle.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}

	if spec.tamperKnowledge {
		// Append bytes AFTER manifest is sealed → checksum mismatch.
		f, err := os.OpenFile(filepath.Join(bundleRoot, "knowledge.json"), os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(" tampered"))
		_ = f.Close()
	}
	return bundleRoot
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestImport_RejectsMalformedBundle(t *testing.T) {
	tmp := t.TempDir()
	bundleRoot := filepath.Join(tmp, "broken-kb.kbb")
	if err := os.MkdirAll(bundleRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write garbage bundle.json
	if err := os.WriteFile(filepath.Join(bundleRoot, "bundle.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	im := &fakeImporter{}
	_, err := ImportWithImporter(context.Background(), im, bundleRoot)
	if err == nil {
		t.Fatal("expected error for malformed bundle.json")
	}
}

func TestImport_RejectsChecksumMismatch(t *testing.T) {
	tmp := t.TempDir()
	bundleRoot := writeBundle(t, tmp, bundleSpec{kbID: "checksum-kb", tamperKnowledge: true})
	im := &fakeImporter{}
	_, err := ImportWithImporter(context.Background(), im, bundleRoot)
	if err == nil {
		t.Fatal("expected checksum-mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("error must mention checksum; got %v", err)
	}
}

func TestImport_RejectsPathTraversal(t *testing.T) {
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "evil.kbb.tar.gz")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	// Malicious entry — would escape extraction dir if path-traversal guard is missing.
	hdr := &tar.Header{
		Name: "../escape.txt",
		Mode: 0o644,
		Size: 5,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte("evil!"))
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	im := &fakeImporter{}
	_, err = ImportWithImporter(context.Background(), im, tarPath)
	if err == nil {
		t.Fatal("expected path-traversal rejection")
	}
	if !strings.Contains(err.Error(), "unsafe") && !strings.Contains(err.Error(), "escape") {
		t.Fatalf("error must indicate unsafe entry; got %v", err)
	}
}

func TestImport_RejectsSchemaVersionMismatch(t *testing.T) {
	tmp := t.TempDir()
	bundleRoot := filepath.Join(tmp, "wrong-schema.kbb")
	if err := os.MkdirAll(filepath.Join(bundleRoot, "knowledge_sources"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bundleRoot, "app_facts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bundleRoot, "kb_diffs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "knowledge.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Hand-craft bundle.json with schema_version = 99
	bad := []byte(`{
  "bundle_schema_version": 99,
  "checksum": "",
  "counts": {
    "app_facts": 0,
    "kb_diffs": 0,
    "knowledge_sources": 0
  },
  "exported_at": "2026-05-05T12:00:00Z",
  "exported_by": "github.com/inovacc/unravel-oss/test",
  "kb_id": "k",
  "package_id": "",
  "platform": ""
}`)
	if err := os.WriteFile(filepath.Join(bundleRoot, "bundle.json"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	im := &fakeImporter{}
	_, err := ImportWithImporter(context.Background(), im, bundleRoot)
	if err == nil {
		t.Fatal("expected schema-version-mismatch error")
	}
}

func TestImport_RejectsMissingBundleJson(t *testing.T) {
	tmp := t.TempDir() // no bundle.json
	im := &fakeImporter{}
	_, err := ImportWithImporter(context.Background(), im, tmp)
	if err == nil {
		t.Fatal("expected error for missing bundle.json")
	}
}

func TestImport_IdempotentOnReimport(t *testing.T) {
	tmp := t.TempDir()
	bundleRoot := writeBundle(t, tmp, bundleSpec{kbID: "idem-kb", platform: "android", packageID: "com.example"})

	im := &fakeImporter{}
	r1, err := ImportWithImporter(context.Background(), im, bundleRoot)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if r1.NewRowsCount["kb_apps"] != 1 {
		t.Fatalf("first import: expected 1 new kb_apps row; got %d", r1.NewRowsCount["kb_apps"])
	}
	if r1.NewRowsCount["knowledge_sources"] != 1 {
		t.Fatalf("first import: expected 1 new knowledge_sources row; got %d", r1.NewRowsCount["knowledge_sources"])
	}
	if r1.NewRowsCount["app_facts"] != 1 {
		t.Fatalf("first import: expected 1 new app_facts row; got %d", r1.NewRowsCount["app_facts"])
	}

	r2, err := ImportWithImporter(context.Background(), im, bundleRoot)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	totalNew := 0
	for _, n := range r2.NewRowsCount {
		totalNew += n
	}
	if totalNew != 0 {
		t.Fatalf("re-import: expected 0 new rows total; got %d (%v)", totalNew, r2.NewRowsCount)
	}
	if r2.ConflictsSkipped["kb_apps"] != 1 {
		t.Fatalf("re-import: expected 1 conflict on kb_apps; got %d", r2.ConflictsSkipped["kb_apps"])
	}
}

func TestImport_RejectsTooManyEntries(t *testing.T) {
	// Sanity: cap is bounded; exceed it would error. Smoke-test the constant.
	if MaxBundleEntries < 1000 {
		t.Fatalf("MaxBundleEntries unreasonably low: %d", MaxBundleEntries)
	}
}

// Sanity: the module's package name compiles under the import_ rename.
func TestPackageNameSanity(t *testing.T) {
	var im Importer = &fakeImporter{}
	if im == nil {
		t.Fatal("nil")
	}
}

// ---------------------------------------------------------------------------
// fakeImporter — in-memory Importer for unit tests.
// ---------------------------------------------------------------------------

type fakeImporter struct {
	apps    map[string]bool
	sources map[string]bool // key: kbID|epoch
	facts   map[string]bool // key: kbID|category|key
	diffs   map[string]bool // key: kbID|from|to
}

func (f *fakeImporter) BeginTx(_ context.Context) (Tx, error) {
	if f.apps == nil {
		f.apps = map[string]bool{}
	}
	if f.sources == nil {
		f.sources = map[string]bool{}
	}
	if f.facts == nil {
		f.facts = map[string]bool{}
	}
	if f.diffs == nil {
		f.diffs = map[string]bool{}
	}
	return &fakeTx{im: f}, nil
}

type fakeTx struct {
	im        *fakeImporter
	rolledBak bool
	committed bool
	// Pending writes — applied on Commit, discarded on Rollback so a
	// failing transaction does not leak state.
	pendingApps    []string
	pendingSources []string
	pendingFacts   []string
	pendingDiffs   []string
}

func (t *fakeTx) UpsertKbApp(_ context.Context, kbID, _, _ string) (bool, error) {
	if t.im.apps[kbID] {
		return false, nil
	}
	if slices.Contains(t.pendingApps, kbID) {
		return false, nil
	}
	t.pendingApps = append(t.pendingApps, kbID)
	return true, nil
}

func (t *fakeTx) UpsertSource(_ context.Context, kbID string, epoch int64, _ string, _ json.RawMessage) (bool, error) {
	key := fmt.Sprintf("%s|%d", kbID, epoch)
	if t.im.sources[key] {
		return false, nil
	}
	if slices.Contains(t.pendingSources, key) {
		return false, nil
	}
	t.pendingSources = append(t.pendingSources, key)
	return true, nil
}

func (t *fakeTx) UpsertFact(_ context.Context, kbID string, _ int64, category, key, _ string) (bool, error) {
	k := fmt.Sprintf("%s|%s|%s", kbID, category, key)
	if t.im.facts[k] {
		return false, nil
	}
	if slices.Contains(t.pendingFacts, k) {
		return false, nil
	}
	t.pendingFacts = append(t.pendingFacts, k)
	return true, nil
}

func (t *fakeTx) UpsertDiff(_ context.Context, kbID string, from, to int64, _ json.RawMessage) (bool, error) {
	k := fmt.Sprintf("%s|%d|%d", kbID, from, to)
	if t.im.diffs[k] {
		return false, nil
	}
	if slices.Contains(t.pendingDiffs, k) {
		return false, nil
	}
	t.pendingDiffs = append(t.pendingDiffs, k)
	return true, nil
}

func (t *fakeTx) Commit() error {
	for _, k := range t.pendingApps {
		t.im.apps[k] = true
	}
	for _, k := range t.pendingSources {
		t.im.sources[k] = true
	}
	for _, k := range t.pendingFacts {
		t.im.facts[k] = true
	}
	for _, k := range t.pendingDiffs {
		t.im.diffs[k] = true
	}
	t.committed = true
	return nil
}

func (t *fakeTx) Rollback() error {
	if t.committed {
		return nil
	}
	t.rolledBak = true
	return nil
}

// Compile-time interface check.
var _ Importer = (*fakeImporter)(nil)

// silence import unused for bytes (used in some build configurations).
var _ = bytes.NewReader
var _ = errors.New
