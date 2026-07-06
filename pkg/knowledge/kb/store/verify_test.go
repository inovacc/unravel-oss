/*
Copyright (c) 2026 Security Research

Tests for the shared bundle-provenance verification seam (hardening
findings #7/#8). VerifyBundleProvenance lets BOTH the CLI and the
supervisor/MCP import path enforce an operator-supplied Ed25519 key —
previously only the CLI could verify. Crypto-only; no Postgres/Docker.
*/
package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kbexport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"

	_ "modernc.org/sqlite"
)

// writeV2Bundle writes a directory-style .kbb bundle (bundle.json) and
// returns the bundle dir path plus the canonical manifest bytes.
func writeV2Bundle(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	kbb := filepath.Join(dir, "app.kbb")
	if err := os.MkdirAll(kbb, 0o755); err != nil {
		t.Fatalf("mkdir kbb: %v", err)
	}
	m := &kbexport.BundleManifest{
		BundleSchemaVersion: 2,
		KbID:                "app",
		PackageID:           "com.example.app",
		Platform:            "electron",
		ExportedAt:          time.Unix(1700000000, 0).UTC(),
		ExportedBy:          "test",
		Checksum:            "0000000000000000000000000000000000000000000000000000000000000000",
	}
	manifestBytes, err := kbexport.MarshalManifest(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kbb, "bundle.json"), manifestBytes, 0o644); err != nil {
		t.Fatalf("write bundle.json: %v", err)
	}
	return kbb, manifestBytes
}

func genKeyFiles(t *testing.T, dir string, manifestBytes []byte, sigPath string) (pubPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sig := kbexport.SignManifest(manifestBytes, priv)
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	pubPath = filepath.Join(dir, "pub.key")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return pubPath
}

func TestVerifyBundleProvenance_NoKeyOptIn(t *testing.T) {
	dir := t.TempDir()
	kbb, _ := writeV2Bundle(t, dir)
	// Empty verify key => opt-in verification skipped (parity with CLI default).
	if err := VerifyBundleProvenance(kbb, ""); err != nil {
		t.Fatalf("VerifyBundleProvenance(no key): want nil (skip), got %v", err)
	}
}

func TestVerifyBundleProvenance_ValidSignature(t *testing.T) {
	dir := t.TempDir()
	kbb, manifestBytes := writeV2Bundle(t, dir)
	pubPath := genKeyFiles(t, dir, manifestBytes, kbb+".sig")

	if err := VerifyBundleProvenance(kbb, pubPath); err != nil {
		t.Fatalf("VerifyBundleProvenance(valid): want nil, got %v", err)
	}
}

func TestVerifyBundleProvenance_TamperedManifestRejected(t *testing.T) {
	dir := t.TempDir()
	kbb, manifestBytes := writeV2Bundle(t, dir)
	pubPath := genKeyFiles(t, dir, manifestBytes, kbb+".sig")

	// Tamper bundle.json after signing — signature must no longer verify.
	if err := os.WriteFile(filepath.Join(kbb, "bundle.json"),
		append(manifestBytes, ' '), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if err := VerifyBundleProvenance(kbb, pubPath); err == nil {
		t.Fatalf("VerifyBundleProvenance(tampered): want error, got nil")
	}
}

func TestVerifyBundleProvenance_MissingSigRejected(t *testing.T) {
	dir := t.TempDir()
	kbb, manifestBytes := writeV2Bundle(t, dir)
	// Generate a key but DO NOT write the .sig sidecar.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	_ = manifestBytes
	pubPath := filepath.Join(dir, "pub.key")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	if err := VerifyBundleProvenance(kbb, pubPath); err == nil {
		t.Fatalf("VerifyBundleProvenance(missing sig): want error, got nil")
	}
}

// TestImport_VerifyKeyRejectsTamperedBeforeDBWrite proves the import path
// (not just the CLI) now enforces signatures: with VerifyKeyPath set and a
// tampered bundle, Import errors out at the provenance gate BEFORE any DB
// write — finding #7. The sqlite handle is real but never reached, since
// verification short-circuits first.
func TestImport_VerifyKeyRejectsTamperedBeforeDBWrite(t *testing.T) {
	dir := t.TempDir()
	kbb, manifestBytes := writeV2Bundle(t, dir)
	pubPath := genKeyFiles(t, dir, manifestBytes, kbb+".sig")
	// Tamper after signing.
	if err := os.WriteFile(filepath.Join(kbb, "bundle.json"), append(manifestBytes, ' '), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, err = Import(context.Background(), db, ImportOptions{BundlePath: kbb, VerifyKeyPath: pubPath})
	if err == nil {
		t.Fatalf("Import(tampered, verify-key): want error, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("want signature-verification error, got %v", err)
	}
}
