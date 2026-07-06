/*
Copyright (c) 2026 Security Research

verify.go — shared Ed25519 bundle-provenance verification (hardening
findings #7/#8). Previously this logic lived ONLY in cmd/kb_import.go's
preflightVerifyBundle, so the supervisor/MCP import path (which calls
kbstore.Import directly) could not verify signatures at all — a provenance
parity gap. This seam lets BOTH the CLI and the supervisor enforce an
operator-supplied pinned key.

Verification is OPT-IN: it runs only when a non-empty verifyKeyPath is
provided, matching the CLI's --verify-key default ("") and ADR-0007's
out-of-band/opt-in pinned-key model. Flipping this to default-on would
reject every currently-importable (unsigned) V2 bundle and is a breaking
change requiring a new ADR — see docs/BACKLOG.md.
*/
package store

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	kbexport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"
)

// VerifyBundleProvenance enforces Ed25519 signature verification on the
// bundle at bundlePath using the pinned public key at verifyKeyPath.
//
// When verifyKeyPath is empty, verification is skipped (opt-in parity with
// the CLI default) and the caller is responsible for any provenance warning.
//
// For V2 bundles with a key set, the sibling .sig sidecar must exist and the
// Ed25519 signature over the canonical bundle.json bytes must validate.
// V1 bundles have no signature surface and pass (the CLI emits the V1
// deprecation warning separately).
func VerifyBundleProvenance(bundlePath, verifyKeyPath string) error {
	if verifyKeyPath == "" {
		return nil
	}
	manifestBytes, err := ReadManifestBytes(bundlePath)
	if err != nil {
		return fmt.Errorf("verify bundle: %w", err)
	}
	manifest, err := kbexport.UnmarshalManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("verify bundle: parse bundle.json: %w", err)
	}
	switch manifest.BundleSchemaVersion {
	case 1:
		// V1 has no signature surface; nothing to verify under a key.
		return nil
	case 2:
		sigPath := DeriveSigPath(bundlePath)
		if _, err := os.Stat(sigPath); err != nil {
			return fmt.Errorf("bundle_signature_missing: %s (V2 bundle requires .sig sidecar when verify-key is set)", sigPath)
		}
		sig, err := kbexport.ReadSignatureFile(sigPath)
		if err != nil {
			return fmt.Errorf("verify bundle: %w", err)
		}
		pub, err := kbexport.LoadEd25519Public(verifyKeyPath)
		if err != nil {
			return fmt.Errorf("verify bundle: verify-key: %w", err)
		}
		if err := kbexport.VerifyManifest(manifestBytes, sig, pub); err != nil {
			return fmt.Errorf("bundle_signature_invalid: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("verify bundle: unsupported bundle_schema_version %d", manifest.BundleSchemaVersion)
	}
}

// ReadManifestBytes extracts bundle.json bytes from either a .kbb.tar.gz
// archive or a directory tree (.kbb/). Signature verification is over these
// raw bytes, so they must be the canonical manifest the signer produced.
// Exported so the CLI shares one bundle.json reader with the verifier.
func ReadManifestBytes(bundlePath string) ([]byte, error) {
	st, err := os.Stat(bundlePath)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		direct := filepath.Join(bundlePath, "bundle.json")
		if _, err := os.Stat(direct); err == nil {
			return os.ReadFile(direct)
		}
		entries, err := os.ReadDir(bundlePath)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".kbb") {
				return os.ReadFile(filepath.Join(bundlePath, e.Name(), "bundle.json"))
			}
		}
		return nil, errors.New("bundle.json not found in directory")
	}
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if filepath.Base(hdr.Name) == "bundle.json" {
			return io.ReadAll(tr)
		}
	}
	return nil, errors.New("bundle.json not found in tarball")
}

// DeriveSigPath returns the expected sibling .sig path for a .kbb.tar.gz
// file or a .kbb/ directory.
func DeriveSigPath(bundlePath string) string {
	if strings.HasSuffix(bundlePath, ".kbb.tar.gz") {
		return strings.TrimSuffix(bundlePath, ".kbb.tar.gz") + ".kbb.sig"
	}
	if strings.HasSuffix(bundlePath, ".kbb") {
		return bundlePath + ".sig"
	}
	return bundlePath + ".sig"
}
