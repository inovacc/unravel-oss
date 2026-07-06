/*
Copyright (c) 2026 Security Research

D-43 V2 (ADR-0007) Ed25519 detached-signature primitives. The signature is
computed over sha256(canonicalize(bundle.json)) and stored as a 64-byte raw
file alongside the .kbb.tar.gz. No PEM, no PKCS, no passphrase — operators
manage keys via OS-native secret stores. See `.planning/notes/2026-05-07-bundle-schema-v2.md`.
*/
package export

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// SignatureLen is the on-disk size of an Ed25519 detached signature.
const SignatureLen = ed25519.SignatureSize

// LoadEd25519Private reads a 32-byte Ed25519 seed (raw, no PEM) from path.
// The path "-" reads from stdin (CI / vault piping).
func LoadEd25519Private(path string) (ed25519.PrivateKey, error) {
	raw, err := readKeyBytes(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("kb_export: ed25519 private key must be %d bytes (got %d)",
			ed25519.SeedSize, len(raw))
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// LoadEd25519Public reads a 32-byte raw Ed25519 public key from path.
// The path "-" reads from stdin.
func LoadEd25519Public(path string) (ed25519.PublicKey, error) {
	raw, err := readKeyBytes(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("kb_export: ed25519 public key must be %d bytes (got %d)",
			ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func readKeyBytes(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// ManifestDigest returns sha256 over the canonical manifest bytes. This is
// the input the Ed25519 signature is computed/verified against.
func ManifestDigest(manifestCanonical []byte) []byte {
	sum := sha256.Sum256(manifestCanonical)
	return sum[:]
}

// SignManifest produces a 64-byte raw Ed25519 signature over the digest of
// the canonical manifest.
func SignManifest(manifestCanonical []byte, key ed25519.PrivateKey) []byte {
	digest := ManifestDigest(manifestCanonical)
	return ed25519.Sign(key, digest)
}

// VerifyManifest returns nil if sig validates the digest under pub, else an
// error suitable for surfacing to the operator.
func VerifyManifest(manifestCanonical, sig []byte, pub ed25519.PublicKey) error {
	if len(sig) != SignatureLen {
		return fmt.Errorf("kb_export: signature length %d != %d", len(sig), SignatureLen)
	}
	digest := ManifestDigest(manifestCanonical)
	if !ed25519.Verify(pub, digest, sig) {
		return errors.New("kb_export: bundle signature invalid")
	}
	return nil
}

// WriteSignatureFile writes sig to <bundlePath>.kbb.sig (or whatever sigPath
// the caller specifies). Sidecar layout per ADR-0007.
func WriteSignatureFile(sigPath string, sig []byte) error {
	if len(sig) != SignatureLen {
		return fmt.Errorf("kb_export: refusing to write signature of length %d", len(sig))
	}
	return os.WriteFile(sigPath, sig, 0o600)
}

// ReadSignatureFile reads a sidecar .sig file and returns its raw bytes.
func ReadSignatureFile(sigPath string) ([]byte, error) {
	data, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("kb_export: read signature %s: %w", sigPath, err)
	}
	if len(data) != SignatureLen {
		return nil, fmt.Errorf("kb_export: signature file %s has length %d, want %d",
			sigPath, len(data), SignatureLen)
	}
	return data, nil
}
