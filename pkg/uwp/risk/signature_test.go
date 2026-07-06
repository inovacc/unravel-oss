/*
Copyright (c) 2026 Security Research

Tests use crypto/x509 only to fabricate test fixtures; the production code
path consumes go.mozilla.org/pkcs7 (already a project dependency) — no new
crypto surface introduced (V6 ASVS).
*/
package risk

import (
	"archive/zip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

func TestSignatureMultiplier_Mapping(t *testing.T) {
	cases := []struct {
		status string
		want   float64
	}{
		{"unsigned", 2.0},
		{"invalid", 2.0},
		{"self-signed", 1.5},
		{"trusted-other", 1.0},
		{"trusted-microsoft", 0.8},
	}
	for _, c := range cases {
		got := Multiplier(uwp.SignatureInfo{Status: c.status}, nil)
		if got != c.want {
			t.Errorf("Multiplier(%q)=%v want %v", c.status, got, c.want)
		}
	}
	// Unknown status falls back to 1.0 defensively.
	if got := Multiplier(uwp.SignatureInfo{Status: "wat"}, nil); got != 1.0 {
		t.Errorf("Multiplier(unknown)=%v want 1.0", got)
	}
}

func TestInspectSignature_Unsigned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unsigned.msix")
	makeZip(t, path, map[string][]byte{
		"AppxManifest.xml": []byte(`<?xml version="1.0"?><Package/>`),
	})
	sig, err := InspectSignature(path)
	if err != nil {
		t.Fatalf("InspectSignature: %v", err)
	}
	if sig.Status != "unsigned" {
		t.Errorf("Status=%q want unsigned", sig.Status)
	}
}

func TestInspectSignature_DirectoryNoP7X(t *testing.T) {
	dir := t.TempDir()
	sig, err := InspectSignature(dir)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Status != "unsigned" {
		t.Errorf("Status=%q want unsigned", sig.Status)
	}
}

func TestInspectSignature_InvalidP7X(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.msix")
	makeZip(t, path, map[string][]byte{
		"AppxManifest.xml":  []byte(`<?xml version="1.0"?><Package/>`),
		"AppxSignature.p7x": []byte("PKCXgarbage-not-pkcs7"),
	})
	sig, _ := InspectSignature(path)
	if sig.Status != "invalid" {
		t.Errorf("Status=%q want invalid", sig.Status)
	}
}

func TestInspectSignature_DirectoryWithBadP7X(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "AppxSignature.p7x"), []byte("PKCXabc"), 0o644); err != nil {
		t.Fatal(err)
	}
	sig, _ := InspectSignature(dir)
	if sig.Status != "invalid" {
		t.Errorf("Status=%q want invalid", sig.Status)
	}
}

func TestClassifyCert_SelfSigned(t *testing.T) {
	cert := makeCert(t, "Self-Signed Test CN", "Self-Signed Test CN")
	sig := classifyCert(cert)
	if sig.Status != "self-signed" {
		t.Errorf("Status=%q want self-signed", sig.Status)
	}
}

func TestClassifyCert_TrustedMicrosoft(t *testing.T) {
	cert := makeCertIssuedBy(t, "Microsoft Code Signing PCA 2011", "MyApp Inc.")
	sig := classifyCert(cert)
	if sig.Status != "trusted-microsoft" {
		t.Errorf("Status=%q want trusted-microsoft", sig.Status)
	}
}

func TestClassifyCert_TrustedMicrosoftWindowsProductionPCA(t *testing.T) {
	cert := makeCertIssuedBy(t, "Microsoft Windows Production PCA 2011", "Win App")
	sig := classifyCert(cert)
	if sig.Status != "trusted-microsoft" {
		t.Errorf("Status=%q want trusted-microsoft", sig.Status)
	}
}

func TestClassifyCert_TrustedOther(t *testing.T) {
	cert := makeCertIssuedBy(t, "DigiCert Trusted G4 Code Signing CA", "ACME Corp")
	sig := classifyCert(cert)
	if sig.Status != "trusted-other" {
		t.Errorf("Status=%q want trusted-other", sig.Status)
	}
}

func TestClassifyCert_NilSafe(t *testing.T) {
	if classifyCert(nil).Status != "invalid" {
		t.Error("nil cert should classify as invalid")
	}
}

func TestIsMicrosoftIssuer(t *testing.T) {
	yes := []string{
		"Microsoft Code Signing PCA",
		"Microsoft Code Signing PCA 2011",
		"Microsoft Windows Production PCA 2011",
		"Microsoft Root Certificate Authority 2010",
	}
	for _, cn := range yes {
		if !isMicrosoftIssuer(cn) {
			t.Errorf("isMicrosoftIssuer(%q) should be true", cn)
		}
	}
	no := []string{"DigiCert", "Sectigo", "Self-Signed CN", ""}
	for _, cn := range no {
		if isMicrosoftIssuer(cn) {
			t.Errorf("isMicrosoftIssuer(%q) should be false", cn)
		}
	}
}

// ----- helpers -----

func makeZip(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := zip.NewWriter(f)
	for name, body := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func makeCert(t *testing.T, subjectCN, issuerCN string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subjectCN},
		Issuer:       pkix.Name{CommonName: issuerCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeCertIssuedBy(t *testing.T, issuerCN, subjectCN string) *x509.Certificate {
	t.Helper()
	issuerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: issuerCN},
		Issuer:                pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerPriv.PublicKey, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: subjectCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerCert, &leafPriv.PublicKey, issuerPriv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
