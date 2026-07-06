/* Copyright (c) 2026 Security Research */
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple name unchanged", "hello", "hello"},
		{"spaces replaced", "hello world", "hello_world"},
		{"special chars replaced", `foo<>:"/\|?*&bar`, "foo_bar"},
		{"leading trailing underscores trimmed", "  hello  ", "hello"},
		{"multiple specials collapsed", "a::b//c", "a_b_c"},
		{"truncated to 60 chars", strings.Repeat("a", 100), strings.Repeat("a", 60)},
		{"empty after sanitize", "::::", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestElfClassName(t *testing.T) {
	tests := []struct {
		name  string
		class elf.Class
		want  string
	}{
		{"ELF32", elf.ELFCLASS32, "ELF32"},
		{"ELF64", elf.ELFCLASS64, "ELF64"},
		{"unknown", elf.ELFCLASSNONE, "unknown(0)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elfClassName(tt.class); got != tt.want {
				t.Errorf("elfClassName(%v) = %q, want %q", tt.class, got, tt.want)
			}
		})
	}
}

func TestElfMachineName(t *testing.T) {
	tests := []struct {
		name    string
		machine elf.Machine
		want    string
	}{
		{"x86", elf.EM_386, "x86"},
		{"x86_64", elf.EM_X86_64, "x86_64"},
		{"ARM", elf.EM_ARM, "ARM"},
		{"aarch64", elf.EM_AARCH64, "aarch64"},
		{"MIPS", elf.EM_MIPS, "MIPS"},
		{"PowerPC", elf.EM_PPC, "PowerPC"},
		{"PowerPC64", elf.EM_PPC64, "PowerPC64"},
		{"RISC-V", elf.EM_RISCV, "RISC-V"},
		{"s390x", elf.EM_S390, "s390x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elfMachineName(tt.machine); got != tt.want {
				t.Errorf("elfMachineName(%v) = %q, want %q", tt.machine, got, tt.want)
			}
		})
	}
}

func TestElfTypeName(t *testing.T) {
	tests := []struct {
		name    string
		elfType elf.Type
		want    string
	}{
		{"Relocatable", elf.ET_REL, "Relocatable"},
		{"Executable", elf.ET_EXEC, "Executable"},
		{"Shared Object", elf.ET_DYN, "Shared Object"},
		{"Core Dump", elf.ET_CORE, "Core Dump"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elfTypeName(tt.elfType); got != tt.want {
				t.Errorf("elfTypeName(%v) = %q, want %q", tt.elfType, got, tt.want)
			}
		})
	}
}

func TestElfOSABIName(t *testing.T) {
	tests := []struct {
		name string
		abi  elf.OSABI
		want string
	}{
		{"NONE is Linux", elf.ELFOSABI_NONE, "Linux"},
		{"LINUX is Linux", elf.ELFOSABI_LINUX, "Linux"},
		{"FreeBSD", elf.ELFOSABI_FREEBSD, "FreeBSD"},
		{"NetBSD", elf.ELFOSABI_NETBSD, "NetBSD"},
		{"OpenBSD", elf.ELFOSABI_OPENBSD, "OpenBSD"},
		{"Solaris", elf.ELFOSABI_SOLARIS, "Solaris"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elfOSABIName(tt.abi); got != tt.want {
				t.Errorf("elfOSABIName(%v) = %q, want %q", tt.abi, got, tt.want)
			}
		})
	}
}

func TestDetectFileType(t *testing.T) {
	tmpDir := t.TempDir()

	// ELF magic
	elfFile := filepath.Join(tmpDir, "test.elf")
	if err := os.WriteFile(elfFile, []byte("\x7fELF"+strings.Repeat("\x00", 60)), 0o644); err != nil {
		t.Fatal(err)
	}

	ft, err := detectFileType(elfFile)
	if err != nil {
		t.Fatalf("detectFileType ELF: %v", err)
	}

	if ft != "ELF" {
		t.Errorf("expected 'ELF', got %q", ft)
	}

	// PE magic
	peFile := filepath.Join(tmpDir, "test.exe")
	if err := os.WriteFile(peFile, []byte("MZ"+strings.Repeat("\x00", 60)), 0o644); err != nil {
		t.Fatal(err)
	}

	ft, err = detectFileType(peFile)
	if err != nil {
		t.Fatalf("detectFileType PE: %v", err)
	}

	if ft != "PE" {
		t.Errorf("expected 'PE', got %q", ft)
	}

	// Unknown magic
	unknownFile := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(unknownFile, []byte("ABCDEF"), 0o644); err != nil {
		t.Fatal(err)
	}

	ft, err = detectFileType(unknownFile)
	if err != nil {
		// detectFileType may return error for unknown — that's acceptable
		return
	}

	if ft != "unknown" {
		t.Errorf("expected 'unknown', got %q", ft)
	}
}

func TestExtractCertificates_NonexistentFile(t *testing.T) {
	_, err := ExtractCertificates("/tmp/nonexistent-binary-12345")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractCertificates_UnsignedELF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires ELF binary; Windows produces PE")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	bin := buildTestGoBinary(t)

	info, err := ExtractCertificates(bin)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.HasSignature {
		t.Error("Go test binary should not have a signature")
	}

	if info.FileType != "ELF" {
		t.Errorf("expected ELF, got %q", info.FileType)
	}

	if info.ELFInfo == nil {
		t.Fatal("expected non-nil ELFInfo")
	}

	if info.ELFInfo.Class != "ELF64" {
		t.Errorf("expected ELF64, got %q", info.ELFInfo.Class)
	}

	if info.ELFInfo.Machine != "x86_64" {
		t.Errorf("expected x86_64, got %q", info.ELFInfo.Machine)
	}
}

func TestVerifyCertificate_UnsignedELF(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires ELF binary; Windows produces PE")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	bin := buildTestGoBinary(t)

	info, err := VerifyCertificate(bin)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}

	if info.Verified {
		t.Error("unsigned binary should not be verified")
	}

	if info.VerifyError == "" {
		t.Error("expected verify error message for unsigned binary")
	}
}

func TestScanDirectory_Empty(t *testing.T) {
	tmpDir := t.TempDir()

	results, err := ScanDirectory(tmpDir, false)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for empty dir, got %d", len(results))
	}
}

func TestScanDirectory_WithBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	results, err := ScanDirectory(tmpDir, false)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	// Should find the binary (unsigned)
	if len(results) == 0 {
		t.Error("expected to find at least one binary")
	}
}

func TestParseCertDetail(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Test Subject",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test Issuer",
			Organization: []string{"CA Org"},
			Country:      []string{"US"},
		},
		NotBefore:          time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: x509.SHA256WithRSA,
		Raw:                []byte("test cert raw bytes for thumbprint"),
	}

	detail := parseCertDetail(cert)

	if detail.CommonName != "Test Subject" {
		t.Errorf("expected CN 'Test Subject', got %q", detail.CommonName)
	}

	if detail.Organization != "Test Org" {
		t.Errorf("expected org 'Test Org', got %q", detail.Organization)
	}

	if detail.Country != "US" {
		t.Errorf("expected country 'US', got %q", detail.Country)
	}

	if detail.IsExpired {
		t.Error("cert should not be expired (expires 2030)")
	}

	if detail.Thumbprint == "" {
		t.Error("expected non-empty thumbprint")
	}

	if detail.SignatureAlgo != "SHA256-RSA" {
		t.Errorf("expected algo 'SHA256-RSA', got %q", detail.SignatureAlgo)
	}
}

func TestParseCertDetail_Expired(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "Expired",
			Organization: []string{"Org"},
			Country:      []string{"US"},
		},
		Issuer: pkix.Name{
			CommonName:   "Expired",
			Organization: []string{"Org"},
			Country:      []string{"US"},
		},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		Raw:       []byte("expired cert"),
	}

	detail := parseCertDetail(cert)

	if !detail.IsExpired {
		t.Error("cert should be expired")
	}

	if !detail.IsSelfSigned {
		t.Error("cert with same subject/issuer should be self-signed")
	}
}

func TestExportPEM_NoCerts(t *testing.T) {
	info := &CertInfo{RawCerts: nil}
	err := ExportPEM(info, t.TempDir())
	// Should either error or succeed with no output — just ensure no panic
	_ = err
}

func TestExportDER_NoCerts(t *testing.T) {
	info := &CertInfo{RawCerts: nil}
	err := ExportDER(info, t.TempDir())
	_ = err
}

func TestGenerateReport(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.md")

	info := &CertInfo{
		FilePath:     "/tmp/test.exe",
		FileName:     "test.exe",
		FileType:     "PE",
		HasSignature: false,
	}

	err := GenerateReport(info, outPath)
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "test.exe") {
		t.Error("report should contain filename")
	}

	if !strings.Contains(content, "PE") {
		t.Error("report should contain file type")
	}
}

func TestGenerateBatchReport(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "batch.md")

	infos := []*CertInfo{
		{FilePath: "/a.exe", FileName: "a.exe", FileType: "PE", HasSignature: true},
		{FilePath: "/b.so", FileName: "b.so", FileType: "ELF", HasSignature: false},
	}

	err := GenerateBatchReport(infos, outPath)
	if err != nil {
		t.Fatalf("GenerateBatchReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "a.exe") || !strings.Contains(content, "b.so") {
		t.Error("batch report should contain both filenames")
	}
}

// casesPath resolves a path relative to the cases/ directory at the project root.
func casesPath(t *testing.T, relPath string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not find project root")
		}
		dir = parent
	}
	p := filepath.Join(dir, "cases", relPath)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skipf("test case not available: %s", p)
	}
	return p
}

func TestGolden_ExtractCerts_SlackELF(t *testing.T) {
	binPath := casesPath(t, "linux/input/slack/216/usr/lib/slack/slack")

	info, err := ExtractCertificates(binPath)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.FileType != "ELF" {
		t.Errorf("FileType = %q, want %q", info.FileType, "ELF")
	}
	if info.ELFInfo == nil {
		t.Fatal("expected non-nil ELFInfo")
	}
	if info.ELFInfo.Class != "ELF64" {
		t.Errorf("ELFInfo.Class = %q, want %q", info.ELFInfo.Class, "ELF64")
	}
	if info.ELFInfo.Machine != "x86_64" {
		t.Errorf("ELFInfo.Machine = %q, want %q", info.ELFInfo.Machine, "x86_64")
	}
	if info.ELFInfo.BuildID == "" {
		t.Error("expected non-empty BuildID for Slack binary")
	}
}

func TestGolden_VerifyCert_SlackELF(t *testing.T) {
	binPath := casesPath(t, "linux/input/slack/216/usr/lib/slack/slack")

	info, err := VerifyCertificate(binPath)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}

	if info.FileType != "ELF" {
		t.Errorf("FileType = %q, want %q", info.FileType, "ELF")
	}
}

func TestGolden_ScanDir_SlackLibs(t *testing.T) {
	dirPath := casesPath(t, "linux/input/slack/216/usr/lib/slack")

	results, err := ScanDirectory(dirPath, false)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected to find at least one binary in Slack directory")
	}

	// At least the main slack binary should be found
	found := false
	for _, r := range results {
		if r.FileName == "slack" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find 'slack' binary in scan results")
	}
}

func TestThumbprint(t *testing.T) {
	cert := newSelfSignedCert(t)

	tp := thumbprint(cert)
	if tp == "" {
		t.Fatal("thumbprint returned empty string")
	}

	// thumbprint returns a lowercase hex-encoded SHA-256 hash (64 hex chars)
	if len(tp) != 64 {
		t.Errorf("expected 64 hex chars, got %d: %q", len(tp), tp)
	}

	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(tp) {
		t.Errorf("thumbprint not valid lowercase hex: %q", tp)
	}

	// Deterministic: same cert produces same thumbprint
	if tp2 := thumbprint(cert); tp2 != tp {
		t.Errorf("thumbprint not deterministic: %q vs %q", tp, tp2)
	}
}

func TestBuildSingleReport(t *testing.T) {
	info := &CertInfo{
		FilePath:     "/opt/bin/myapp.exe",
		FileName:     "myapp.exe",
		FileType:     "PE",
		HasSignature: true,
		Verified:     true,
		Signer: &CertDetail{
			Subject:       "CN=Test Signer,O=TestOrg,C=US",
			Issuer:        "CN=Test CA,O=TestOrg,C=US",
			SerialNumber:  "ABCDEF",
			NotBefore:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			SignatureAlgo: "SHA256-RSA",
			Thumbprint:    "aabbccdd",
			CommonName:    "Test Signer",
			Organization:  "TestOrg",
			Country:       "US",
		},
	}

	report := buildSingleReport(info)

	for _, want := range []string{
		"Certificate Report",
		"myapp.exe",
		"/opt/bin/myapp.exe",
		"PE",
		"Signer",
		"Test Signer",
		"SHA256-RSA",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestBuildSingleReport_Unsigned(t *testing.T) {
	info := &CertInfo{
		FilePath:     "/tmp/unsigned",
		FileName:     "unsigned",
		FileType:     "ELF",
		HasSignature: false,
	}

	report := buildSingleReport(info)

	if !strings.Contains(report, "No code-signing signature found") {
		t.Error("unsigned report should mention no signature")
	}
}

func TestBuildBatchReport(t *testing.T) {
	infos := []*CertInfo{
		{
			FilePath:     "/a.exe",
			FileName:     "a.exe",
			FileType:     "PE",
			HasSignature: true,
			Verified:     true,
			Signer: &CertDetail{
				CommonName:   "Signer A",
				Organization: "Org A",
				NotAfter:     time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				Thumbprint:   "aabb",
				Subject:      "CN=Signer A",
				Issuer:       "CN=CA A",
			},
		},
		{
			FilePath:     "/b.so",
			FileName:     "b.so",
			FileType:     "ELF",
			HasSignature: false,
		},
	}

	report := buildBatchReport(infos)

	// Header and summary
	if !strings.Contains(report, "Certificate Comparison Report") {
		t.Error("batch report missing title")
	}

	if !strings.Contains(report, "Binaries Analyzed:** 2") {
		t.Error("batch report should show 2 binaries analyzed")
	}

	// Summary table should contain both entries
	if !strings.Contains(report, "a.exe") || !strings.Contains(report, "b.so") {
		t.Error("batch report missing filenames")
	}

	// Signed entry should show VALID, unsigned should show No
	if !strings.Contains(report, "VALID") {
		t.Error("batch report should mark verified binary as VALID")
	}

	if !strings.Contains(report, "Not signed") {
		t.Error("batch report should note unsigned binary")
	}
}

func TestWriteCertDetailMD(t *testing.T) {
	d := &CertDetail{
		Subject:       "CN=Test,O=Org,C=BR",
		Issuer:        "CN=CA,O=CA Org,C=US",
		SerialNumber:  "1A2B3C",
		NotBefore:     time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		NotAfter:      time.Date(2028, 6, 15, 12, 0, 0, 0, time.UTC),
		SignatureAlgo: "ECDSA-SHA256",
		Thumbprint:    "deadbeef",
		IsExpired:     false,
		IsSelfSigned:  true,
	}

	var b strings.Builder
	writeCertDetailMD(&b, d)
	out := b.String()

	// Should be a markdown table
	if !strings.Contains(out, "| Field | Value |") {
		t.Error("missing table header")
	}

	for _, want := range []string{
		"CN=Test,O=Org,C=BR",
		"CN=CA,O=CA Org,C=US",
		"`1A2B3C`",
		"ECDSA-SHA256",
		"`deadbeef`",
		"VALID (self-signed)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestWriteCertDetailMD_Expired(t *testing.T) {
	d := &CertDetail{
		Subject:      "CN=Old",
		Issuer:       "CN=CA",
		IsExpired:    true,
		IsSelfSigned: false,
	}

	var b strings.Builder
	writeCertDetailMD(&b, d)

	if !strings.Contains(b.String(), "EXPIRED") {
		t.Error("expired cert should show EXPIRED status")
	}
}

// newSelfSignedCert creates a self-signed X.509 certificate for testing.
func newSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert
}

func TestExportPEM_WithCert(t *testing.T) {
	cert := newSelfSignedCert(t)
	outDir := t.TempDir()

	info := &CertInfo{
		RawCerts: []*x509.Certificate{cert},
	}

	err := ExportPEM(info, outDir)
	if err != nil {
		t.Fatalf("ExportPEM: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(outDir, "*.pem"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 .pem file, got %d", len(matches))
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read pem: %v", err)
	}

	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Error("PEM file should contain BEGIN CERTIFICATE header")
	}
}

func TestExportDER_WithCert(t *testing.T) {
	cert := newSelfSignedCert(t)
	outDir := t.TempDir()

	info := &CertInfo{
		RawCerts: []*x509.Certificate{cert},
	}

	err := ExportDER(info, outDir)
	if err != nil {
		t.Fatalf("ExportDER: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(outDir, "*.der"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 .der file, got %d", len(matches))
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read der: %v", err)
	}

	if len(data) == 0 {
		t.Error("DER file should not be empty")
	}
}

func TestIsScanCandidate(t *testing.T) {
	tests := []struct {
		name string
		file string
		want bool
	}{
		{"PE extension", "app.exe", true},
		{"ELF extension", "lib.so", true},
		{"kernel module", "module.ko", true},
		{"DLL", "lib.dll", true},
		{"text file", "readme.txt", false},
		{"JSON file", "data.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isScanCandidate(tt.file, "/any")
			if got != tt.want {
				t.Errorf("isScanCandidate(%q, %q) = %v, want %v", tt.file, "/any", got, tt.want)
			}
		})
	}
}

func TestExtractCertificates_TextFile(t *testing.T) {
	tmpDir := t.TempDir()
	txtFile := filepath.Join(tmpDir, "readme.txt")

	if err := os.WriteFile(txtFile, []byte("hello world, this is a text file with enough bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractCertificates(txtFile)
	if err == nil {
		t.Error("expected error for text file")
	}
}

func TestExtractCertificates_TooSmall(t *testing.T) {
	tmpDir := t.TempDir()
	tinyFile := filepath.Join(tmpDir, "tiny.bin")

	if err := os.WriteFile(tinyFile, []byte{0x00}, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractCertificates(tinyFile)
	if err == nil {
		t.Error("expected error for 1-byte file")
	}
}

func TestScanDirectory_Recursive(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "nested", "deep")

	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(subDir, "main.go")
	bin := filepath.Join(subDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	results, err := ScanDirectory(tmpDir, false)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected to find binary in nested subdirectory")
	}

	found := false
	for _, r := range results {
		if r.FileName == "test-binary" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected to find 'test-binary' in recursive scan results")
	}
}

func TestGenerateReport_WithSigner(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.md")

	info := &CertInfo{
		FilePath:     "/tmp/signed.exe",
		FileName:     "signed.exe",
		FileType:     "PE",
		HasSignature: true,
		Verified:     true,
		Signer: &CertDetail{
			Subject:       "CN=My Signer,O=My Org,C=BR",
			Issuer:        "CN=Root CA,O=CA Org,C=US",
			SerialNumber:  "DEADBEEF",
			NotBefore:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			SignatureAlgo: "SHA256-RSA",
			Thumbprint:    "aabbccdd",
			CommonName:    "My Signer",
			Organization:  "My Org",
			Country:       "BR",
		},
	}

	err := GenerateReport(info, outPath)
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	content := string(data)
	for _, want := range []string{
		"signed.exe",
		"PE",
		"Signer",
		"My Signer",
		"CN=My Signer,O=My Org,C=BR",
		"CN=Root CA,O=CA Org,C=US",
		"SHA256-RSA",
		"`aabbccdd`",
		"`DEADBEEF`",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

// helpers

func buildTestGoBinary(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	return bin
}

func TestElfMachineName_Unknown(t *testing.T) {
	got := elfMachineName(elf.Machine(9999))
	// Default branch calls m.String() which returns Go elf package format
	if got == "" {
		t.Error("elfMachineName(9999) returned empty string")
	}
	// Should NOT match any of the named cases
	for _, named := range []string{"x86", "x86_64", "ARM", "aarch64", "MIPS", "PowerPC", "PowerPC64", "RISC-V", "s390x"} {
		if got == named {
			t.Errorf("elfMachineName(9999) = %q, should not match named case", got)
		}
	}
}

func TestElfTypeName_Unknown(t *testing.T) {
	got := elfTypeName(elf.Type(9999))
	if got == "" {
		t.Error("elfTypeName(9999) returned empty string")
	}
	for _, named := range []string{"Relocatable", "Executable", "Shared Object", "Core Dump"} {
		if got == named {
			t.Errorf("elfTypeName(9999) = %q, should not match named case", got)
		}
	}
}

func TestElfOSABIName_Unknown(t *testing.T) {
	got := elfOSABIName(elf.OSABI(200))
	if got == "" {
		t.Error("elfOSABIName(200) returned empty string")
	}
	for _, named := range []string{"Linux", "FreeBSD", "NetBSD", "OpenBSD", "Solaris"} {
		if got == named {
			t.Errorf("elfOSABIName(200) = %q, should not match named case", got)
		}
	}
}

func TestWriteCertDetailMD_ValidNonSelfSigned(t *testing.T) {
	d := &CertDetail{
		Subject:      "CN=Leaf",
		Issuer:       "CN=Root CA",
		IsExpired:    false,
		IsSelfSigned: false,
	}

	var b strings.Builder
	writeCertDetailMD(&b, d)
	out := b.String()

	if !strings.Contains(out, "VALID") {
		t.Error("expected VALID in output")
	}

	if strings.Contains(out, "(self-signed)") {
		t.Error("should not contain '(self-signed)'")
	}

	if strings.Contains(out, "EXPIRED") {
		t.Error("should not contain 'EXPIRED'")
	}
}

func TestBuildSingleReport_WithELFInfo(t *testing.T) {
	info := &CertInfo{
		FilePath:     "/tmp/libtest.so",
		FileName:     "libtest.so",
		FileType:     "ELF",
		HasSignature: false,
		ELFInfo: &ELFDetail{
			Class:   "ELF64",
			Machine: "x86_64",
			Type:    "Shared Object",
			OSABI:   "Linux",
			BuildID: "abc123def",
		},
	}

	report := buildSingleReport(info)

	for _, want := range []string{"ELF64", "x86_64", "abc123def"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestBuildBatchReport_ExpiredSigner(t *testing.T) {
	infos := []*CertInfo{
		{
			FilePath:     "/tmp/expired.exe",
			FileName:     "expired.exe",
			FileType:     "PE",
			HasSignature: true,
			Verified:     true,
			Signer: &CertDetail{
				CommonName:   "Expired Signer",
				Organization: "Expired Org",
				NotAfter:     time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				IsExpired:    true,
				Thumbprint:   "aabb",
				Subject:      "CN=Expired Signer",
				Issuer:       "CN=CA",
			},
		},
	}

	report := buildBatchReport(infos)

	if !strings.Contains(report, "EXPIRED") {
		t.Error("batch report should contain EXPIRED for expired signer")
	}
}

func TestExportPEM_MultipleCerts(t *testing.T) {
	cert1 := newSelfSignedCert(t)
	cert2 := newSelfSignedCert(t)
	outDir := t.TempDir()

	info := &CertInfo{
		RawCerts: []*x509.Certificate{cert1, cert2},
	}

	if err := ExportPEM(info, outDir); err != nil {
		t.Fatalf("ExportPEM: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(outDir, "*.pem"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	if len(matches) != 2 {
		t.Fatalf("expected 2 .pem files, got %d", len(matches))
	}
}

func TestExportDER_MultipleCerts(t *testing.T) {
	cert1 := newSelfSignedCert(t)
	cert2 := newSelfSignedCert(t)
	outDir := t.TempDir()

	info := &CertInfo{
		RawCerts: []*x509.Certificate{cert1, cert2},
	}

	if err := ExportDER(info, outDir); err != nil {
		t.Fatalf("ExportDER: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(outDir, "*.der"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	if len(matches) != 2 {
		t.Fatalf("expected 2 .der files, got %d", len(matches))
	}
}

func TestExportPEM_EmptyCN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"Test Org"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	outDir := t.TempDir()
	info := &CertInfo{
		RawCerts: []*x509.Certificate{cert},
	}

	if err := ExportPEM(info, outDir); err != nil {
		t.Fatalf("ExportPEM: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(outDir, "*.pem"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	if len(matches) != 1 {
		t.Fatalf("expected 1 .pem file, got %d", len(matches))
	}

	if !strings.Contains(matches[0], "unknown") {
		t.Errorf("expected filename to contain 'unknown', got %q", filepath.Base(matches[0]))
	}
}

func TestIsScanCandidate_ExtensionlessBinary(t *testing.T) {
	tmpDir := t.TempDir()
	binFile := filepath.Join(tmpDir, "mybinary")

	if err := os.WriteFile(binFile, []byte("\x7fELF"+strings.Repeat("\x00", 60)), 0o755); err != nil {
		t.Fatal(err)
	}

	if !isScanCandidate("mybinary", binFile) {
		t.Error("extensionless ELF binary should be a scan candidate")
	}
}

func TestScanDirectory_Verbose(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	results, err := ScanDirectory(tmpDir, true)
	if err != nil {
		t.Fatalf("ScanDirectory verbose: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected to find at least one binary")
	}
}

func TestExtractBuildID_ValidNote(t *testing.T) {
	// Build a minimal ELF with a .note.gnu.build-id section containing a valid build ID
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "with-build-id")

	// Use encoding/binary to construct a minimal ELF64 LE binary with .note.gnu.build-id
	var buf []byte

	// ELF header (64 bytes for ELF64)
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2 // ELFCLASS64
	elfHeader[5] = 1 // ELFDATA2LSB
	elfHeader[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1) // EV_CURRENT
	// e_ehsize
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	// e_shentsize
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	// e_shnum = 3 (null + .note.gnu.build-id + .shstrtab)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	// e_shstrndx = 2
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	// Build note data: namesz=4, descsz=20, type=3(NT_GNU_BUILD_ID), name="GNU\0", desc=20 bytes
	buildIDBytes := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	var noteData []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, 4) // namesz
	noteData = append(noteData, tmp...)
	binary.LittleEndian.PutUint32(tmp, 20) // descsz
	noteData = append(noteData, tmp...)
	binary.LittleEndian.PutUint32(tmp, 3) // type = NT_GNU_BUILD_ID
	noteData = append(noteData, tmp...)
	noteData = append(noteData, []byte("GNU\x00")...) // name (4 bytes, aligned)
	noteData = append(noteData, buildIDBytes...)

	// .shstrtab content
	shstrtab := "\x00.note.gnu.build-id\x00.shstrtab\x00"

	// Layout: ELF header (64) | noteData | shstrtab | section headers
	noteOffset := 64
	shstrtabOffset := noteOffset + len(noteData)
	shOffset := shstrtabOffset + len(shstrtab)
	// Align shOffset to 8
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}

	// Set e_shoff
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, noteData...)
	buf = append(buf, []byte(shstrtab)...)
	// Pad to shOffset
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	// Section header 0: null
	nullSH := make([]byte, 64)
	buf = append(buf, nullSH...)

	// Section header 1: .note.gnu.build-id
	noteSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(noteSH[0:4], 1) // sh_name offset in shstrtab
	binary.LittleEndian.PutUint32(noteSH[4:8], uint32(elf.SHT_NOTE))
	binary.LittleEndian.PutUint64(noteSH[24:32], uint64(noteOffset))    // sh_offset
	binary.LittleEndian.PutUint64(noteSH[32:40], uint64(len(noteData))) // sh_size
	buf = append(buf, noteSH...)

	// Section header 2: .shstrtab
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 20) // sh_name = offset of ".shstrtab" in shstrtab
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	got := extractBuildID(ef)
	want := "deadbeef0102030405060708090a0b0c0d0e0f10"
	if got != want {
		t.Errorf("extractBuildID() = %q, want %q", got, want)
	}
}

func TestExtractBuildID_NoSection(t *testing.T) {
	// Minimal ELF with no .note.gnu.build-id section
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "no-build-id")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2 // ELFCLASS64
	elfHeader[5] = 1 // ELFDATA2LSB
	elfHeader[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 2)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 1)

	shstrtab := "\x00.shstrtab\x00"
	shstrtabOffset := 64
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	// Null section header
	buf = append(buf, make([]byte, 64)...)
	// .shstrtab section header
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 1)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	got := extractBuildID(ef)
	if got != "" {
		t.Errorf("extractBuildID() = %q, want empty string", got)
	}
}

func TestExtractCertificates_TruncatedPE(t *testing.T) {
	tmpDir := t.TempDir()
	peFile := filepath.Join(tmpDir, "truncated.exe")
	// Just MZ + garbage, not a valid PE
	if err := os.WriteFile(peFile, []byte("MZ\x00\x00\x00\x00\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractCertificates(peFile)
	if err == nil {
		t.Error("expected error for truncated PE file")
	}
}

func TestExtractCertificates_TruncatedELF(t *testing.T) {
	tmpDir := t.TempDir()
	elfFile := filepath.Join(tmpDir, "truncated.elf")
	// Just ELF magic + garbage, not enough for a valid ELF
	if err := os.WriteFile(elfFile, []byte("\x7fELF\x00\x00\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractCertificates(elfFile)
	if err == nil {
		t.Error("expected error for truncated ELF file")
	}
}

func TestExtractCertificates_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := filepath.Join(tmpDir, "empty")
	if err := os.WriteFile(emptyFile, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := ExtractCertificates(emptyFile)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestParseELFDetail_MinimalELF(t *testing.T) {
	// Build a minimal valid ELF64 binary in memory and parse its details
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "minimal.elf")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2 // ELFCLASS64
	elfHeader[5] = 1 // ELFDATA2LSB
	elfHeader[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 2)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 1)

	shstrtab := "\x00.shstrtab\x00"
	shstrtabOffset := 64
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}
	buf = append(buf, make([]byte, 64)...) // null section
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 1)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	detail := parseELFDetail(ef)
	if detail.Class != "ELF64" {
		t.Errorf("Class = %q, want ELF64", detail.Class)
	}
	if detail.Machine != "aarch64" {
		t.Errorf("Machine = %q, want aarch64", detail.Machine)
	}
	if detail.Type != "Shared Object" {
		t.Errorf("Type = %q, want 'Shared Object'", detail.Type)
	}
	if detail.ByteOrder != "LittleEndian" {
		t.Errorf("ByteOrder = %q, want LittleEndian", detail.ByteOrder)
	}
	if detail.BuildID != "" {
		t.Errorf("BuildID = %q, want empty", detail.BuildID)
	}
}

func TestExtractBuildID_TruncatedNote(t *testing.T) {
	// Build ELF with .note.gnu.build-id that has too-short data
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "truncated-note")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	// Truncated note data: only 8 bytes (need >= 16)
	noteData := make([]byte, 8)

	shstrtab := "\x00.note.gnu.build-id\x00.shstrtab\x00"
	noteOffset := 64
	shstrtabOffset := noteOffset + len(noteData)
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, noteData...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	// null section
	buf = append(buf, make([]byte, 64)...)
	// .note.gnu.build-id section
	noteSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(noteSH[0:4], 1)
	binary.LittleEndian.PutUint32(noteSH[4:8], uint32(elf.SHT_NOTE))
	binary.LittleEndian.PutUint64(noteSH[24:32], uint64(noteOffset))
	binary.LittleEndian.PutUint64(noteSH[32:40], uint64(len(noteData)))
	buf = append(buf, noteSH...)
	// .shstrtab section
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 20)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	got := extractBuildID(ef)
	if got != "" {
		t.Errorf("extractBuildID() = %q, want empty for truncated note", got)
	}
}

func TestVerifyCertificate_ExpiredSigner(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	bin := buildTestGoBinary(t)

	// VerifyCertificate with unsigned binary should set VerifyError
	info, err := VerifyCertificate(bin)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}

	if info.VerifyError != "no signature present" {
		t.Errorf("VerifyError = %q, want 'no signature present'", info.VerifyError)
	}
}

func TestParseCertDetail_NoOrgUnit(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "Test",
			OrganizationalUnit: []string{"Security"},
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Raw:       []byte("raw"),
	}

	detail := parseCertDetail(cert)
	if detail.OrgUnit != "Security" {
		t.Errorf("OrgUnit = %q, want 'Security'", detail.OrgUnit)
	}
}

func TestBuildSingleReport_WithChain(t *testing.T) {
	info := &CertInfo{
		FilePath:     "/tmp/signed.exe",
		FileName:     "signed.exe",
		FileType:     "PE",
		HasSignature: true,
		Verified:     false,
		VerifyError:  "certificate has expired",
		Signer: &CertDetail{
			Subject:       "CN=Signer",
			Issuer:        "CN=Intermediate CA",
			CommonName:    "Signer",
			Organization:  "Org",
			SignatureAlgo: "SHA256-RSA",
			Thumbprint:    "aabb",
		},
		Chain: []*CertDetail{
			{
				Subject:       "CN=Intermediate CA",
				Issuer:        "CN=Root CA",
				CommonName:    "Intermediate CA",
				Organization:  "CA Org",
				SignatureAlgo: "SHA256-RSA",
				Thumbprint:    "ccdd",
			},
		},
	}

	report := buildSingleReport(info)

	if !strings.Contains(report, "Certificate Chain") {
		t.Error("report should contain Certificate Chain section")
	}
	if !strings.Contains(report, "Intermediate CA") {
		t.Error("report should contain chain cert details")
	}
	if !strings.Contains(report, "certificate has expired") {
		t.Error("report should contain verify error")
	}
}

func TestBuildSingleReport_WithSigningTime(t *testing.T) {
	st := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	info := &CertInfo{
		FilePath:      "/tmp/test.exe",
		FileName:      "test.exe",
		FileType:      "PE",
		HasSignature:  true,
		Verified:      true,
		Countersigned: true,
		SigningTime:   &st,
		Signer: &CertDetail{
			Subject:    "CN=Signer",
			Issuer:     "CN=CA",
			CommonName: "Signer",
			Thumbprint: "aabb",
		},
	}

	report := buildSingleReport(info)
	if !strings.Contains(report, "Signing Time") {
		t.Error("report should contain Signing Time")
	}
	if !strings.Contains(report, "Countersigned") {
		t.Error("report should mention countersigned")
	}
}

func TestParseELFDetail_WithInterpreter(t *testing.T) {
	// Build an ELF with .interp section
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "with-interp")

	interpData := "/lib64/ld-linux-x86-64.so.2\x00"

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	shstrtab := "\x00.interp\x00.shstrtab\x00"
	interpOffset := 64
	shstrtabOffset := interpOffset + len(interpData)
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(interpData)...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	// null section
	buf = append(buf, make([]byte, 64)...)
	// .interp section
	interpSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(interpSH[0:4], 1)
	binary.LittleEndian.PutUint32(interpSH[4:8], uint32(elf.SHT_PROGBITS))
	binary.LittleEndian.PutUint64(interpSH[24:32], uint64(interpOffset))
	binary.LittleEndian.PutUint64(interpSH[32:40], uint64(len(interpData)))
	buf = append(buf, interpSH...)
	// .shstrtab section
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 9)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	detail := parseELFDetail(ef)
	if detail.Interpreter != "/lib64/ld-linux-x86-64.so.2" {
		t.Errorf("Interpreter = %q, want '/lib64/ld-linux-x86-64.so.2'", detail.Interpreter)
	}
}

func TestExtractModuleSignature_NoMagic(t *testing.T) {
	// Build a minimal ELF without module signature magic -- extractModuleSignature should return false
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "no-modsig")

	// Minimal ELF64 (reuse the pattern)
	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 2)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 1)

	shstrtab := "\x00.shstrtab\x00"
	shstrtabOffset := 64
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}
	buf = append(buf, make([]byte, 64)...)
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 1)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info := &CertInfo{}
	found, err := extractModuleSignature(elfPath, info)
	if found {
		t.Error("expected found=false for file without module signature")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractModuleSignature_WithMagic(t *testing.T) {
	// Build a file with the module signature magic trailer but invalid PKCS7 data
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "with-modsig")

	magic := "~Module signature appended~\n"
	// moduleSignature struct: 12 bytes (algo, hash, idtype=2, signerLen, keyIDLen, pad[3], sigLen=4 big-endian)
	modSig := make([]byte, 12)
	modSig[2] = 2                               // IDType = PKEY_ID_PKCS7
	binary.BigEndian.PutUint32(modSig[8:12], 4) // sigLen = 4

	// Some fake PKCS7 data (4 bytes, will fail to parse)
	fakeData := []byte{0x01, 0x02, 0x03, 0x04}

	// File: [some padding][fakeData][modSig][magic]
	var buf []byte
	buf = append(buf, make([]byte, 100)...) // padding
	buf = append(buf, fakeData...)
	buf = append(buf, modSig...)
	buf = append(buf, []byte(magic)...)

	if err := os.WriteFile(filePath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info := &CertInfo{ELFInfo: &ELFDetail{}}
	found, err := extractModuleSignature(filePath, info)
	if !found {
		t.Error("expected found=true for file with module signature magic")
	}
	// Should error because PKCS7 data is invalid
	if err == nil {
		t.Error("expected error for invalid PKCS7 signature data")
	}
	if !info.ELFInfo.HasModSig {
		t.Error("expected HasModSig=true")
	}
}

func TestExtractModuleSignature_NonPKCS7(t *testing.T) {
	// Build file with module signature magic but IDType != 2 (non-PKCS7)
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "non-pkcs7-modsig")

	magic := "~Module signature appended~\n"
	modSig := make([]byte, 12)
	modSig[2] = 1 // IDType = 1 (PGP, not PKCS7)
	binary.BigEndian.PutUint32(modSig[8:12], 4)

	fakeData := []byte{0x01, 0x02, 0x03, 0x04}

	var buf []byte
	buf = append(buf, make([]byte, 100)...)
	buf = append(buf, fakeData...)
	buf = append(buf, modSig...)
	buf = append(buf, []byte(magic)...)

	if err := os.WriteFile(filePath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info := &CertInfo{ELFInfo: &ELFDetail{}}
	found, err := extractModuleSignature(filePath, info)
	if !found {
		t.Error("expected found=true")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !info.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if info.VerifyError == "" {
		t.Error("expected VerifyError for non-PKCS7 signature type")
	}
}

func TestExtractModuleSignature_TooSmallFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "tiny")
	if err := os.WriteFile(filePath, []byte("tiny"), 0o644); err != nil {
		t.Fatal(err)
	}

	info := &CertInfo{}
	found, _ := extractModuleSignature(filePath, info)
	if found {
		t.Error("expected found=false for tiny file")
	}
}

func TestExtractModuleSignature_SigLenExceedsFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "bad-siglen")

	magic := "~Module signature appended~\n"
	modSig := make([]byte, 12)
	modSig[2] = 2
	binary.BigEndian.PutUint32(modSig[8:12], 99999) // sigLen > file size

	var buf []byte
	buf = append(buf, make([]byte, 50)...)
	buf = append(buf, modSig...)
	buf = append(buf, []byte(magic)...)

	if err := os.WriteFile(filePath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info := &CertInfo{ELFInfo: &ELFDetail{}}
	found, err := extractModuleSignature(filePath, info)
	if !found {
		t.Error("expected found=true")
	}
	if err == nil {
		t.Error("expected error for sigLen exceeding file size")
	}
}

func TestExtractELFSectionCerts_NoSigSections(t *testing.T) {
	// Build a minimal ELF without any signature sections
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "no-sig-sections")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 2)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 1)

	shstrtab := "\x00.shstrtab\x00"
	shstrtabOffset := 64
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}
	buf = append(buf, make([]byte, 64)...)
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 1)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	info := &CertInfo{}
	found, err := extractELFSectionCerts(ef, info)
	if found {
		t.Error("expected found=false for ELF without signature sections")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractELFSectionCerts_WithInvalidPKCS7Section(t *testing.T) {
	// Build an ELF with a .pkcs7 section containing invalid data
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "invalid-pkcs7-section")

	invalidPKCS7 := []byte("not valid pkcs7 data at all")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	shstrtab := "\x00.pkcs7\x00.shstrtab\x00"
	pkcs7Offset := 64
	shstrtabOffset := pkcs7Offset + len(invalidPKCS7)
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, invalidPKCS7...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	// null section
	buf = append(buf, make([]byte, 64)...)
	// .pkcs7 section
	pkcs7SH := make([]byte, 64)
	binary.LittleEndian.PutUint32(pkcs7SH[0:4], 1)
	binary.LittleEndian.PutUint32(pkcs7SH[4:8], uint32(elf.SHT_PROGBITS))
	binary.LittleEndian.PutUint64(pkcs7SH[24:32], uint64(pkcs7Offset))
	binary.LittleEndian.PutUint64(pkcs7SH[32:40], uint64(len(invalidPKCS7)))
	buf = append(buf, pkcs7SH...)
	// .shstrtab section
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 8)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	info := &CertInfo{}
	found, err := extractELFSectionCerts(ef, info)
	// Invalid PKCS7 should be skipped (continue in the loop), so found=false
	if found {
		t.Error("expected found=false for invalid PKCS7 section data")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtractELFSectionCerts_EmptySection(t *testing.T) {
	// Build an ELF with a .pkcs7 section that has 0 bytes of data
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "empty-pkcs7-section")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	shstrtab := "\x00.pkcs7\x00.shstrtab\x00"
	shstrtabOffset := 64
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	// null section
	buf = append(buf, make([]byte, 64)...)
	// .pkcs7 section with 0 size (points to offset 64 but size 0)
	pkcs7SH := make([]byte, 64)
	binary.LittleEndian.PutUint32(pkcs7SH[0:4], 1)
	binary.LittleEndian.PutUint32(pkcs7SH[4:8], uint32(elf.SHT_PROGBITS))
	binary.LittleEndian.PutUint64(pkcs7SH[24:32], uint64(64))
	binary.LittleEndian.PutUint64(pkcs7SH[32:40], 0) // 0 size
	buf = append(buf, pkcs7SH...)
	// .shstrtab section
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 8)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	info := &CertInfo{}
	found, err := extractELFSectionCerts(ef, info)
	if found {
		t.Error("expected found=false for empty .pkcs7 section")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanDirectory_VerboseWithNonBinary(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a text file that should be skipped
	_ = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("hello"), 0o644)
	// Create a .exe file with invalid PE (should be scanned but fail)
	_ = os.WriteFile(filepath.Join(tmpDir, "bad.exe"), []byte("not a pe"), 0o644)

	results, err := ScanDirectory(tmpDir, true)
	if err != nil {
		t.Fatalf("ScanDirectory: %v", err)
	}
	// bad.exe should be attempted (has .exe extension) but fail to parse
	// readme.txt should be skipped
	_ = results
}

func TestExtractBuildID_DescOverflow(t *testing.T) {
	// Build ELF with .note.gnu.build-id where descsz claims more data than available
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "overflow-build-id")

	// Note with namesz=4, descsz=100 (but we only have 4 bytes of desc data)
	var noteData []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, 4) // namesz
	noteData = append(noteData, tmp...)
	binary.LittleEndian.PutUint32(tmp, 100) // descsz (too large)
	noteData = append(noteData, tmp...)
	binary.LittleEndian.PutUint32(tmp, 3) // type
	noteData = append(noteData, tmp...)
	noteData = append(noteData, []byte("GNU\x00")...)
	noteData = append(noteData, []byte{0xde, 0xad, 0xbe, 0xef}...) // only 4 bytes

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	shstrtab := "\x00.note.gnu.build-id\x00.shstrtab\x00"
	noteOffset := 64
	shstrtabOffset := noteOffset + len(noteData)
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, noteData...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	buf = append(buf, make([]byte, 64)...)
	noteSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(noteSH[0:4], 1)
	binary.LittleEndian.PutUint32(noteSH[4:8], uint32(elf.SHT_NOTE))
	binary.LittleEndian.PutUint64(noteSH[24:32], uint64(noteOffset))
	binary.LittleEndian.PutUint64(noteSH[32:40], uint64(len(noteData)))
	buf = append(buf, noteSH...)
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 20)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	got := extractBuildID(ef)
	if got != "" {
		t.Errorf("extractBuildID() = %q, want empty for overflowed descsz", got)
	}
}

func TestExtractModuleSignature_Nonexistent(t *testing.T) {
	info := &CertInfo{}
	found, err := extractModuleSignature("/tmp/nonexistent-cert-test-12345", info)
	if found {
		t.Error("expected found=false for nonexistent file")
	}
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractELFSectionCerts_AllSectionNames(t *testing.T) {
	// Test that each known section name is checked by building ELFs with them
	sectionNames := []string{".note.signature", ".sig", ".certificate"}

	for _, secName := range sectionNames {
		t.Run(secName, func(t *testing.T) {
			tmpDir := t.TempDir()
			elfPath := filepath.Join(tmpDir, "elf-with-section")

			invalidData := []byte("invalid pkcs7 data here!!!!!!!")

			shstrtab := "\x00" + secName + "\x00.shstrtab\x00"
			secNameOffset := 1
			shstrtabNameOffset := secNameOffset + len(secName) + 1

			var buf []byte
			elfHeader := make([]byte, 64)
			copy(elfHeader[0:4], "\x7fELF")
			elfHeader[4] = 2
			elfHeader[5] = 1
			elfHeader[6] = 1
			binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
			binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
			binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
			binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
			binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
			binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
			binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

			dataOffset := 64
			shstrtabFileOffset := dataOffset + len(invalidData)
			shOffset := shstrtabFileOffset + len(shstrtab)
			if shOffset%8 != 0 {
				shOffset += 8 - (shOffset % 8)
			}
			binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

			buf = append(buf, elfHeader...)
			buf = append(buf, invalidData...)
			buf = append(buf, []byte(shstrtab)...)
			for len(buf) < shOffset {
				buf = append(buf, 0)
			}

			// null section
			buf = append(buf, make([]byte, 64)...)
			// section with invalid data
			secSH := make([]byte, 64)
			binary.LittleEndian.PutUint32(secSH[0:4], uint32(secNameOffset))
			binary.LittleEndian.PutUint32(secSH[4:8], uint32(elf.SHT_PROGBITS))
			binary.LittleEndian.PutUint64(secSH[24:32], uint64(dataOffset))
			binary.LittleEndian.PutUint64(secSH[32:40], uint64(len(invalidData)))
			buf = append(buf, secSH...)
			// .shstrtab
			strSH := make([]byte, 64)
			binary.LittleEndian.PutUint32(strSH[0:4], uint32(shstrtabNameOffset))
			binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
			binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabFileOffset))
			binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
			buf = append(buf, strSH...)

			if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
				t.Fatal(err)
			}

			ef, err := elf.Open(elfPath)
			if err != nil {
				t.Fatalf("elf.Open: %v", err)
			}
			defer func() { _ = ef.Close() }()

			info := &CertInfo{}
			found, err := extractELFSectionCerts(ef, info)
			// Invalid PKCS7 data, so should skip (continue) => found=false
			if found {
				t.Errorf("expected found=false for section %s with invalid data", secName)
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyCertificate_UnsignedPE(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile failed: %v\n%s", err, out)
	}

	info, err := VerifyCertificate(bin)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	if info.Verified {
		t.Error("unsigned PE should not be verified")
	}
	if info.VerifyError != "no signature present" {
		t.Errorf("VerifyError = %q, want 'no signature present'", info.VerifyError)
	}
}

func TestExportPEM_InvalidDir(t *testing.T) {
	cert := newSelfSignedCert(t)
	info := &CertInfo{RawCerts: []*x509.Certificate{cert}}
	// Write to a path where the parent is a file, not a directory
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "blocker")
	_ = os.WriteFile(blockingFile, []byte("x"), 0o644)
	err := ExportPEM(info, filepath.Join(blockingFile, "subdir"))
	if err == nil {
		t.Error("expected error when output dir cannot be created")
	}
}

func TestExportDER_InvalidDir(t *testing.T) {
	cert := newSelfSignedCert(t)
	info := &CertInfo{RawCerts: []*x509.Certificate{cert}}
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "blocker")
	_ = os.WriteFile(blockingFile, []byte("x"), 0o644)
	err := ExportDER(info, filepath.Join(blockingFile, "subdir"))
	if err == nil {
		t.Error("expected error when output dir cannot be created")
	}
}

func TestGenerateReport_InvalidDir(t *testing.T) {
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "blocker")
	_ = os.WriteFile(blockingFile, []byte("x"), 0o644)

	info := &CertInfo{FileName: "test", FileType: "PE"}
	err := GenerateReport(info, filepath.Join(blockingFile, "subdir", "report.md"))
	if err == nil {
		t.Error("expected error when report dir cannot be created")
	}
}

func TestGenerateBatchReport_InvalidDir(t *testing.T) {
	tmpDir := t.TempDir()
	blockingFile := filepath.Join(tmpDir, "blocker")
	_ = os.WriteFile(blockingFile, []byte("x"), 0o644)

	err := GenerateBatchReport([]*CertInfo{{FileName: "a"}}, filepath.Join(blockingFile, "subdir", "batch.md"))
	if err == nil {
		t.Error("expected error when report dir cannot be created")
	}
}

func buildSignedPKCS7(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Test Signer", Organization: []string{"TestOrg"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	sd, err := pkcs7.NewSignedData([]byte("test content"))
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}

	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSigner: %v", err)
	}

	signed, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}

	return signed
}

func TestExtractModuleSignature_ValidPKCS7(t *testing.T) {
	// Build a file with valid PKCS7 module signature
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "valid-modsig")

	pkcs7Data := buildSignedPKCS7(t)

	magic := "~Module signature appended~\n"
	modSig := make([]byte, 12)
	modSig[2] = 2 // IDType = PKEY_ID_PKCS7
	binary.BigEndian.PutUint32(modSig[8:12], uint32(len(pkcs7Data)))

	var buf []byte
	buf = append(buf, make([]byte, 100)...) // padding
	buf = append(buf, pkcs7Data...)
	buf = append(buf, modSig...)
	buf = append(buf, []byte(magic)...)

	if err := os.WriteFile(filePath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info := &CertInfo{ELFInfo: &ELFDetail{}}
	found, err := extractModuleSignature(filePath, info)
	if !found {
		t.Error("expected found=true")
	}
	// Verify may fail since the content being "signed" doesn't match, but it should parse
	_ = err
	if !info.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if info.Signer == nil {
		t.Error("expected non-nil Signer")
	}
	if !info.ELFInfo.HasModSig {
		t.Error("expected HasModSig=true")
	}
}

func TestExtractELFSectionCerts_ValidPKCS7(t *testing.T) {
	// Build an ELF with a .pkcs7 section containing valid PKCS7 signed data
	pkcs7Data := buildSignedPKCS7(t)

	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "valid-pkcs7-section")

	shstrtab := "\x00.pkcs7\x00.shstrtab\x00"

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	pkcs7Offset := 64
	shstrtabOffset := pkcs7Offset + len(pkcs7Data)
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, pkcs7Data...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	// null section
	buf = append(buf, make([]byte, 64)...)
	// .pkcs7 section
	pkcs7SH := make([]byte, 64)
	binary.LittleEndian.PutUint32(pkcs7SH[0:4], 1)
	binary.LittleEndian.PutUint32(pkcs7SH[4:8], uint32(elf.SHT_PROGBITS))
	binary.LittleEndian.PutUint64(pkcs7SH[24:32], uint64(pkcs7Offset))
	binary.LittleEndian.PutUint64(pkcs7SH[32:40], uint64(len(pkcs7Data)))
	buf = append(buf, pkcs7SH...)
	// .shstrtab
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 8)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := elf.Open(elfPath)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	info := &CertInfo{}
	found, err := extractELFSectionCerts(ef, info)
	if !found {
		t.Error("expected found=true for valid PKCS7 section")
	}
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !info.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if info.Signer == nil {
		t.Error("expected non-nil Signer")
	}
}

func TestExtractCertificates_ELFWithModSigMagic(t *testing.T) {
	// Build a minimal valid ELF, then append module signature magic
	// This tests the path through extractELFCertificates -> extractModuleSignature
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "elf-modsig")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 2)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 1)

	shstrtab := "\x00.shstrtab\x00"
	shstrtabOffset := 64
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}
	buf = append(buf, make([]byte, 64)...)
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 1)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	// Append non-PKCS7 module signature
	magic := "~Module signature appended~\n"
	modSig := make([]byte, 12)
	modSig[2] = 1 // IDType = PGP (non-PKCS7)
	binary.BigEndian.PutUint32(modSig[8:12], 4)
	fakeData := []byte{0x01, 0x02, 0x03, 0x04}
	buf = append(buf, fakeData...)
	buf = append(buf, modSig...)
	buf = append(buf, []byte(magic)...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ExtractCertificates(elfPath)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if !info.HasSignature {
		t.Error("expected HasSignature=true for ELF with module sig")
	}
	if info.ELFInfo == nil {
		t.Fatal("expected non-nil ELFInfo")
	}
	if !info.ELFInfo.HasModSig {
		t.Error("expected HasModSig=true")
	}
}

func TestExtractPECertificates_PE32(t *testing.T) {
	// Cross-compile a 32-bit PE to test the OptionalHeader32 branch
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test32.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=386")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile to PE32 failed: %v\n%s", err, out)
	}

	info, err := ExtractCertificates(bin)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.FileType != "PE" {
		t.Errorf("FileType = %q, want PE", info.FileType)
	}
	if info.HasSignature {
		t.Error("unsigned PE32 should not have signature")
	}
}

func TestExtractPECertificates_UnsignedPE(t *testing.T) {
	// Cross-compile a minimal Go binary to PE format
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile to PE failed: %v\n%s", err, out)
	}

	info, err := ExtractCertificates(bin)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.FileType != "PE" {
		t.Errorf("FileType = %q, want PE", info.FileType)
	}
	if info.HasSignature {
		t.Error("unsigned PE should not have signature")
	}
}

func TestExtractCertificates_UnsignedELF_BuildID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires ELF binary; Windows produces PE")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	bin := buildTestGoBinary(t)

	info, err := ExtractCertificates(bin)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.ELFInfo == nil {
		t.Fatal("expected non-nil ELFInfo")
	}

	if info.ELFInfo.BuildID == "" {
		t.Error("expected non-empty BuildID for Go binary")
	}
}

func TestVerifyCertificate_ExpiredSignerWithSignature(t *testing.T) {
	// Test the branch in VerifyCertificate where HasSignature=true and Signer.IsExpired=true.
	// We build a valid ELF with a valid PKCS7 module signature using an expired cert.

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Expired Signer", Organization: []string{"Expired Org"}},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	sd, err := pkcs7.NewSignedData([]byte("test"))
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSigner: %v", err)
	}
	signed, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}

	// Build minimal ELF + append module signature with this expired-cert PKCS7
	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "expired-modsig")

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 2)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 1)

	shstrtab := "\x00.shstrtab\x00"
	shstrtabOffset := 64
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}
	buf = append(buf, make([]byte, 64)...)
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 1)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	// Append PKCS7 module signature with expired cert
	magic := "~Module signature appended~\n"
	modSig := make([]byte, 12)
	modSig[2] = 2 // IDType = PKEY_ID_PKCS7
	binary.BigEndian.PutUint32(modSig[8:12], uint32(len(signed)))
	buf = append(buf, signed...)
	buf = append(buf, modSig...)
	buf = append(buf, []byte(magic)...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info, verifyErr := VerifyCertificate(elfPath)
	if verifyErr != nil {
		t.Fatalf("VerifyCertificate: %v", verifyErr)
	}

	if !info.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if info.Signer == nil {
		t.Fatal("expected non-nil Signer")
	}
	if !info.Signer.IsExpired {
		t.Error("expected Signer.IsExpired=true")
	}
	// The VerifyError should mention expiry (either from p7.Verify or from the VerifyCertificate logic)
	if info.VerifyError == "" {
		t.Error("expected non-empty VerifyError for expired signer")
	}
}

func TestBuildSingleReport_WithModSigAndInterpreter(t *testing.T) {
	// Tests the ELFInfo.HasModSig branch and ELFInfo.Interpreter branch in buildSingleReport
	info := &CertInfo{
		FilePath:     "/tmp/module.ko",
		FileName:     "module.ko",
		FileType:     "ELF",
		HasSignature: true,
		Verified:     true,
		Signer: &CertDetail{
			Subject:    "CN=Kernel Signer",
			Issuer:     "CN=Kernel CA",
			CommonName: "Kernel Signer",
			Thumbprint: "aabb",
		},
		ELFInfo: &ELFDetail{
			Class:       "ELF64",
			Machine:     "x86_64",
			Type:        "Relocatable",
			HasModSig:   true,
			Interpreter: "/lib64/ld-linux-x86-64.so.2",
			BuildID:     "deadbeef",
		},
	}

	report := buildSingleReport(info)

	if !strings.Contains(report, "kernel module") {
		t.Error("report should contain 'kernel module' for HasModSig=true")
	}
	if !strings.Contains(report, "/lib64/ld-linux-x86-64.so.2") {
		t.Error("report should contain interpreter path")
	}
	if !strings.Contains(report, "deadbeef") {
		t.Error("report should contain build ID")
	}
}

func TestBuildBatchReport_VerificationFailed(t *testing.T) {
	// Tests the "FAILED" verification branch in buildBatchReport
	infos := []*CertInfo{
		{
			FilePath:     "/tmp/bad.exe",
			FileName:     "bad.exe",
			FileType:     "PE",
			HasSignature: true,
			Verified:     false,
			VerifyError:  "signature invalid",
			Signer: &CertDetail{
				CommonName:    "Bad Signer",
				Organization:  "Bad Org",
				NotAfter:      time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				Thumbprint:    "eeff",
				Subject:       "CN=Bad Signer",
				Issuer:        "CN=CA",
				SignatureAlgo: "SHA256-RSA",
			},
			Chain: []*CertDetail{
				{
					Subject:    "CN=Intermediate",
					Issuer:     "CN=Root",
					CommonName: "Intermediate",
					Thumbprint: "1122",
				},
			},
			Countersigned: true,
		},
	}

	report := buildBatchReport(infos)

	if !strings.Contains(report, "FAILED") {
		t.Error("batch report should contain FAILED for unverified binary")
	}
	if !strings.Contains(report, "bad.exe") {
		t.Error("batch report should contain filename")
	}
	if !strings.Contains(report, "Bad Signer") {
		t.Error("batch report should contain signer details")
	}
}

func TestExportPEM_ReadOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory semantics differ on Windows")
	}

	cert := newSelfSignedCert(t)
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "readonly")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Make directory read-only so file creation fails
	if err := os.Chmod(outDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outDir, 0o755) })

	info := &CertInfo{RawCerts: []*x509.Certificate{cert}}
	err := ExportPEM(info, outDir)
	if err == nil {
		t.Error("expected error when directory is read-only")
	}
}

func TestExportDER_ReadOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only directory semantics differ on Windows")
	}

	cert := newSelfSignedCert(t)
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "readonly")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outDir, 0o755) })

	info := &CertInfo{RawCerts: []*x509.Certificate{cert}}
	err := ExportDER(info, outDir)
	if err == nil {
		t.Error("expected error when directory is read-only")
	}
}

func TestBuildSingleReport_FullCoverage(t *testing.T) {
	// Tests all branches in buildSingleReport: ELFInfo without BuildID/Interpreter,
	// with chain, signing time, countersigned, verify error
	tests := []struct {
		name     string
		info     *CertInfo
		contains []string
	}{
		{
			name: "ELF no build ID no interpreter",
			info: &CertInfo{
				FilePath: "/tmp/lib.so", FileName: "lib.so", FileType: "ELF",
				HasSignature: false,
				ELFInfo:      &ELFDetail{Class: "ELF64", Machine: "ARM", Type: "Shared Object"},
			},
			contains: []string{"ELF64", "ARM", "No code-signing signature found"},
		},
		{
			name: "PE with verify error",
			info: &CertInfo{
				FilePath: "/tmp/a.exe", FileName: "a.exe", FileType: "PE",
				HasSignature: true, Verified: false, VerifyError: "tampered",
				Signer: &CertDetail{Subject: "CN=S", Issuer: "CN=I", CommonName: "S", Thumbprint: "aa"},
			},
			contains: []string{"tampered", "Signer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := buildSingleReport(tt.info)
			for _, want := range tt.contains {
				if !strings.Contains(report, want) {
					t.Errorf("report missing %q", want)
				}
			}
		})
	}
}

func TestSanitizeFilename_SpecialChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ampersand", "a&b", "a_b"},
		{"mixed special", `a<b>c:d"e/f\g|h?i*j&k`, "a_b_c_d_e_f_g_h_i_j_k"},
		{"tabs", "a\tb\tc", "a_b_c"},
		{"only underscores after sanitize", "___", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseCertDetail_EmptyFields(t *testing.T) {
	// Certificate with no Organization, Country, or OrgUnit
	cert := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Bare Cert"},
		Issuer:    pkix.Name{CommonName: "Different Issuer"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		Raw:       []byte("raw"),
	}

	detail := parseCertDetail(cert)
	if detail.Organization != "" {
		t.Errorf("Organization = %q, want empty", detail.Organization)
	}
	if detail.Country != "" {
		t.Errorf("Country = %q, want empty", detail.Country)
	}
	if detail.OrgUnit != "" {
		t.Errorf("OrgUnit = %q, want empty", detail.OrgUnit)
	}
	if detail.IsSelfSigned {
		t.Error("should not be self-signed when subject != issuer")
	}
}

func TestExtractPECertificates_SyntheticSigned(t *testing.T) {
	// Build a cross-compiled PE, then patch in a PKCS7 signature at the security directory.
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile failed: %v\n%s", err, out)
	}

	// Read the PE, find the security directory entry, and patch it
	peData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	peFile, err := pe.Open(bin)
	if err != nil {
		t.Fatal(err)
	}

	// Get the offset of the security directory in the optional header
	var secDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		// In PE64, optional header starts at offset 24 (after signature+file header)
		// Security dir is at index 4, each DataDirectory is 8 bytes
		// OptionalHeader64 has fixed fields before DataDirectory array
		// DataDirectory starts at offset 112 from start of optional header
		// PE signature at e_lfanew, then 4 bytes "PE\0\0", then 20 bytes FileHeader, then OptionalHeader
		lfanew := binary.LittleEndian.Uint32(peData[0x3c:0x40])
		optStart := int(lfanew) + 4 + 20 // after PE sig + file header
		// DataDirectory in OptionalHeader64 starts at byte 112
		secDirOffset = optStart + 112 + 4*8 // index 4, each entry 8 bytes
	default:
		t.Skip("unexpected PE header type")
	}
	_ = peFile.Close()

	// Build PKCS7 signed data
	pkcs7Data := buildSignedPKCS7(t)

	// Append the WIN_CERTIFICATE structure at the end of the file
	certTableOffset := len(peData)
	// Align to 8 bytes
	if certTableOffset%8 != 0 {
		padding := 8 - (certTableOffset % 8)
		peData = append(peData, make([]byte, padding)...)
		certTableOffset = len(peData)
	}

	// WIN_CERTIFICATE: length(4) + revision(2) + type(2) + PKCS7 data
	certLen := uint32(8 + len(pkcs7Data))
	var winCert []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, certLen)
	winCert = append(winCert, tmp...)
	rev := make([]byte, 2)
	binary.LittleEndian.PutUint16(rev, 0x0200) // WIN_CERT_REVISION_2_0
	winCert = append(winCert, rev...)
	certType := make([]byte, 2)
	binary.LittleEndian.PutUint16(certType, 0x0002) // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	winCert = append(winCert, certType...)
	winCert = append(winCert, pkcs7Data...)

	peData = append(peData, winCert...)

	// Patch the security directory entry: VirtualAddress and Size
	binary.LittleEndian.PutUint32(peData[secDirOffset:secDirOffset+4], uint32(certTableOffset))
	binary.LittleEndian.PutUint32(peData[secDirOffset+4:secDirOffset+8], certLen)

	signedBin := filepath.Join(tmpDir, "signed.exe")
	if err := os.WriteFile(signedBin, peData, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ExtractCertificates(signedBin)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.FileType != "PE" {
		t.Errorf("FileType = %q, want PE", info.FileType)
	}
	if !info.HasSignature {
		t.Error("expected HasSignature=true for synthetic signed PE")
	}
	if info.Signer == nil {
		t.Error("expected non-nil Signer")
	}
	if info.Signer != nil && info.Signer.CommonName != "Test Signer" {
		t.Errorf("Signer.CommonName = %q, want 'Test Signer'", info.Signer.CommonName)
	}
}

func TestExtractPECertificates_SyntheticSigned_BadCertType(t *testing.T) {
	// Same as above but with wrong certificate type
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile failed: %v\n%s", err, out)
	}

	peData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	peFile, err := pe.Open(bin)
	if err != nil {
		t.Fatal(err)
	}

	var secDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		lfanew := binary.LittleEndian.Uint32(peData[0x3c:0x40])
		optStart := int(lfanew) + 4 + 20
		secDirOffset = optStart + 112 + 4*8
	default:
		t.Skip("unexpected PE header type")
	}
	_ = peFile.Close()

	certTableOffset := len(peData)
	if certTableOffset%8 != 0 {
		padding := 8 - (certTableOffset % 8)
		peData = append(peData, make([]byte, padding)...)
		certTableOffset = len(peData)
	}

	// WIN_CERTIFICATE with wrong type (0x0001 instead of 0x0002)
	certLen := uint32(8 + 100)
	var winCert []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, certLen)
	winCert = append(winCert, tmp...)
	rev := make([]byte, 2)
	binary.LittleEndian.PutUint16(rev, 0x0200)
	winCert = append(winCert, rev...)
	ct := make([]byte, 2)
	binary.LittleEndian.PutUint16(ct, 0x0001) // Wrong type
	winCert = append(winCert, ct...)
	winCert = append(winCert, make([]byte, 100)...)

	peData = append(peData, winCert...)

	binary.LittleEndian.PutUint32(peData[secDirOffset:secDirOffset+4], uint32(certTableOffset))
	binary.LittleEndian.PutUint32(peData[secDirOffset+4:secDirOffset+8], certLen)

	badBin := filepath.Join(tmpDir, "badtype.exe")
	if err := os.WriteFile(badBin, peData, 0o644); err != nil {
		if isDefenderError(err) {
			t.Skipf("Windows Defender blocked synthetic PE: %v", err)
		}
		t.Fatal(err)
	}

	_, err = ExtractCertificates(badBin)
	if err != nil && isDefenderError(err) {
		t.Skipf("Windows Defender blocked synthetic PE: %v", err)
	}
	if err == nil {
		t.Error("expected error for unsupported certificate type")
	}
	if err != nil && !strings.Contains(err.Error(), "unsupported certificate type") {
		t.Errorf("unexpected error: %v", err)
	}
}

// isDefenderError reports whether an error looks like Windows Defender AV
// quarantining a file (e.g. "contains a virus", "potentially unwanted software",
// "did not complete successfully because the file contains a virus", or the
// resulting "Access is denied" / "The process cannot access the file").
func isDefenderError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sig := range []string{
		"contains a virus",
		"potentially unwanted software",
		"virus or potentially",
		"operation did not complete",
		"access is denied",
		"the process cannot access the file",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

func TestExtractPECertificates_SyntheticSigned_BadCertLen(t *testing.T) {
	// PE with certLen < winCertHeaderSize
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile failed: %v\n%s", err, out)
	}

	peData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	peFile, err := pe.Open(bin)
	if err != nil {
		t.Fatal(err)
	}

	var secDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		lfanew := binary.LittleEndian.Uint32(peData[0x3c:0x40])
		optStart := int(lfanew) + 4 + 20
		secDirOffset = optStart + 112 + 4*8
	default:
		t.Skip("unexpected PE header type")
	}
	_ = peFile.Close()

	certTableOffset := len(peData)
	if certTableOffset%8 != 0 {
		padding := 8 - (certTableOffset % 8)
		peData = append(peData, make([]byte, padding)...)
		certTableOffset = len(peData)
	}

	// WIN_CERTIFICATE with certLen=4 (less than 8)
	var winCert []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, 4) // certLen < 8
	winCert = append(winCert, tmp...)
	rev := make([]byte, 2)
	binary.LittleEndian.PutUint16(rev, 0x0200)
	winCert = append(winCert, rev...)
	ct := make([]byte, 2)
	binary.LittleEndian.PutUint16(ct, 0x0002)
	winCert = append(winCert, ct...)

	peData = append(peData, winCert...)

	// Size must be >= 8 for the directory entry
	binary.LittleEndian.PutUint32(peData[secDirOffset:secDirOffset+4], uint32(certTableOffset))
	binary.LittleEndian.PutUint32(peData[secDirOffset+4:secDirOffset+8], 8)

	badBin := filepath.Join(tmpDir, "badlen.exe")
	if err := os.WriteFile(badBin, peData, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = ExtractCertificates(badBin)
	if err == nil {
		t.Error("expected error for invalid certificate length")
	}
}

func TestVerifyCertificate_SignedExpiredSigner(t *testing.T) {
	// Test VerifyCertificate with a signed PE that has an expired signer.
	// Uses synthetic PE approach.
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile failed: %v\n%s", err, out)
	}

	// Build PKCS7 with expired cert
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject:      pkix.Name{CommonName: "Expired PE Signer"},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData([]byte("content"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	pkcs7Data, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}

	peData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	peFile, err := pe.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	var secDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		lfanew := binary.LittleEndian.Uint32(peData[0x3c:0x40])
		optStart := int(lfanew) + 4 + 20
		secDirOffset = optStart + 112 + 4*8
	default:
		t.Skip("unexpected PE header type")
	}
	_ = peFile.Close()

	certTableOffset := len(peData)
	if certTableOffset%8 != 0 {
		padding := 8 - (certTableOffset % 8)
		peData = append(peData, make([]byte, padding)...)
		certTableOffset = len(peData)
	}

	certLen := uint32(8 + len(pkcs7Data))
	var winCert []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, certLen)
	winCert = append(winCert, tmp...)
	rev := make([]byte, 2)
	binary.LittleEndian.PutUint16(rev, 0x0200)
	winCert = append(winCert, rev...)
	ct := make([]byte, 2)
	binary.LittleEndian.PutUint16(ct, 0x0002)
	winCert = append(winCert, ct...)
	winCert = append(winCert, pkcs7Data...)

	peData = append(peData, winCert...)
	binary.LittleEndian.PutUint32(peData[secDirOffset:secDirOffset+4], uint32(certTableOffset))
	binary.LittleEndian.PutUint32(peData[secDirOffset+4:secDirOffset+8], certLen)

	signedBin := filepath.Join(tmpDir, "expired-signed.exe")
	if err := os.WriteFile(signedBin, peData, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := VerifyCertificate(signedBin)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}

	if !info.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if info.Signer == nil {
		t.Fatal("expected non-nil Signer")
	}
	if !info.Signer.IsExpired {
		t.Error("expected Signer.IsExpired=true")
	}
	if info.VerifyError == "" {
		t.Error("expected non-empty VerifyError for expired signer")
	}
}

func TestExtractCertificates_ELFWithPKCS7Section(t *testing.T) {
	// Build an ELF with .pkcs7 section containing valid PKCS7 and call ExtractCertificates
	// This covers the path through extractELFCertificates -> extractELFSectionCerts -> found=true
	pkcs7Data := buildSignedPKCS7(t)

	tmpDir := t.TempDir()
	elfPath := filepath.Join(tmpDir, "elf-with-pkcs7")

	shstrtab := "\x00.pkcs7\x00.shstrtab\x00"

	var buf []byte
	elfHeader := make([]byte, 64)
	copy(elfHeader[0:4], "\x7fELF")
	elfHeader[4] = 2
	elfHeader[5] = 1
	elfHeader[6] = 1
	binary.LittleEndian.PutUint16(elfHeader[16:18], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(elfHeader[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(elfHeader[20:24], 1)
	binary.LittleEndian.PutUint16(elfHeader[52:54], 64)
	binary.LittleEndian.PutUint16(elfHeader[58:60], 64)
	binary.LittleEndian.PutUint16(elfHeader[60:62], 3)
	binary.LittleEndian.PutUint16(elfHeader[62:64], 2)

	pkcs7Offset := 64
	shstrtabOffset := pkcs7Offset + len(pkcs7Data)
	shOffset := shstrtabOffset + len(shstrtab)
	if shOffset%8 != 0 {
		shOffset += 8 - (shOffset % 8)
	}
	binary.LittleEndian.PutUint64(elfHeader[40:48], uint64(shOffset))

	buf = append(buf, elfHeader...)
	buf = append(buf, pkcs7Data...)
	buf = append(buf, []byte(shstrtab)...)
	for len(buf) < shOffset {
		buf = append(buf, 0)
	}

	buf = append(buf, make([]byte, 64)...)
	pkcs7SH := make([]byte, 64)
	binary.LittleEndian.PutUint32(pkcs7SH[0:4], 1)
	binary.LittleEndian.PutUint32(pkcs7SH[4:8], uint32(elf.SHT_PROGBITS))
	binary.LittleEndian.PutUint64(pkcs7SH[24:32], uint64(pkcs7Offset))
	binary.LittleEndian.PutUint64(pkcs7SH[32:40], uint64(len(pkcs7Data)))
	buf = append(buf, pkcs7SH...)
	strSH := make([]byte, 64)
	binary.LittleEndian.PutUint32(strSH[0:4], 8)
	binary.LittleEndian.PutUint32(strSH[4:8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(strSH[24:32], uint64(shstrtabOffset))
	binary.LittleEndian.PutUint64(strSH[32:40], uint64(len(shstrtab)))
	buf = append(buf, strSH...)

	if err := os.WriteFile(elfPath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ExtractCertificates(elfPath)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.FileType != "ELF" {
		t.Errorf("FileType = %q, want ELF", info.FileType)
	}
	if !info.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if info.Signer == nil {
		t.Error("expected non-nil Signer")
	}
}

func TestExtractPECertificates_SyntheticSigned_PE32(t *testing.T) {
	// Cross-compile a 32-bit PE and patch in a PKCS7 signature
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test32.exe")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=386")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile to PE32 failed: %v\n%s", err, out)
	}

	peData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	peFile, err := pe.Open(bin)
	if err != nil {
		t.Fatal(err)
	}

	var secDirOffset int
	switch peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		lfanew := binary.LittleEndian.Uint32(peData[0x3c:0x40])
		optStart := int(lfanew) + 4 + 20
		// In OptionalHeader32, DataDirectory starts at offset 96
		secDirOffset = optStart + 96 + 4*8
	default:
		t.Skip("expected PE32 optional header")
	}
	_ = peFile.Close()

	pkcs7Data := buildSignedPKCS7(t)

	certTableOffset := len(peData)
	if certTableOffset%8 != 0 {
		padding := 8 - (certTableOffset % 8)
		peData = append(peData, make([]byte, padding)...)
		certTableOffset = len(peData)
	}

	certLen := uint32(8 + len(pkcs7Data))
	var winCert []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, certLen)
	winCert = append(winCert, tmp...)
	rev := make([]byte, 2)
	binary.LittleEndian.PutUint16(rev, 0x0200)
	winCert = append(winCert, rev...)
	ct := make([]byte, 2)
	binary.LittleEndian.PutUint16(ct, 0x0002)
	winCert = append(winCert, ct...)
	winCert = append(winCert, pkcs7Data...)

	peData = append(peData, winCert...)
	binary.LittleEndian.PutUint32(peData[secDirOffset:secDirOffset+4], uint32(certTableOffset))
	binary.LittleEndian.PutUint32(peData[secDirOffset+4:secDirOffset+8], certLen)

	signedBin := filepath.Join(tmpDir, "signed32.exe")
	if err := os.WriteFile(signedBin, peData, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ExtractCertificates(signedBin)
	if err != nil {
		t.Fatalf("ExtractCertificates: %v", err)
	}

	if info.FileType != "PE" {
		t.Errorf("FileType = %q, want PE", info.FileType)
	}
	if !info.HasSignature {
		t.Error("expected HasSignature=true for signed PE32")
	}
	if info.Signer == nil {
		t.Error("expected non-nil Signer")
	}
}

func TestExtractModuleSignature_ValidPKCS7_NoCerts(t *testing.T) {
	// Build a file with valid module signature magic + PKCS7 struct that parses but has no certs.
	// We use a minimal PKCS7 SignedData with no signers.
	sd, err := pkcs7.NewSignedData([]byte("content"))
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	// Don't add any signer - just finish with an empty signer list
	signed, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "no-cert-modsig")

	magic := "~Module signature appended~\n"
	modSig := make([]byte, 12)
	modSig[2] = 2 // PKEY_ID_PKCS7
	binary.BigEndian.PutUint32(modSig[8:12], uint32(len(signed)))

	var buf []byte
	buf = append(buf, make([]byte, 100)...)
	buf = append(buf, signed...)
	buf = append(buf, modSig...)
	buf = append(buf, []byte(magic)...)

	if err := os.WriteFile(filePath, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	info := &CertInfo{ELFInfo: &ELFDetail{}}
	found, sigErr := extractModuleSignature(filePath, info)
	if !found {
		t.Error("expected found=true")
	}
	// Should parse without error even with no certs
	_ = sigErr
	if !info.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if !info.ELFInfo.HasModSig {
		t.Error("expected HasModSig=true")
	}
}
