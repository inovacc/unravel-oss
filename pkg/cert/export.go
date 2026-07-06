/*
Copyright © 2026 Security Research
*/
package cert

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ExportPEM writes each certificate in the chain as a PEM file to outDir.
func ExportPEM(info *CertInfo, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	for i, cert := range info.RawCerts {
		cn := sanitizeFilename(cert.Subject.CommonName)
		if cn == "" {
			cn = "unknown"
		}

		filename := fmt.Sprintf("%d_%s.pem", i, cn)

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		path := filepath.Join(outDir, filename)

		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create %s: %w", filename, err)
		}

		if err := pem.Encode(f, block); err != nil {
			_ = f.Close()
			return fmt.Errorf("encode PEM %s: %w", filename, err)
		}

		_ = f.Close()
	}

	return nil
}

// ExportDER writes each certificate as a raw DER file to outDir.
func ExportDER(info *CertInfo, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	for i, cert := range info.RawCerts {
		cn := sanitizeFilename(cert.Subject.CommonName)
		if cn == "" {
			cn = "unknown"
		}

		filename := fmt.Sprintf("%d_%s.der", i, cn)

		path := filepath.Join(outDir, filename)
		if err := os.WriteFile(path, cert.Raw, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", filename, err)
		}
	}

	return nil
}

// GenerateReport writes a markdown report for a single binary's certificate.
func GenerateReport(info *CertInfo, outPath string) error {
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}

	report := buildSingleReport(info)

	return os.WriteFile(outPath, []byte(report), 0o644)
}

// GenerateBatchReport writes a comparative markdown report for multiple binaries.
func GenerateBatchReport(infos []*CertInfo, outPath string) error {
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}

	report := buildBatchReport(infos)

	return os.WriteFile(outPath, []byte(report), 0o644)
}

func buildSingleReport(info *CertInfo) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Certificate Report: %s\n\n", info.FileName))
	b.WriteString(fmt.Sprintf("- **File:** `%s`\n", info.FilePath))
	b.WriteString(fmt.Sprintf("- **Format:** %s\n", info.FileType))
	b.WriteString(fmt.Sprintf("- **Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))

	if info.ELFInfo != nil {
		b.WriteString(fmt.Sprintf("- **ELF Class:** %s %s (%s)\n", info.ELFInfo.Class, info.ELFInfo.Machine, info.ELFInfo.Type))

		if info.ELFInfo.BuildID != "" {
			b.WriteString(fmt.Sprintf("- **Build ID:** `%s`\n", info.ELFInfo.BuildID))
		}

		if info.ELFInfo.Interpreter != "" {
			b.WriteString(fmt.Sprintf("- **Interpreter:** `%s`\n", info.ELFInfo.Interpreter))
		}
	}

	if !info.HasSignature {
		b.WriteString("\n**No code-signing signature found.**\n")
		return b.String()
	}

	sigType := "Present"
	if info.ELFInfo != nil && info.ELFInfo.HasModSig {
		sigType = "Present (kernel module)"
	}

	b.WriteString(fmt.Sprintf("- **Signature:** %s\n", sigType))
	b.WriteString(fmt.Sprintf("- **Verified:** %v\n", info.Verified))

	if info.VerifyError != "" {
		b.WriteString(fmt.Sprintf("- **Verify Error:** %s\n", info.VerifyError))
	}

	b.WriteString("\n")

	if info.Signer != nil {
		b.WriteString("## Signer\n\n")
		writeCertDetailMD(&b, info.Signer)
	}

	if len(info.Chain) > 0 {
		b.WriteString(fmt.Sprintf("## Certificate Chain (%d certificates)\n\n", len(info.Chain)))

		for i, cert := range info.Chain {
			b.WriteString(fmt.Sprintf("### [%d] %s\n\n", i+1, cert.CommonName))
			writeCertDetailMD(&b, cert)
		}
	}

	if info.SigningTime != nil {
		b.WriteString("## Timestamps\n\n")
		b.WriteString(fmt.Sprintf("- **Signing Time:** %s\n", info.SigningTime.Format("2006-01-02 15:04:05 UTC")))
		b.WriteString(fmt.Sprintf("- **Countersigned:** %v\n", info.Countersigned))
		b.WriteString("\n")
	}

	return b.String()
}

func buildBatchReport(infos []*CertInfo) string {
	var b strings.Builder

	b.WriteString("# Certificate Comparison Report\n\n")
	b.WriteString(fmt.Sprintf("- **Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- **Binaries Analyzed:** %d\n\n", len(infos)))

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Binary | Type | Signed | Signer | Organization | Valid Until | Verified |\n")
	b.WriteString("|--------|------|--------|--------|--------------|-------------|----------|\n")

	for _, info := range infos {
		signed := "No"
		signer := "-"
		org := "-"
		validUntil := "-"
		verified := "-"

		if info.HasSignature {
			signed = "Yes"

			if info.Signer != nil {
				signer = info.Signer.CommonName
				org = info.Signer.Organization

				validUntil = info.Signer.NotAfter.Format("2006-01-02")
				if info.Signer.IsExpired {
					validUntil += " (EXPIRED)"
				}
			}

			if info.Verified {
				verified = "VALID"
			} else {
				verified = "FAILED"
			}
		}

		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
			info.FileName, info.FileType, signed, signer, org, validUntil, verified))
	}

	b.WriteString("\n")

	// Detailed per-binary sections
	for _, info := range infos {
		b.WriteString(fmt.Sprintf("## %s\n\n", info.FileName))
		b.WriteString(fmt.Sprintf("- **Path:** `%s`\n", info.FilePath))

		if !info.HasSignature {
			b.WriteString("- **Signature:** Not signed\n\n")
			continue
		}

		if info.Signer != nil {
			b.WriteString(fmt.Sprintf("- **Signer:** %s\n", info.Signer.Subject))
			b.WriteString(fmt.Sprintf("- **Issuer:** %s\n", info.Signer.Issuer))
			b.WriteString(fmt.Sprintf("- **Algorithm:** %s\n", info.Signer.SignatureAlgo))
			b.WriteString(fmt.Sprintf("- **Thumbprint:** `%s`\n", info.Signer.Thumbprint))
		}

		b.WriteString(fmt.Sprintf("- **Chain Length:** %d\n", len(info.Chain)))
		b.WriteString(fmt.Sprintf("- **Countersigned:** %v\n", info.Countersigned))
		b.WriteString("\n")
	}

	return b.String()
}

func writeCertDetailMD(b *strings.Builder, d *CertDetail) {
	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	fmt.Fprintf(b, "| **Subject** | %s |\n", d.Subject)
	fmt.Fprintf(b, "| **Issuer** | %s |\n", d.Issuer)
	fmt.Fprintf(b, "| **Serial Number** | `%s` |\n", d.SerialNumber)
	fmt.Fprintf(b, "| **Not Before** | %s |\n", d.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(b, "| **Not After** | %s |\n", d.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(b, "| **Algorithm** | %s |\n", d.SignatureAlgo)
	fmt.Fprintf(b, "| **Thumbprint** | `%s` |\n", d.Thumbprint)

	status := "VALID"
	if d.IsExpired {
		status = "EXPIRED"
	}

	if d.IsSelfSigned {
		status += " (self-signed)"
	}

	fmt.Fprintf(b, "| **Status** | %s |\n", status)
	b.WriteString("\n")
}

func sanitizeFilename(name string) string {
	re := regexp.MustCompile(`[<>:"/\\|?*&\s]+`)
	safe := re.ReplaceAllString(name, "_")

	safe = strings.Trim(safe, "_")
	if len(safe) > 60 {
		safe = safe[:60]
	}

	return safe
}
