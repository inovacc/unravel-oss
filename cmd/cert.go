/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/cert"

	"github.com/spf13/cobra"
)

var (
	certJSONFormat   bool
	certOutputDir    string
	certExportFormat string
)

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Binary certificate extraction and analysis (PE + ELF)",
	Long: `Extract, verify, and compare code-signing certificates from PE and ELF binaries.

Supported formats:
  PE   - Authenticode PKCS#7 signatures (.exe, .dll)
  ELF  - Kernel module appended signatures (.ko), section-embedded certs (.so)

Subcommands:
  info      - Display certificate details for a binary
  extract   - Export certificates as PEM or DER files
  verify    - Verify signature chain validity
  compare   - Compare certificates across multiple binaries
  scan      - Scan a directory for all signed binaries`,
}

var certInfoCmd = &cobra.Command{
	Use:   "info <binary>",
	Short: "Display certificate details",
	Long:  `Parse and display certificate information from a PE or ELF binary.`,
	Args:  cobra.ExactArgs(1),
	Run:   runCertInfo,
}

var certExtractCmd = &cobra.Command{
	Use:   "extract <binary>",
	Short: "Export certificates as PEM or DER files",
	Long:  `Extract certificates from a PE or ELF binary and write them to disk.`,
	Args:  cobra.ExactArgs(1),
	Run:   runCertExtract,
}

var certVerifyCmd = &cobra.Command{
	Use:   "verify <binary>",
	Short: "Verify signature chain validity",
	Long:  `Verify the signature and certificate chain of a PE or ELF binary.`,
	Args:  cobra.ExactArgs(1),
	Run:   runCertVerify,
}

var certCompareCmd = &cobra.Command{
	Use:   "compare <bin1> <bin2> [bin3...]",
	Short: "Compare certificates across multiple binaries",
	Long:  `Extract and compare certificates from multiple PE/ELF binaries side by side.`,
	Args:  cobra.MinimumNArgs(2),
	Run:   runCertCompare,
}

var certScanCmd = &cobra.Command{
	Use:   "scan <directory>",
	Short: "Scan directory for signed binaries",
	Long: `Recursively scan a directory for PE (.exe, .dll) and ELF (.so, .ko)
binaries, extracting certificate information from each.
Extensionless files are checked by magic bytes.`,
	Args: cobra.ExactArgs(1),
	Run:  runCertScan,
}

func init() {
	rootCmd.AddCommand(certCmd)
	certCmd.AddCommand(certInfoCmd)
	certCmd.AddCommand(certExtractCmd)
	certCmd.AddCommand(certVerifyCmd)
	certCmd.AddCommand(certCompareCmd)
	certCmd.AddCommand(certScanCmd)

	certCmd.PersistentFlags().BoolVar(&certJSONFormat, "json", false, "Output as JSON")

	certExtractCmd.Flags().StringVarP(&certOutputDir, "output", "o", "", "Output directory (required)")
	_ = certExtractCmd.MarkFlagRequired("output")
	certExtractCmd.Flags().StringVar(&certExportFormat, "format", "pem", "Export format: pem or der")

	certCompareCmd.Flags().StringVarP(&certOutputDir, "output", "o", "", "Output report path (optional)")

	certScanCmd.Flags().StringVarP(&certOutputDir, "output", "o", "", "Output report path (optional)")
}

func runCertInfo(_ *cobra.Command, args []string) {
	info, err := cert.ExtractCertificates(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if certJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	out.PrintCertInfo(info)
}

func runCertExtract(_ *cobra.Command, args []string) {
	info, err := cert.ExtractCertificates(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if !info.HasSignature {
		fmt.Printf("No signature found in %s\n", info.FileName)
		return
	}

	switch certExportFormat {
	case "der":
		if err := cert.ExportDER(info, certOutputDir); err != nil {
			fmt.Printf("Error exporting DER: %v\n", err)
			os.Exit(1)
		}
	default:
		if err := cert.ExportPEM(info, certOutputDir); err != nil {
			fmt.Printf("Error exporting PEM: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Exported %d certificates to %s (format: %s)\n", len(info.RawCerts), certOutputDir, certExportFormat)

	// Also generate a report
	reportPath := certOutputDir + "/REPORT.md"
	if err := cert.GenerateReport(info, reportPath); err != nil {
		fmt.Printf("Warning: could not generate report: %v\n", err)
	} else {
		fmt.Printf("Report written to %s\n", reportPath)
	}
}

func runCertVerify(_ *cobra.Command, args []string) {
	info, err := cert.VerifyCertificate(args[0])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if certJSONFormat {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))

		return
	}

	fmt.Printf("File: %s\n", info.FileName)
	fmt.Printf("Type: %s\n", info.FileType)

	if !info.HasSignature {
		fmt.Println("Signature: NOT PRESENT")
		return
	}

	fmt.Println("Signature: PRESENT")

	if info.Verified {
		fmt.Println("Verification: VALID")
	} else {
		fmt.Printf("Verification: FAILED - %s\n", info.VerifyError)
	}

	if info.Signer != nil {
		fmt.Printf("Signer: %s\n", info.Signer.CommonName)

		if info.Signer.IsExpired {
			fmt.Printf("Status: EXPIRED (valid until %s)\n", info.Signer.NotAfter.Format("2006-01-02"))
		} else {
			fmt.Printf("Status: Valid until %s\n", info.Signer.NotAfter.Format("2006-01-02"))
		}

		if info.Signer.IsSelfSigned {
			fmt.Println("Warning: Self-signed certificate")
		}
	}

	fmt.Printf("Chain length: %d\n", len(info.Chain))
	fmt.Printf("Countersigned: %v\n", info.Countersigned)
}

func runCertCompare(_ *cobra.Command, args []string) {
	var infos []*cert.CertInfo

	for _, path := range args {
		info, err := cert.ExtractCertificates(path)
		if err != nil {
			fmt.Printf("Warning: %s: %v\n", path, err)
			continue
		}

		infos = append(infos, info)
	}

	if len(infos) == 0 {
		fmt.Println("No valid binaries found.")
		os.Exit(1)
	}

	if certJSONFormat {
		data, _ := json.MarshalIndent(infos, "", "  ")
		fmt.Println(string(data))

		return
	}

	// Print comparison table
	fmt.Println()
	out.PrintCertCompare(infos)

	// Generate report if output specified
	if certOutputDir != "" {
		reportPath := certOutputDir
		if !strings.HasSuffix(reportPath, ".md") {
			reportPath = reportPath + "/COMPARISON.md"
		}

		if err := cert.GenerateBatchReport(infos, reportPath); err != nil {
			fmt.Printf("Error writing report: %v\n", err)
		} else {
			fmt.Printf("\nReport written to %s\n", reportPath)
		}
	}
}

func runCertScan(_ *cobra.Command, args []string) {
	fmt.Printf("Scanning directory: %s\n\n", args[0])

	results, err := cert.ScanDirectory(args[0], verbose)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Println("No binaries found.")
		return
	}

	if certJSONFormat {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))

		return
	}

	// Summary
	signed := 0
	unsigned := 0
	peCount := 0
	elfCount := 0

	for _, info := range results {
		if info.HasSignature {
			signed++
		} else {
			unsigned++
		}

		switch info.FileType {
		case "PE":
			peCount++
		case "ELF":
			elfCount++
		}
	}

	fmt.Printf("Found %d binaries (%d PE, %d ELF) — %d signed, %d unsigned\n\n",
		len(results), peCount, elfCount, signed, unsigned)

	// Table
	fmt.Printf("%-30s %-5s %-8s %-30s %-20s %-10s\n", "FILE", "TYPE", "SIGNED", "SIGNER", "VALID UNTIL", "VERIFIED")
	fmt.Println(strings.Repeat("-", 105))

	for _, info := range results {
		name := info.FileName
		if len(name) > 30 {
			name = name[:27] + "..."
		}

		if !info.HasSignature {
			fmt.Printf("%-30s %-5s %-8s %-30s %-20s %-10s\n", name, info.FileType, "No", "-", "-", "-")
			continue
		}

		signer := "-"
		validUntil := "-"
		verified := "FAILED"

		if info.Signer != nil {
			signer = info.Signer.CommonName
			if len(signer) > 30 {
				signer = signer[:27] + "..."
			}

			validUntil = info.Signer.NotAfter.Format("2006-01-02")
			if info.Signer.IsExpired {
				validUntil += " !"
			}
		}

		if info.Verified {
			verified = "VALID"
		}

		fmt.Printf("%-30s %-5s %-8s %-30s %-20s %-10s\n", name, info.FileType, "Yes", signer, validUntil, verified)
	}

	// Generate report if output specified
	if certOutputDir != "" {
		reportPath := certOutputDir
		if !strings.HasSuffix(reportPath, ".md") {
			reportPath = reportPath + "/SCAN_REPORT.md"
		}

		if err := cert.GenerateBatchReport(results, reportPath); err != nil {
			fmt.Printf("\nError writing report: %v\n", err)
		} else {
			fmt.Printf("\nReport written to %s\n", reportPath)
		}
	}
}
