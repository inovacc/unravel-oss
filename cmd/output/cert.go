/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cert"
)

// PrintCertInfo prints certificate details box.
func PrintCertInfo(info *cert.CertInfo) {
	w := 62
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  CERTIFICATE ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, info.FileName)
	fmt.Printf("║ Type: %-*s║\n", w-7, FormatCertFileType(info))

	if info.ELFInfo != nil {
		if info.ELFInfo.BuildID != "" {
			fmt.Printf("║ Build ID: %-*s║\n", w-11, Truncate(info.ELFInfo.BuildID, w-12))
		}

		if info.ELFInfo.Interpreter != "" {
			fmt.Printf("║ Interp: %-*s║\n", w-9, Truncate(info.ELFInfo.Interpreter, w-10))
		}
	}

	if !info.HasSignature {
		fmt.Printf("║ Signature: %-*s║\n", w-12, "NOT PRESENT")
		fmt.Printf("╚%s╝\n", border)

		return
	}

	sigLabel := "PRESENT"
	if info.ELFInfo != nil && info.ELFInfo.HasModSig {
		sigLabel = "PRESENT (kernel module)"
	}

	fmt.Printf("║ Signature: %-*s║\n", w-12, sigLabel)
	fmt.Printf("╠%s╣\n", border)

	if info.Signer != nil {
		fmt.Printf("║ %-*s║\n", w-1, "SIGNER")
		fmt.Printf("║   Subject:    %-*s║\n", w-15, Truncate(info.Signer.Subject, w-16))
		fmt.Printf("║   Issuer:     %-*s║\n", w-15, Truncate(info.Signer.Issuer, w-16))
		fmt.Printf("║   Serial:     %-*s║\n", w-15, Truncate(info.Signer.SerialNumber, w-16))
		fmt.Printf("║   Valid:      %-*s║\n", w-15,
			fmt.Sprintf("%s to %s", info.Signer.NotBefore.Format("2006-01-02"), info.Signer.NotAfter.Format("2006-01-02")))
		fmt.Printf("║   Algorithm:  %-*s║\n", w-15, info.Signer.SignatureAlgo)
		fmt.Printf("║   Thumbprint: %-*s║\n", w-15, Truncate(info.Signer.Thumbprint, w-16))

		status := "VALID"
		if info.Signer.IsExpired {
			status = "EXPIRED"
		}

		if info.Signer.IsSelfSigned {
			status += " (self-signed)"
		}

		fmt.Printf("║   Status:     %-*s║\n", w-15, status)
	}

	if len(info.Chain) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ CHAIN (%d certificates)%-*s║\n", len(info.Chain), w-23-CountDigits(len(info.Chain)), "")

		for i, c := range info.Chain {
			fmt.Printf("║   [%d] %-*s║\n", i+1, w-7, Truncate(c.CommonName, w-8))

			if c.IsSelfSigned {
				fmt.Printf("║       %-*s║\n", w-7, "Self-signed root")
			} else {
				fmt.Printf("║       Issuer: %-*s║\n", w-15, Truncate(c.Issuer, w-16))
			}
		}
	}

	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "TIMESTAMPS")

	if info.SigningTime != nil {
		fmt.Printf("║   Signing Time:    %-*s║\n", w-20, info.SigningTime.Format("2006-01-02 15:04:05 UTC"))
	} else {
		fmt.Printf("║   Signing Time:    %-*s║\n", w-20, "Unknown")
	}

	csStr := "No"
	if info.Countersigned {
		csStr = "Yes"
	}

	fmt.Printf("║   Countersigned:   %-*s║\n", w-20, csStr)

	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "VERIFICATION")

	if info.Verified {
		fmt.Printf("║   Result: %-*s║\n", w-11, "VALID")
	} else {
		fmt.Printf("║   Result: %-*s║\n", w-11, "FAILED")

		if info.VerifyError != "" {
			fmt.Printf("║   Error:  %-*s║\n", w-11, Truncate(info.VerifyError, w-12))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// FormatCertFileType formats the file type string for certificate display.
func FormatCertFileType(info *cert.CertInfo) string {
	if info.ELFInfo != nil {
		return fmt.Sprintf("%s %s (%s)", info.ELFInfo.Class, info.ELFInfo.Machine, info.ELFInfo.Type)
	}

	return info.FileType
}

// PrintCertCompare prints a side-by-side certificate comparison table.
func PrintCertCompare(infos []*cert.CertInfo) {
	fmt.Printf("%-25s %-5s %-8s %-25s %-20s %-15s %-10s\n",
		"BINARY", "TYPE", "SIGNED", "SIGNER", "ORGANIZATION", "VALID UNTIL", "VERIFIED")
	fmt.Println(strings.Repeat("-", 110))

	for _, info := range infos {
		name := info.FileName
		if len(name) > 25 {
			name = name[:22] + "..."
		}

		if !info.HasSignature {
			fmt.Printf("%-25s %-5s %-8s %-25s %-20s %-15s %-10s\n",
				name, info.FileType, "No", "-", "-", "-", "-")

			continue
		}

		signer := "-"
		org := "-"
		validUntil := "-"
		verified := "FAILED"

		if info.Signer != nil {
			signer = info.Signer.CommonName
			if len(signer) > 25 {
				signer = signer[:22] + "..."
			}

			org = info.Signer.Organization
			if len(org) > 20 {
				org = org[:17] + "..."
			}

			validUntil = info.Signer.NotAfter.Format("2006-01-02")
		}

		if info.Verified {
			verified = "VALID"
		}

		fmt.Printf("%-25s %-5s %-8s %-25s %-20s %-15s %-10s\n",
			name, info.FileType, "Yes", signer, org, validUntil, verified)
	}

	// Check if binaries share the same signer
	fmt.Println()

	signers := make(map[string][]string)

	for _, info := range infos {
		if info.Signer != nil {
			signers[info.Signer.Thumbprint] = append(signers[info.Signer.Thumbprint], info.FileName)
		}
	}

	for _, files := range signers {
		if len(files) > 1 {
			fmt.Printf("Shared signer: %s\n", strings.Join(files, ", "))
		}
	}
}
