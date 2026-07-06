/*
Copyright © 2026 Security Research
*/
package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
)

const (
	imageDirectoryEntrySecurity = 4
	winCertTypePKCSSignedData   = 0x0002
	winCertHeaderSize           = 8 // length(4) + revision(2) + type(2)

	// maxCertBytes is an absolute upper bound on the PKCS#7 blob we will read.
	// Legitimate Authenticode signatures are well under 1 MiB; 64 MiB is generous.
	maxCertBytes = 64 << 20
)

// CertInfo holds all certificate information extracted from a binary.
type CertInfo struct {
	FilePath      string        `json:"file_path"`
	FileName      string        `json:"file_name"`
	FileType      string        `json:"file_type"`
	HasSignature  bool          `json:"has_signature"`
	Signer        *CertDetail   `json:"signer,omitempty"`
	Chain         []*CertDetail `json:"chain,omitempty"`
	SigningTime   *time.Time    `json:"signing_time,omitempty"`
	Countersigned bool          `json:"countersigned"`
	Verified      bool          `json:"verified"`
	VerifyError   string        `json:"verify_error,omitempty"`
	ELFInfo       *ELFDetail    `json:"elf_info,omitempty"`
	// Raw certificates for export
	RawCerts []*x509.Certificate `json:"-"`
}

// CertDetail holds parsed details for a single X.509 certificate.
type CertDetail struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	IsExpired     bool      `json:"is_expired"`
	IsSelfSigned  bool      `json:"is_self_signed"`
	SignatureAlgo string    `json:"signature_algorithm"`
	Thumbprint    string    `json:"thumbprint"`
	CommonName    string    `json:"common_name"`
	Organization  string    `json:"organization"`
	Country       string    `json:"country"`
	OrgUnit       string    `json:"org_unit,omitempty"`
}

// ExtractCertificates auto-detects the binary format (PE or ELF) and extracts
// certificate information accordingly.
func ExtractCertificates(binPath string) (*CertInfo, error) {
	absPath, err := filepath.Abs(binPath)
	if err != nil {
		absPath = binPath
	}

	info := &CertInfo{
		FilePath: absPath,
		FileName: filepath.Base(binPath),
	}

	ft, err := detectFileType(binPath)
	if err != nil {
		return nil, err
	}

	switch ft {
	case "PE":
		return extractPECertificates(binPath, info)
	case "ELF":
		if err := extractELFCertificates(binPath, info); err != nil {
			return nil, err
		}

		return info, nil
	default:
		return nil, fmt.Errorf("unsupported binary format: %s", ft)
	}
}

// VerifyCertificate performs detailed verification of a binary's certificate.
func VerifyCertificate(binPath string) (*CertInfo, error) {
	info, err := ExtractCertificates(binPath)
	if err != nil {
		return nil, err
	}

	if !info.HasSignature {
		info.VerifyError = "no signature present"
		return info, nil
	}

	if info.Signer != nil && info.Signer.IsExpired {
		if info.VerifyError == "" {
			info.VerifyError = "signer certificate has expired"
		}
	}

	return info, nil
}

// ScanDirectory recursively scans a directory for PE and ELF binaries and extracts certificates.
func ScanDirectory(dirPath string, verbose bool) ([]*CertInfo, error) {
	var results []*CertInfo

	err := filepath.Walk(dirPath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if fi.IsDir() {
			return nil
		}

		if !isScanCandidate(fi.Name(), path) {
			return nil
		}

		if verbose {
			fmt.Printf("  [SCAN] %s\n", path)
		}

		info, extractErr := ExtractCertificates(path)
		if extractErr != nil {
			if verbose {
				fmt.Printf("  [SKIP] %s: %v\n", path, extractErr)
			}

			return nil
		}

		results = append(results, info)

		return nil
	})

	return results, err
}

// isScanCandidate checks whether a file should be scanned based on its extension
// or, for extensionless files, by reading magic bytes.
func isScanCandidate(name, path string) bool {
	ext := strings.ToLower(filepath.Ext(name))

	// PE extensions
	if ext == ".exe" || ext == ".dll" {
		return true
	}

	// ELF extensions
	if ext == ".so" || ext == ".ko" {
		return true
	}

	// Extensionless files: check magic bytes
	if ext == "" {
		ft, err := detectFileType(path)
		if err == nil && (ft == "PE" || ft == "ELF") {
			return true
		}
	}

	return false
}

// detectFileType reads the magic bytes at the start of a file to determine its format.
func detectFileType(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return "", fmt.Errorf("read magic bytes: %w", err)
	}

	// ELF: \x7fELF
	if magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return "ELF", nil
	}

	// PE: MZ header
	if magic[0] == 'M' && magic[1] == 'Z' {
		return "PE", nil
	}

	return "unknown", fmt.Errorf("unrecognized binary format (magic: %x)", magic)
}

// extractPECertificates parses a PE binary and extracts Authenticode certificate information.
func extractPECertificates(exePath string, info *CertInfo) (*CertInfo, error) {
	info.FileType = "PE"

	peFile, err := pe.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("open PE file: %w", err)
	}

	defer func() { _ = peFile.Close() }()

	// Read the security data directory entry
	var secDir pe.DataDirectory

	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if int(opt.NumberOfRvaAndSizes) <= imageDirectoryEntrySecurity {
			return info, nil
		}

		secDir = opt.DataDirectory[imageDirectoryEntrySecurity]
	case *pe.OptionalHeader64:
		if int(opt.NumberOfRvaAndSizes) <= imageDirectoryEntrySecurity {
			return info, nil
		}

		secDir = opt.DataDirectory[imageDirectoryEntrySecurity]
	default:
		return nil, fmt.Errorf("unsupported PE optional header type")
	}

	if secDir.Size == 0 {
		return info, nil
	}

	// Read raw certificate table from the file offset
	f, err := os.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("reopen file: %w", err)
	}

	defer func() { _ = f.Close() }()

	// SEC: validate VirtualAddress+Size against actual file size before seeking
	// (prevents OOB seek + fake certLen OOM on crafted PEs).
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat PE file: %w", err)
	}
	if int64(secDir.VirtualAddress)+int64(secDir.Size) > fi.Size() {
		return nil, fmt.Errorf("security directory extends beyond file: offset=%d size=%d filesize=%d",
			secDir.VirtualAddress, secDir.Size, fi.Size())
	}

	if _, err := f.Seek(int64(secDir.VirtualAddress), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek to cert table: %w", err)
	}

	// Read WIN_CERTIFICATE header
	var (
		certLen  uint32
		certRev  uint16
		certType uint16
	)

	if err := binary.Read(f, binary.LittleEndian, &certLen); err != nil {
		return nil, fmt.Errorf("read cert length: %w", err)
	}

	if err := binary.Read(f, binary.LittleEndian, &certRev); err != nil {
		return nil, fmt.Errorf("read cert revision: %w", err)
	}

	if err := binary.Read(f, binary.LittleEndian, &certType); err != nil {
		return nil, fmt.Errorf("read cert type: %w", err)
	}

	if certType != winCertTypePKCSSignedData {
		return nil, fmt.Errorf("unsupported certificate type: 0x%04x", certType)
	}

	if certLen < winCertHeaderSize {
		return nil, fmt.Errorf("invalid certificate length: %d", certLen)
	}

	// SEC: bound certLen against secDir.Size and an absolute cap to prevent OOM.
	if certLen > secDir.Size {
		return nil, fmt.Errorf("certificate length %d exceeds security directory size %d", certLen, secDir.Size)
	}
	pkcs7Len := certLen - winCertHeaderSize
	if pkcs7Len > maxCertBytes {
		return nil, fmt.Errorf("certificate payload too large: %d bytes (max %d)", pkcs7Len, maxCertBytes)
	}

	// Read the PKCS#7 signed data
	pkcs7Data := make([]byte, pkcs7Len)
	if _, err := io.ReadFull(f, pkcs7Data); err != nil {
		return nil, fmt.Errorf("read PKCS7 data: %w", err)
	}

	p7, err := pkcs7.Parse(pkcs7Data)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS7: %w", err)
	}

	info.HasSignature = true
	info.RawCerts = p7.Certificates

	if len(p7.Certificates) == 0 {
		return info, nil
	}

	// First certificate is the signer
	info.Signer = parseCertDetail(p7.Certificates[0])

	// Remaining certificates form the chain
	for i := 1; i < len(p7.Certificates); i++ {
		info.Chain = append(info.Chain, parseCertDetail(p7.Certificates[i]))
	}

	// Try to extract signing time from signer info
	signer := p7.GetOnlySigner()
	if signer != nil {
		for _, si := range p7.Signers {
			for _, attr := range si.AuthenticatedAttributes {
				// OID 1.2.840.113549.1.9.5 = signingTime
				if attr.Type.String() == "1.2.840.113549.1.9.5" {
					if len(attr.Value.Bytes) > 0 {
						var st time.Time
						if t, parseErr := time.Parse("060102150405Z", string(attr.Value.Bytes)); parseErr == nil {
							st = t
						}

						if !st.IsZero() {
							info.SigningTime = &st
						}
					}
				}
			}

			// Check for countersignature in unauthenticated attributes
			for _, attr := range si.UnauthenticatedAttributes {
				// OID 1.2.840.113549.1.9.6 = countersignature
				if attr.Type.String() == "1.2.840.113549.1.9.6" {
					info.Countersigned = true
				}
				// OID 1.3.6.1.4.1.311.3.3.1 = MS RFC3161 timestamp
				if attr.Type.String() == "1.3.6.1.4.1.311.3.3.1" {
					info.Countersigned = true
				}
			}
		}
	}

	// Verify the signature
	if err := p7.Verify(); err != nil {
		info.Verified = false
		info.VerifyError = err.Error()
	} else {
		info.Verified = true
	}

	return info, nil
}

func parseCertDetail(cert *x509.Certificate) *CertDetail {
	now := time.Now()

	detail := &CertDetail{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  fmt.Sprintf("%X", cert.SerialNumber),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		IsExpired:     now.After(cert.NotAfter),
		IsSelfSigned:  cert.Subject.String() == cert.Issuer.String(),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		Thumbprint:    thumbprint(cert),
		CommonName:    cert.Subject.CommonName,
	}

	if len(cert.Subject.Organization) > 0 {
		detail.Organization = cert.Subject.Organization[0]
	}

	if len(cert.Subject.Country) > 0 {
		detail.Country = cert.Subject.Country[0]
	}

	if len(cert.Subject.OrganizationalUnit) > 0 {
		detail.OrgUnit = cert.Subject.OrganizationalUnit[0]
	}

	return detail
}

func thumbprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", h[:])
}
