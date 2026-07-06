/*
Copyright (c) 2026 Security Research
*/
package apk

import (
	"archive/zip"
	"crypto/md5"  //nolint:gosec // G501 -- MD5 used only for cert fingerprint identification/reporting, never for security; matches apksigner/keytool MD5 output
	"crypto/sha1" //nolint:gosec // G505 -- SHA1 used only for cert fingerprint identification/reporting, never for security; matches apksigner/keytool SHA1 output
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/internal/boundedzip"
)

// CertResult contains certificates extracted from an APK.
type CertResult struct {
	Path         string         `json:"path"`
	FileName     string         `json:"file_name"`
	Certificates []*Certificate `json:"certificates"`
	Source       string         `json:"source"`
}

// Certificate represents a parsed X.509 certificate.
type Certificate struct {
	Subject            string      `json:"subject"`
	Issuer             string      `json:"issuer"`
	SerialNumber       string      `json:"serial_number"`
	NotBefore          time.Time   `json:"not_before"`
	NotAfter           time.Time   `json:"not_after"`
	IsExpired          bool        `json:"is_expired"`
	IsSelfSigned       bool        `json:"is_self_signed"`
	SignatureAlgorithm string      `json:"signature_algorithm"`
	PublicKeyAlgorithm string      `json:"public_key_algorithm"`
	Fingerprint        Fingerprint `json:"fingerprint"`
	Version            int         `json:"version"`
}

// Fingerprint contains hash digests of the certificate DER encoding.
type Fingerprint struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// PKCS#7 ASN.1 structures for v1 certificate parsing.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
}

// ExtractCertificates extracts signing certificates from an APK.
// It tries v3, then v2, then v1, returning the first successful result.
func ExtractCertificates(apkPath string) (*CertResult, error) {
	absPath, err := filepath.Abs(apkPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	result := &CertResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
	}

	// Try v3 first
	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	certs, err := extractSigningBlockCerts(f, blockIDV3)
	if err == nil && len(certs) > 0 {
		_ = f.Close()
		result.Certificates = certs
		result.Source = "v3"

		return result, nil
	}

	// Try v2
	certs, err = extractSigningBlockCerts(f, blockIDV2)
	if err == nil && len(certs) > 0 {
		_ = f.Close()
		result.Certificates = certs
		result.Source = "v2"

		return result, nil
	}

	_ = f.Close()

	// Try v1
	zr, err := boundedzip.OpenReader(absPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = zr.Close() }()

	certs, err = extractV1Certs(zr.Reader)
	if err == nil && len(certs) > 0 {
		result.Certificates = certs
		result.Source = "v1"

		return result, nil
	}

	result.Source = "none"

	return result, nil
}

// extractV1Certs parses certificates from META-INF/*.RSA/DSA/EC files (PKCS#7).
func extractV1Certs(zr *zip.Reader) ([]*Certificate, error) {
	var allCerts []*Certificate

	for _, f := range zr.File {
		dir := filepath.Dir(f.Name)
		base := filepath.Base(f.Name)

		if dir != "META-INF" {
			continue
		}

		if !strings.HasSuffix(base, ".RSA") && !strings.HasSuffix(base, ".DSA") && !strings.HasSuffix(base, ".EC") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		data, err := io.ReadAll(rc)
		_ = rc.Close()

		if err != nil {
			continue
		}

		certs, err := parsePKCS7Certs(data)
		if err != nil {
			continue
		}

		allCerts = append(allCerts, certs...)
	}

	return allCerts, nil
}

// parsePKCS7Certs extracts X.509 certificates from a PKCS#7 SignedData structure.
func parsePKCS7Certs(der []byte) ([]*Certificate, error) {
	var ci contentInfo

	_, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}

	var sd signedData

	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, fmt.Errorf("unmarshal SignedData: %w", err)
	}

	// Parse certificates from the IMPLICIT SET OF Certificate
	var rawCerts []asn1.RawValue

	_, err = asn1.Unmarshal(sd.Certificates.Bytes, &rawCerts)
	if err != nil {
		// Try as a single certificate
		raw, parseErr := x509.ParseCertificate(sd.Certificates.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("unmarshal certificates: %w", err)
		}

		return []*Certificate{parseCertificate(raw, sd.Certificates.Bytes)}, nil
	}

	var certs []*Certificate

	for _, rc := range rawCerts {
		parsed, parseErr := x509.ParseCertificate(rc.FullBytes)
		if parseErr != nil {
			continue
		}

		certs = append(certs, parseCertificate(parsed, rc.FullBytes))
	}

	return certs, nil
}

// extractSigningBlockCerts extracts certificates from v2/v3 signing block data.
func extractSigningBlockCerts(f *os.File, blockID uint32) ([]*Certificate, error) {
	offset, size, err := findSigningBlock(f)
	if err != nil {
		return nil, err
	}

	pairs, err := parseSigningBlock(f, offset, size)
	if err != nil {
		return nil, err
	}

	data, ok := pairs[blockID]
	if !ok {
		return nil, fmt.Errorf("block ID 0x%x not found", blockID)
	}

	return parseSignerCerts(data)
}

// parseSignerCerts extracts certificates from a v2/v3 signer block.
//
// Block format:
//
//	length-prefixed sequence of signers
//	  each signer:
//	    length-prefixed signed data
//	      length-prefixed sequence of digests
//	      length-prefixed sequence of certificates (raw X.509 DER)
//	    length-prefixed sequence of signatures
//	    length-prefixed public key
func parseSignerCerts(data []byte) ([]*Certificate, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short")
	}

	var allCerts []*Certificate

	signersLen := int(binary.LittleEndian.Uint32(data[0:4]))
	pos := 4
	end := min(pos+signersLen, len(data))

	for pos < end {
		if pos+4 > len(data) {
			break
		}

		signerLen := int(binary.LittleEndian.Uint32(data[pos:]))
		pos += 4

		signerEnd := pos + signerLen
		if signerEnd > len(data) {
			break
		}

		// Parse signed data
		if pos+4 > signerEnd {
			pos = signerEnd
			continue
		}

		signedDataLen := int(binary.LittleEndian.Uint32(data[pos:]))
		sdStart := pos + 4

		sdEnd := sdStart + signedDataLen
		if sdEnd > signerEnd {
			pos = signerEnd
			continue
		}

		// Inside signed data: skip digests, then read certificates
		sdPos := sdStart
		if sdPos+4 > sdEnd {
			pos = signerEnd
			continue
		}

		// Skip digests sequence
		digestsLen := int(binary.LittleEndian.Uint32(data[sdPos:]))
		sdPos += 4 + digestsLen

		// Read certificates sequence
		if sdPos+4 > sdEnd {
			pos = signerEnd
			continue
		}

		certsLen := int(binary.LittleEndian.Uint32(data[sdPos:]))
		sdPos += 4
		certsEnd := min(sdPos+certsLen, sdEnd)

		// Each cert is length-prefixed raw DER
		for sdPos < certsEnd {
			if sdPos+4 > certsEnd {
				break
			}

			certLen := int(binary.LittleEndian.Uint32(data[sdPos:]))

			sdPos += 4
			if sdPos+certLen > certsEnd {
				break
			}

			certDER := data[sdPos : sdPos+certLen]

			parsed, parseErr := x509.ParseCertificate(certDER)
			if parseErr == nil {
				allCerts = append(allCerts, parseCertificate(parsed, certDER))
			}

			sdPos += certLen
		}

		pos = signerEnd
	}

	return allCerts, nil
}

func parseCertificate(raw *x509.Certificate, der []byte) *Certificate {
	return &Certificate{
		Subject:            raw.Subject.String(),
		Issuer:             raw.Issuer.String(),
		SerialNumber:       raw.SerialNumber.String(),
		NotBefore:          raw.NotBefore,
		NotAfter:           raw.NotAfter,
		IsExpired:          time.Now().After(raw.NotAfter),
		IsSelfSigned:       raw.Subject.String() == raw.Issuer.String(),
		SignatureAlgorithm: raw.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: raw.PublicKeyAlgorithm.String(),
		Fingerprint:        computeFingerprint(der),
		Version:            raw.Version,
	}
}

func computeFingerprint(der []byte) Fingerprint {
	md5Sum := md5.Sum(der)   //nolint:gosec // G401 -- non-security cert fingerprint (matches apksigner/keytool MD5 output); not used for integrity or authentication
	sha1Sum := sha1.Sum(der) //nolint:gosec // G401 -- non-security cert fingerprint (matches apksigner/keytool SHA1 output); not used for integrity or authentication
	sha256Sum := sha256.Sum256(der)

	return Fingerprint{
		MD5:    formatFingerprint(hex.EncodeToString(md5Sum[:])),
		SHA1:   formatFingerprint(hex.EncodeToString(sha1Sum[:])),
		SHA256: formatFingerprint(hex.EncodeToString(sha256Sum[:])),
	}
}

func formatFingerprint(hexStr string) string {
	hexStr = strings.ToUpper(hexStr)

	var parts []string

	for i := 0; i < len(hexStr); i += 2 {
		end := min(i+2, len(hexStr))
		parts = append(parts, hexStr[i:end])
	}

	return strings.Join(parts, ":")
}
