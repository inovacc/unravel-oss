/*
Copyright (c) 2026 Security Research
*/
package risk

import (
	"archive/zip"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.mozilla.org/pkcs7"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

// p7xMagic is the 4-byte header prefix Microsoft emits in front of the PKCS#7
// payload of AppxSignature.p7x. We strip it before handing bytes to pkcs7.Parse.
var p7xMagic = []byte{'P', 'K', 'C', 'X'}

// InspectSignature classifies the signature embedded in an MSIX archive (or
// an already-extracted directory containing AppxSignature.p7x). It reuses the
// project's pkcs7 surface (V6 ASVS — no new crypto introduced).
//
// Statuses returned (uwp.SignatureInfo.Status):
//
//	"unsigned"           — no AppxSignature.p7x present
//	"invalid"            — present but PKCS#7 parse failed or no certificates
//	"self-signed"        — signer cert subject == issuer
//	"trusted-microsoft"  — issuer CN matches a Microsoft Authenticode CA
//	"trusted-other"      — any other valid signer
func InspectSignature(msixPath string) (uwp.SignatureInfo, error) {
	data, err := readP7XBytes(msixPath)
	if err != nil {
		if errors.Is(err, errNoSignature) {
			return uwp.SignatureInfo{Status: "unsigned"}, nil
		}
		return uwp.SignatureInfo{Status: "invalid"}, fmt.Errorf("inspect signature: %w", err)
	}
	return classifyPKCS7(data), nil
}

// Multiplier returns the signature multiplier applicable to sig.Status. When
// the rubric does not list the status, returns 1.0 (defensive default).
func Multiplier(sig uwp.SignatureInfo, rubric *uwp.Rubric) float64 {
	if rubric == nil {
		rubric = DefaultRubric()
	}
	if m, ok := rubric.SignatureMultipliers[sig.Status]; ok {
		return m
	}
	return 1.0
}

// errNoSignature is returned when the input does not contain an
// AppxSignature.p7x file.
var errNoSignature = errors.New("no AppxSignature.p7x present")

func readP7XBytes(path string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	stat, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	// Directory: look for AppxSignature.p7x in the root.
	if stat.IsDir() {
		candidate := filepath.Join(abs, "AppxSignature.p7x")
		f, err := os.Open(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, errNoSignature
			}
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return io.ReadAll(f)
	}

	// File: open as zip and look for AppxSignature.p7x.
	r, err := zip.OpenReader(abs)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		if !strings.EqualFold(f.Name, "AppxSignature.p7x") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open p7x: %w", err)
		}
		data, readErr := io.ReadAll(rc)
		_ = rc.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read p7x: %w", readErr)
		}
		return data, nil
	}
	return nil, errNoSignature
}

// classifyPKCS7 strips the PKCX magic, parses the PKCS#7 blob, and maps the
// signer issuer CN to one of the four signed statuses.
func classifyPKCS7(raw []byte) uwp.SignatureInfo {
	body := raw
	if len(body) >= 4 && body[0] == p7xMagic[0] && body[1] == p7xMagic[1] && body[2] == p7xMagic[2] && body[3] == p7xMagic[3] {
		body = body[4:]
	}

	p7, err := pkcs7.Parse(body)
	if err != nil || p7 == nil || len(p7.Certificates) == 0 {
		return uwp.SignatureInfo{Status: "invalid"}
	}

	return classifyCert(p7.Certificates[0])
}

// classifyCert maps a single x509 cert to a uwp.SignatureInfo. Exposed for
// unit testing without the PKCS#7 ceremony.
func classifyCert(signer *x509.Certificate) uwp.SignatureInfo {
	if signer == nil {
		return uwp.SignatureInfo{Status: "invalid"}
	}
	subject := signer.Subject.String()
	issuer := signer.Issuer.String()
	issuerCN := signer.Issuer.CommonName

	status := "trusted-other"
	if subject == issuer {
		status = "self-signed"
	} else if isMicrosoftIssuer(issuerCN) {
		status = "trusted-microsoft"
	}
	return uwp.SignatureInfo{Status: status, Issuer: issuer, Subject: subject}
}

// isMicrosoftIssuer reports whether an Issuer CN matches a known Microsoft
// Authenticode root/intermediate CA. Match is prefix-based on the canonical
// CN strings published by Microsoft.
func isMicrosoftIssuer(cn string) bool {
	cn = strings.TrimSpace(cn)
	prefixes := []string{
		"Microsoft Code Signing PCA",
		"Microsoft Windows Production PCA",
		"Microsoft Root Certificate Authority",
		"Microsoft Marketplace PCA",
		"Microsoft Authenticode(tm)",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(cn, p) {
			return true
		}
	}
	return false
}
