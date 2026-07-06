/*
Copyright (c) 2026 Security Research
*/
package secret

import (
	"regexp"
	"strings"
)

// buildConfigPattern matches Java BuildConfig field declarations with string values.
var buildConfigPattern = regexp.MustCompile(`(?m)^\s*public\s+static\s+final\s+String\s+(\w+)\s*=\s*"([^"]+)"`)

// scanBuildConfig extracts interesting fields from BuildConfig.java / BuildConfig.smali.
func scanBuildConfig(content, file string) []Finding {
	lower := strings.ToLower(file)
	isBuildConfig := strings.HasSuffix(lower, "buildconfig.java") ||
		strings.HasSuffix(lower, "buildconfig.smali") ||
		strings.Contains(lower, "buildconfig")

	if !isBuildConfig {
		return nil
	}

	var findings []Finding

	matches := buildConfigPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		name := m[1]
		value := m[2]

		// Skip standard fields
		switch name {
		case "APPLICATION_ID", "BUILD_TYPE", "FLAVOR", "VERSION_NAME", "VERSION_CODE":
			continue
		}

		// Flag fields that look like they contain secrets
		nameLower := strings.ToLower(name)
		if containsAny(nameLower, "key", "secret", "token", "api", "url", "endpoint", "host", "base") {
			findings = append(findings, Finding{
				Type:       TypeBuildConfig,
				Value:      name + "=" + maskValue(value),
				RawLength:  len(value),
				File:       file,
				Confidence: "medium",
			})
		}
	}

	return findings
}

// keystoreMagic is the PKCS#12/JKS magic bytes.
var jksMagic = []byte{0xFE, 0xED, 0xFE, 0xED}
var p12Magic = []byte{0x30, 0x82} // ASN.1 SEQUENCE (common for PKCS#12)

// scanEmbeddedKeystore checks binary content for keystore file signatures.
func scanEmbeddedKeystore(data []byte, file string) []Finding {
	lower := strings.ToLower(file)

	// Check file extension
	isKeystore := strings.HasSuffix(lower, ".jks") ||
		strings.HasSuffix(lower, ".keystore") ||
		strings.HasSuffix(lower, ".p12") ||
		strings.HasSuffix(lower, ".pfx") ||
		strings.HasSuffix(lower, ".bks")

	if !isKeystore {
		// Also check magic bytes for files without keystore extension
		if len(data) < 4 {
			return nil
		}
		hasJKS := data[0] == jksMagic[0] && data[1] == jksMagic[1] && data[2] == jksMagic[2] && data[3] == jksMagic[3]
		if !hasJKS {
			return nil
		}
	}

	return []Finding{{
		Type:       TypeEmbeddedKeystore,
		Value:      file,
		RawLength:  len(data),
		File:       file,
		Confidence: "high",
	}}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
