/*
Copyright (c) 2026 Security Research
*/
package secret

// ScanText runs the secret pattern engine + embedded-keystore detection over
// an in-memory string (e.g. parsed localStorage). label populates Finding.File.
// Dedupes within the returned slice. No file/zip I/O.
func ScanText(label, content string) []Finding {
	if content == "" {
		return nil
	}

	var findings []Finding
	seen := make(map[string]bool)

	// Embedded keystore detection (runs on raw data, before content scan).
	for _, finding := range scanEmbeddedKeystore([]byte(content), label) {
		key := string(finding.Type) + ":" + finding.Value
		if !seen[key] {
			seen[key] = true
			findings = append(findings, finding)
		}
	}

	// Run pattern matching (mirrors scanner.go's match loop exactly).
	for _, pat := range patterns {
		matches := pat.Pattern.FindAllString(content, 20)
		for _, match := range matches {
			key := string(pat.Type) + ":" + maskValue(match)
			if seen[key] {
				continue
			}

			seen[key] = true

			findings = append(findings, Finding{
				Type:       pat.Type,
				Value:      maskValue(match),
				RawLength:  len(match),
				File:       label,
				Confidence: pat.Confidence,
			})
		}
	}

	return findings
}
