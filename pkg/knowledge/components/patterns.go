/*
Copyright (c) 2026 Security Research
*/
package components

import (
	"path/filepath"
	"regexp"
)

// maxContentScan caps the byte slice that matchContent will scan, so that a
// huge minified bundle does not dominate classification cost.
const maxContentScan = 4 * 1024

// pathPatterns are evaluated against the full source-relative path.
// Order matters only for tie-breaking; first match within a single bucket wins.
var pathPatterns = []struct {
	re         *regexp.Regexp
	bucket     Bucket
	confidence float64
}{
	{regexp.MustCompile(`(?i)\b(auth|login|signin|signup|oauth|jwt|session)\b`), BucketAuth, 0.85},
	{regexp.MustCompile(`(?i)\b(api|endpoint|client|fetch|axios|graphql)\b`), BucketAPI, 0.75},
	{regexp.MustCompile(`(?i)\b(ipc|bridge|preload|webcontent|invoke|handle)\b`), BucketIPC, 0.85},
	{regexp.MustCompile(`(?i)\b(telemetry|analytics|tracking|sentry|mixpanel|amplitude|segment)\b`), BucketTelemetry, 0.90},
	{regexp.MustCompile(`(?i)\b(crypto|encrypt|hash|hmac|aes|rsa|sha256?)\b`), BucketCrypto, 0.80},
	{regexp.MustCompile(`(?i)\b(persist|storage|cache|leveldb|sqlite|indexeddb)\b`), BucketPersistence, 0.75},
	{regexp.MustCompile(`(?i)\b(update|autoupdater|squirrel|electron-builder)\b`), BucketUpdate, 0.80},
	{regexp.MustCompile(`(?i)\b(components?|pages?|views?|screens?|routes?|render)\b`), BucketUI, 0.60},
}

// namePatterns operate on filepath.Base only; they reuse the same regex set so
// a hit on the leaf still classifies even when the directory path is generic.
var namePatterns = pathPatterns

// contentPatterns are scanned against the first maxContentScan bytes of file
// content to bound CPU per file.
var contentPatterns = pathPatterns

// matchPath returns the first path-pattern bucket hit and its confidence, or
// (BucketUnknown, 0) if no pattern matches.
func matchPath(path string) (Bucket, float64) {
	for _, p := range pathPatterns {
		if p.re.MatchString(path) {
			return p.bucket, p.confidence
		}
	}
	return BucketUnknown, 0
}

// matchName runs the name-pattern set against filepath.Base(path).
func matchName(path string) (Bucket, float64) {
	leaf := filepath.Base(path)
	for _, p := range namePatterns {
		if p.re.MatchString(leaf) {
			return p.bucket, p.confidence
		}
	}
	return BucketUnknown, 0
}

// matchContent scans the first maxContentScan bytes of content. Confidence is
// reduced by 0.1 versus path/name hits since substring matches over content
// are noisier.
func matchContent(content []byte) (Bucket, float64) {
	if len(content) == 0 {
		return BucketUnknown, 0
	}
	scan := content
	if len(scan) > maxContentScan {
		scan = scan[:maxContentScan]
	}
	for _, p := range contentPatterns {
		if p.re.Match(scan) {
			conf := p.confidence - 0.1
			if conf < 0 {
				conf = 0
			}
			return p.bucket, conf
		}
	}
	return BucketUnknown, 0
}
