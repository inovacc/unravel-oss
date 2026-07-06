/*
Copyright © 2026 Security Research
*/
package garble

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// maxStringsBytes caps the size of a binary that ExtractStrings will slurp
// into memory. The whole file is read into a single []byte, so an oversized
// (attacker-supplied) input would force an equally large allocation and OOM
// the analyst process. Legitimate Go agent binaries routinely exceed 64 MiB,
// so the bound is deliberately generous (2 GiB) and overridable.
var maxStringsBytes int64 = 2 << 30

// StringCategory classifies an extracted string.
type StringCategory string

const (
	CatURL          StringCategory = "URL"
	CatFilePath     StringCategory = "FILE_PATH"
	CatErrorMessage StringCategory = "ERROR_MESSAGE"
	CatAPIEndpoint  StringCategory = "API_ENDPOINT"
	CatCrypto       StringCategory = "CRYPTO"
	CatNetwork      StringCategory = "NETWORK"
	CatRegistry     StringCategory = "REGISTRY"
	CatHighEntropy  StringCategory = "HIGH_ENTROPY"
	CatGeneral      StringCategory = "GENERAL"
)

// ExtractedString represents a single extracted string with metadata.
type ExtractedString struct {
	Value    string         `json:"value"`
	Offset   int64          `json:"offset"`
	Length   int            `json:"length"`
	Category StringCategory `json:"category"`
	Entropy  float64        `json:"entropy"`
}

// StringsResult holds the aggregate results of string extraction.
type StringsResult struct {
	FilePath         string                      `json:"file_path"`
	FileName         string                      `json:"file_name"`
	TotalStrings     int                         `json:"total_strings"`
	ByCategory       map[StringCategory]int      `json:"by_category"`
	AvgEntropy       float64                     `json:"avg_entropy"`
	HighEntropyCount int                         `json:"high_entropy_count"`
	Strings          []ExtractedString           `json:"strings,omitempty"`
	TopByCategory    map[StringCategory][]string `json:"top_by_category,omitempty"`
}

// ExtractStrings scans a binary for printable ASCII strings of at least minLen characters,
// computes Shannon entropy for each, and categorizes them.
func ExtractStrings(binPath string, minLen int) (*StringsResult, error) {
	if minLen < 4 {
		minLen = 4
	}

	// SEC: bound the whole-file slurp against an oversized untrusted binary so
	// a multi-GB input cannot drive an equally large allocation and OOM the host.
	if fi, statErr := os.Stat(binPath); statErr != nil {
		return nil, fmt.Errorf("stat file: %w", statErr)
	} else if err := safeio.CheckSize(fi.Size(), maxStringsBytes); err != nil {
		return nil, fmt.Errorf("binary too large to scan: %w", err)
	}

	data, err := os.ReadFile(binPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	result := &StringsResult{
		FilePath:      binPath,
		FileName:      filepath.Base(binPath),
		ByCategory:    make(map[StringCategory]int),
		TopByCategory: make(map[StringCategory][]string),
	}

	var (
		current     []byte
		startOffset int64
	)

	for i, b := range data {
		if b >= 0x20 && b < 0x7f {
			if len(current) == 0 {
				startOffset = int64(i)
			}

			current = append(current, b)
		} else {
			if len(current) >= minLen {
				s := string(current)
				entropy := shannonEntropy(s)
				cat := categorizeString(s)

				es := ExtractedString{
					Value:    s,
					Offset:   startOffset,
					Length:   len(current),
					Category: cat,
					Entropy:  entropy,
				}

				result.Strings = append(result.Strings, es)
				result.ByCategory[cat]++

				if entropy > 4.5 {
					result.HighEntropyCount++
				}
			}

			current = current[:0]
		}
	}

	// Handle last string
	if len(current) >= minLen {
		s := string(current)
		entropy := shannonEntropy(s)
		cat := categorizeString(s)

		result.Strings = append(result.Strings, ExtractedString{
			Value:    s,
			Offset:   startOffset,
			Length:   len(current),
			Category: cat,
			Entropy:  entropy,
		})
		result.ByCategory[cat]++

		if entropy > 4.5 {
			result.HighEntropyCount++
		}
	}

	result.TotalStrings = len(result.Strings)

	// Compute average entropy
	if result.TotalStrings > 0 {
		var totalEntropy float64
		for _, s := range result.Strings {
			totalEntropy += s.Entropy
		}

		result.AvgEntropy = totalEntropy / float64(result.TotalStrings)
	}

	// Build top strings per category (up to 5 each)
	catStrings := make(map[StringCategory][]ExtractedString)
	for _, s := range result.Strings {
		catStrings[s.Category] = append(catStrings[s.Category], s)
	}

	for cat, strs := range catStrings {
		// Sort by entropy descending
		sort.Slice(strs, func(i, j int) bool {
			return strs[i].Entropy > strs[j].Entropy
		})

		limit := min(len(strs), 5)

		for _, s := range strs[:limit] {
			result.TopByCategory[cat] = append(result.TopByCategory[cat], s.Value)
		}
	}

	return result, nil
}

// ShannonEntropy computes the Shannon entropy of a string in bits per character.
// Exported for reuse by other packages (e.g. secret scanning).
func ShannonEntropy(s string) float64 {
	return shannonEntropy(s)
}

// shannonEntropy computes the Shannon entropy of a string in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}

	length := float64(len(s))
	entropy := 0.0

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return math.Round(entropy*100) / 100
}

// categorizeString classifies a string based on pattern matching.
func categorizeString(s string) StringCategory {
	lower := strings.ToLower(s)

	// URL patterns
	if urlPattern.MatchString(s) {
		return CatURL
	}

	// API endpoint patterns
	if apiPattern.MatchString(s) {
		return CatAPIEndpoint
	}

	// File path patterns
	if filePathPattern.MatchString(s) {
		return CatFilePath
	}

	// Windows registry
	if registryPattern.MatchString(s) {
		return CatRegistry
	}

	// Error messages
	if errorPattern.MatchString(lower) {
		return CatErrorMessage
	}

	// Crypto-related
	if cryptoPattern.MatchString(lower) {
		return CatCrypto
	}

	// Network-related
	if networkPattern.MatchString(lower) {
		return CatNetwork
	}

	// High entropy (potential encoded/encrypted data)
	if shannonEntropy(s) > 4.5 && len(s) > 16 {
		return CatHighEntropy
	}

	return CatGeneral
}

var (
	urlPattern      = regexp.MustCompile(`^https?://[^\s]+`)
	apiPattern      = regexp.MustCompile(`^/(?:api|v[0-9]+)/[a-zA-Z0-9/_-]+`)
	filePathPattern = regexp.MustCompile(`^(?:[A-Z]:\\|/(?:usr|etc|var|home|tmp|opt|proc|sys|dev)/)`)
	registryPattern = regexp.MustCompile(`^(?i)(?:HKEY_|HKLM\\|HKCU\\|SOFTWARE\\)`)
	errorPattern    = regexp.MustCompile(`(?:error|failed|invalid|cannot|unable|denied|timeout|refused|not found|panic|fatal)`)
	cryptoPattern   = regexp.MustCompile(`(?:aes|rsa|sha[0-9]+|hmac|tls|ssl|x509|certificate|encrypt|decrypt|cipher|pkcs|ecdsa|ed25519)`)
	networkPattern  = regexp.MustCompile(`(?:tcp|udp|http|https|grpc|websocket|dns|socket|connect|listen|dial|localhost|0\.0\.0\.0|127\.0\.0\.1)`)
)
