/*
Copyright (c) 2026 Security Research
*/

package network

import (
	"archive/zip"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// URL pattern: matches http:// or https:// followed by valid URL characters
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>\x00-\x1f]{8,200}`)

// Text file extensions to scan in assets/res
var textExtensions = map[string]bool{
	".json":       true,
	".xml":        true,
	".yml":        true,
	".yaml":       true,
	".properties": true,
	".txt":        true,
	".js":         true,
	".html":       true,
	".cfg":        true,
	".conf":       true,
}

const maxFileSize = 1024 * 1024 // 1MB

// ScanAPK performs network analysis on an APK file
func ScanAPK(apkPath string, dexResult *dex.ParseResult) (*ScanResult, error) {
	result := &ScanResult{
		Endpoints: []EndpointInfo{},
		Domains:   []DomainInfo{},
	}

	// Open APK as ZIP
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open APK: %w", err)
	}
	defer func() { _ = reader.Close() }()

	// Collect all strings to scan
	allStrings := []string{}

	// Add DEX strings if provided
	if dexResult != nil {
		for _, dexFile := range dexResult.DexFiles {
			allStrings = append(allStrings, dexFile.Strings...)
		}
	}

	// Scan text files in assets/ and res/
	for _, file := range reader.File {
		if shouldScanFile(file) {
			content, err := readFileFromZip(file)
			if err != nil {
				continue // Skip files that can't be read
			}
			allStrings = append(allStrings, content)
		}
	}

	// Extract URLs and parse endpoints
	endpointMap := make(map[string]EndpointInfo)
	domainCount := make(map[string]int)
	domainSchemes := make(map[string]map[string]bool)

	for _, str := range allStrings {
		urls := urlPattern.FindAllString(str, -1)
		for _, urlStr := range urls {
			parsedURL, err := url.Parse(urlStr)
			if err != nil {
				continue
			}

			if parsedURL.Host == "" {
				continue
			}

			// Determine source based on which collection the string came from
			source := determineSource(str, dexResult)

			// Add endpoint (deduplicated by full URL)
			if _, exists := endpointMap[urlStr]; !exists {
				endpointMap[urlStr] = EndpointInfo{
					URL:    urlStr,
					Scheme: parsedURL.Scheme,
					Host:   parsedURL.Host,
					Path:   parsedURL.Path,
					Source: source,
				}
			}

			// Count domains
			host := strings.ToLower(parsedURL.Host)
			domainCount[host]++

			// Track schemes per domain
			if domainSchemes[host] == nil {
				domainSchemes[host] = make(map[string]bool)
			}
			domainSchemes[host][parsedURL.Scheme] = true
		}
	}

	// Convert endpoint map to slice
	for _, endpoint := range endpointMap {
		result.Endpoints = append(result.Endpoints, endpoint)
	}
	result.TotalURLs = len(result.Endpoints)

	// Build domain info
	for domain, count := range domainCount {
		schemes := []string{}
		for scheme := range domainSchemes[domain] {
			schemes = append(schemes, scheme)
		}

		result.Domains = append(result.Domains, DomainInfo{
			Domain:   domain,
			Category: ClassifyDomain(domain),
			Count:    count,
			Schemes:  schemes,
		})
	}
	result.TotalDomains = len(result.Domains)

	// Sort domains by count descending
	sort.Slice(result.Domains, func(i, j int) bool {
		return result.Domains[i].Count > result.Domains[j].Count
	})

	// Check network security config
	configData, err := FindNetworkSecConfig(apkPath)
	if err == nil && configData != nil {
		config, err := ParseNetworkSecurityConfig(configData)
		if err == nil && config != nil {
			result.NetworkSecConfig = config
		}
	}

	// Detect cert pinning
	dexStrings := []string{}
	if dexResult != nil {
		for _, dexFile := range dexResult.DexFiles {
			dexStrings = append(dexStrings, dexFile.Strings...)
		}
	}
	result.CertPinning = DetectPinning(apkPath, dexStrings)

	// Determine cleartext allowed
	result.CleartextAllowed = determineCleartextAllowed(result.NetworkSecConfig)

	return result, nil
}

// shouldScanFile determines if a ZIP file should be scanned for URLs
func shouldScanFile(file *zip.File) bool {
	// Check if in assets/ or res/
	if !strings.HasPrefix(file.Name, "assets/") && !strings.HasPrefix(file.Name, "res/") {
		return false
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(file.Name))
	if !textExtensions[ext] {
		return false
	}

	// Check file size
	if file.UncompressedSize64 > maxFileSize {
		return false
	}

	return true
}

// readFileFromZip reads a file from a ZIP archive
func readFileFromZip(file *zip.File) (string, error) {
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// determineSource determines the source of a string
func determineSource(str string, dexResult *dex.ParseResult) string {
	// Check if from DEX
	if dexResult != nil {
		for _, dexFile := range dexResult.DexFiles {
			if slices.Contains(dexFile.Strings, str) {
				return "dex_strings"
			}
		}
	}

	// Check if from assets or resources
	if strings.Contains(str, "assets/") {
		return "assets"
	}
	if strings.Contains(str, "res/") {
		return "resources"
	}

	return "unknown"
}

// determineCleartextAllowed checks if cleartext traffic is allowed
func determineCleartextAllowed(config *NetworkSecConfig) bool {
	if config == nil {
		return true // Default Android behavior
	}

	// Check base config
	if config.BaseConfig != nil && config.BaseConfig.CleartextPermitted != nil {
		return *config.BaseConfig.CleartextPermitted
	}

	// If no explicit base config, default is true for Android < 9
	// For Android 9+, default is false, but we don't know target SDK here
	return true
}
