// Package cache parses Chromium HTTP cache (Simple Cache / Block File Cache).
package cache

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// Cache file magic numbers
const (
	IndexMagic       = 0xC103CAC3
	BlockFileMagic   = 0xC104CAC3
	SimpleCacheMagic = 0xFCFB6D1B
)

// Block file sizes
const (
	BlockSize36   = 36
	BlockSize256  = 256
	BlockSize1024 = 1024
	BlockSize4096 = 4096
)

// CacheEntry represents a single cached HTTP resource.
type CacheEntry struct {
	URL           string            `json:"url"`
	Key           string            `json:"key"`
	Hash          string            `json:"hash"`
	HTTPStatus    int               `json:"http_status,omitempty"`
	HTTPHeaders   map[string]string `json:"http_headers,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length"`
	CreationTime  string            `json:"creation_time,omitempty"`
	LastAccess    string            `json:"last_access,omitempty"`
	ExpiresTime   string            `json:"expires,omitempty"`
	BodyFile      string            `json:"body_file,omitempty"`
	BodySize      int64             `json:"body_size"`
	BodyHash      string            `json:"body_sha256,omitempty"`
	SourceFile    string            `json:"source_file"`
	Compressed    bool              `json:"compressed"`
}

// ParseResult holds the complete cache parsing result.
type ParseResult struct {
	SourcePath  string         `json:"source_path"`
	ParsedAt    string         `json:"parsed_at"`
	CacheFormat string         `json:"cache_format"`
	Entries     []CacheEntry   `json:"entries"`
	ByDomain    map[string]int `json:"entries_by_domain"`
	ByType      map[string]int `json:"entries_by_content_type"`
	Stats       CacheStats     `json:"stats"`
	Errors      []string       `json:"errors,omitempty"`
}

// CacheStats contains statistics about the cache parsing.
type CacheStats struct {
	TotalEntries    int   `json:"total_entries"`
	ValidEntries    int   `json:"valid_entries"`
	ExtractedBodies int   `json:"extracted_bodies"`
	TotalBodySize   int64 `json:"total_body_size"`
	ParseErrors     int   `json:"parse_errors"`
}

// IndexHeader is the block file index header.
type IndexHeader struct {
	Magic      uint32
	Version    uint32
	NumEntries uint32
	NumBytes   uint32
	LastFile   uint32
	ThisID     uint32
	TableLen   uint32
	CrashCount uint32
	Experiment uint32
	CreateTime uint64
	Padding    [52]byte
}

// DetectFormat detects the cache format at the given path.
func DetectFormat(path string) string {
	indexPath := filepath.Join(path, "index")
	if data, err := os.ReadFile(indexPath); err == nil && len(data) >= 8 {
		magic := binary.LittleEndian.Uint32(data[:4])
		if magic == IndexMagic {
			return "blockfile"
		}
	}

	if _, err := os.Stat(filepath.Join(path, "index-dir")); err == nil {
		return "simple"
	}

	if _, err := os.Stat(filepath.Join(path, "data_0")); err == nil {
		return "blockfile"
	}

	files, _ := filepath.Glob(filepath.Join(path, "f_*"))
	if len(files) > 0 {
		return "blockfile"
	}

	return "unknown"
}

// Parse parses a Chromium cache directory and optionally extracts bodies to outputDir.
// If outputDir is empty, bodies are not saved to disk.
func Parse(sourcePath, outputDir string) (*ParseResult, error) {
	if _, err := os.Stat(sourcePath); err != nil {
		return nil, fmt.Errorf("path does not exist: %w", err)
	}

	result := &ParseResult{
		SourcePath: sourcePath,
		ParsedAt:   time.Now().UTC().Format(time.RFC3339),
		Entries:    []CacheEntry{},
		ByDomain:   make(map[string]int),
		ByType:     make(map[string]int),
		Errors:     []string{},
	}

	if outputDir != "" {
		_ = os.MkdirAll(filepath.Join(outputDir, "bodies"), 0755)
	}

	result.CacheFormat = DetectFormat(sourcePath)

	switch result.CacheFormat {
	case "simple":
		parseSimpleCache(sourcePath, outputDir, result)
	case "blockfile":
		parseBlockFileCache(sourcePath, outputDir, result)
	default:
		parseGenericCache(sourcePath, outputDir, result)
	}

	organizeResults(result)

	return result, nil
}

func parseSimpleCache(sourcePath, outputDir string, result *ParseResult) {
	entries, _ := os.ReadDir(sourcePath)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if name == "index" || strings.HasPrefix(name, "index-dir") {
			continue
		}

		if !isHexString(name) && !strings.HasSuffix(name, "_0") && !strings.HasSuffix(name, "_1") {
			continue
		}

		filePath := filepath.Join(sourcePath, name)
		parseSimpleCacheEntry(filePath, outputDir, result)
	}
}

func parseSimpleCacheEntry(filePath, outputDir string, result *ParseResult) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read %s: %v", filePath, err))
		return
	}

	result.Stats.TotalEntries++

	if len(data) < 24 {
		return
	}

	entry := CacheEntry{SourceFile: filePath}

	if httpIdx := bytes.Index(data, []byte("HTTP/")); httpIdx >= 0 {
		parseHTTPResponse(data[httpIdx:], &entry)
	}

	urlRe := regexp.MustCompile(`https?://[^\s\x00"'<>]+`)
	if matches := urlRe.FindAll(data, 10); len(matches) > 0 {
		entry.URL = string(matches[0])
		entry.Key = entry.URL
	}

	bodyStart := findBodyStart(data)
	if bodyStart > 0 && bodyStart < len(data) {
		body := data[bodyStart:]
		entry.BodySize = int64(len(body))

		if len(body) > 0 {
			if isGzipped(body) {
				entry.Compressed = true

				if decompressed, err := decompressGzip(body); err == nil {
					body = decompressed
				}
			}

			if outputDir != "" {
				entry.BodyFile = saveBody(body, outputDir, entry.URL, entry.ContentType)
			}

			hash := sha256.Sum256(body)
			entry.BodyHash = hex.EncodeToString(hash[:])
			result.Stats.ExtractedBodies++
			result.Stats.TotalBodySize += int64(len(body))
		}
	}

	if entry.URL != "" || entry.BodySize > 0 {
		result.Stats.ValidEntries++
		result.Entries = append(result.Entries, entry)
	}
}

func parseBlockFileCache(sourcePath, outputDir string, result *ParseResult) {
	indexPath := filepath.Join(sourcePath, "index")
	if indexData, err := os.ReadFile(indexPath); err == nil {
		parseIndexFile(indexData, result)
	}

	for i := 0; i <= 3; i++ {
		dataPath := filepath.Join(sourcePath, fmt.Sprintf("data_%d", i))
		if data, err := os.ReadFile(dataPath); err == nil {
			parseDataFile(data, i, outputDir, result)
		}
	}

	fFiles, _ := filepath.Glob(filepath.Join(sourcePath, "f_*"))
	for _, fFile := range fFiles {
		if data, err := os.ReadFile(fFile); err == nil {
			parseSeparateEntry(data, fFile, outputDir, result)
		}
	}
}

func parseIndexFile(data []byte, result *ParseResult) {
	if len(data) < 256 {
		return
	}

	var header IndexHeader

	reader := bytes.NewReader(data)
	_ = binary.Read(reader, binary.LittleEndian, &header)
}

func parseDataFile(data []byte, fileNum int, outputDir string, result *ParseResult) {
	if len(data) < 8192 {
		return
	}

	offset := 8192

	var blockSize int

	switch fileNum {
	case 0:
		blockSize = BlockSize36
	case 1:
		blockSize = BlockSize256
	case 2:
		blockSize = BlockSize1024
	case 3:
		blockSize = BlockSize4096
	default:
		blockSize = BlockSize256
	}

	for offset < len(data)-blockSize {
		block := data[offset : offset+blockSize]
		if bytes.Contains(block, []byte("HTTP/")) {
			entry := extractEntryFromBlock(data, offset, blockSize, result)
			if entry != nil {
				entry.SourceFile = fmt.Sprintf("data_%d", fileNum)
				saveEntryBody(entry, data, offset, outputDir, result)
				result.Entries = append(result.Entries, *entry)
			}
		}

		offset += blockSize
	}
}

func extractEntryFromBlock(data []byte, offset, blockSize int, result *ParseResult) *CacheEntry {
	result.Stats.TotalEntries++

	searchStart := offset
	if searchStart > 1024 {
		searchStart = offset - 1024
	}

	searchEnd := min(offset+blockSize*4, len(data))

	chunk := data[searchStart:searchEnd]
	entry := &CacheEntry{}

	urlRe := regexp.MustCompile(`https?://[^\s\x00"'<>]+`)
	if matches := urlRe.FindAll(chunk, 5); len(matches) > 0 {
		entry.URL = string(matches[0])
		entry.Key = entry.URL
	}

	if httpIdx := bytes.Index(chunk, []byte("HTTP/")); httpIdx >= 0 {
		parseHTTPResponse(chunk[httpIdx:], entry)
	}

	if entry.URL != "" || entry.ContentType != "" {
		result.Stats.ValidEntries++
		return entry
	}

	return nil
}

func parseSeparateEntry(data []byte, filePath, outputDir string, result *ParseResult) {
	result.Stats.TotalEntries++

	entry := CacheEntry{SourceFile: filepath.Base(filePath)}

	if httpIdx := bytes.Index(data, []byte("HTTP/")); httpIdx >= 0 {
		parseHTTPResponse(data[httpIdx:], &entry)
	}

	urlRe := regexp.MustCompile(`https?://[^\s\x00"'<>]+`)
	if matches := urlRe.FindAll(data, 5); len(matches) > 0 {
		entry.URL = string(matches[0])
		entry.Key = entry.URL
	}

	bodyStart := findBodyStart(data)
	if bodyStart > 0 && bodyStart < len(data) {
		body := data[bodyStart:]
		entry.BodySize = int64(len(body))

		if len(body) > 0 {
			if isGzipped(body) {
				entry.Compressed = true

				if decompressed, err := decompressGzip(body); err == nil {
					body = decompressed
				}
			}

			if outputDir != "" {
				entry.BodyFile = saveBody(body, outputDir, entry.URL, entry.ContentType)
			}

			hash := sha256.Sum256(body)
			entry.BodyHash = hex.EncodeToString(hash[:])
			result.Stats.ExtractedBodies++
			result.Stats.TotalBodySize += int64(len(body))
		}
	}

	if entry.URL != "" || entry.BodySize > 0 {
		result.Stats.ValidEntries++
		result.Entries = append(result.Entries, entry)
	}
}

func parseGenericCache(sourcePath, outputDir string, result *ParseResult) {
	_ = filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		if bytes.Contains(data, []byte("HTTP/")) {
			entry := CacheEntry{SourceFile: path}

			httpIdx := bytes.Index(data, []byte("HTTP/"))
			parseHTTPResponse(data[httpIdx:], &entry)

			urlRe := regexp.MustCompile(`https?://[^\s\x00"'<>]+`)
			if matches := urlRe.FindAll(data, 5); len(matches) > 0 {
				entry.URL = string(matches[0])
			}

			bodyStart := findBodyStart(data)
			if bodyStart > 0 {
				body := data[bodyStart:]
				entry.BodySize = int64(len(body))

				if len(body) > 0 && len(body) < 50*1024*1024 {
					if isGzipped(body) {
						entry.Compressed = true

						if decompressed, err := decompressGzip(body); err == nil {
							body = decompressed
						}
					}

					if outputDir != "" {
						entry.BodyFile = saveBody(body, outputDir, entry.URL, entry.ContentType)
					}

					result.Stats.ExtractedBodies++
					result.Stats.TotalBodySize += int64(len(body))
				}
			}

			if entry.URL != "" || entry.BodySize > 0 {
				result.Stats.TotalEntries++
				result.Stats.ValidEntries++
				result.Entries = append(result.Entries, entry)
			}
		}

		return nil
	})
}

func parseHTTPResponse(data []byte, entry *CacheEntry) {
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(data, []byte("\n\n"))
	}

	if headerEnd < 0 || headerEnd > 8192 {
		return
	}

	headerSection := string(data[:headerEnd])
	lines := strings.Split(headerSection, "\n")

	entry.HTTPHeaders = make(map[string]string)

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if i == 0 {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 2 {
				_, _ = fmt.Sscanf(parts[1], "%d", &entry.HTTPStatus)
			}

			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			entry.HTTPHeaders[key] = value

			switch strings.ToLower(key) {
			case "content-type":
				entry.ContentType = strings.Split(value, ";")[0]
			case "content-length":
				_, _ = fmt.Sscanf(value, "%d", &entry.ContentLength)
			}
		}
	}
}

func findBodyStart(data []byte) int {
	patterns := [][]byte{
		[]byte("\r\n\r\n"),
		[]byte("\n\n"),
	}
	for _, pattern := range patterns {
		if idx := bytes.Index(data, pattern); idx >= 0 {
			return idx + len(pattern)
		}
	}

	return -1
}

func saveBody(body []byte, outputDir, url, contentType string) string {
	if len(body) == 0 {
		return ""
	}

	ext := getExtensionForContentType(contentType)
	if ext == "" {
		ext = detectFileType(body)
	}

	var filename string

	if url != "" {
		urlHash := sha256.Sum256([]byte(url))
		filename = fmt.Sprintf("%s%s", hex.EncodeToString(urlHash[:8]), ext)
	} else {
		bodyHash := sha256.Sum256(body)
		filename = fmt.Sprintf("%s%s", hex.EncodeToString(bodyHash[:8]), ext)
	}

	filePath := filepath.Join(outputDir, "bodies", filename)
	_ = os.WriteFile(filePath, body, 0644)

	return filename
}

func saveEntryBody(entry *CacheEntry, data []byte, offset int, outputDir string, result *ParseResult) {
	searchEnd := min(offset+65536, len(data))

	chunk := data[offset:searchEnd]
	bodyStart := findBodyStart(chunk)

	if bodyStart > 0 && bodyStart < len(chunk) {
		body := chunk[bodyStart:]

		if endIdx := bytes.Index(body, []byte("HTTP/")); endIdx > 0 {
			body = body[:endIdx]
		}

		body = bytes.TrimRight(body, "\x00")

		if len(body) > 0 {
			entry.BodySize = int64(len(body))

			if isGzipped(body) {
				entry.Compressed = true

				if decompressed, err := decompressGzip(body); err == nil {
					body = decompressed
				}
			}

			if outputDir != "" {
				entry.BodyFile = saveBody(body, outputDir, entry.URL, entry.ContentType)
			}

			hash := sha256.Sum256(body)
			entry.BodyHash = hex.EncodeToString(hash[:])
			result.Stats.ExtractedBodies++
			result.Stats.TotalBodySize += int64(len(body))
		}
	}
}

func isGzipped(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// maxDecompressedCacheBody bounds a single gzip-decompressed cache body so a
// hostile decompression bomb cannot OOM the host (hardening finding #21).
// Generous for real HTTP bodies; a package var so it is overridable.
var maxDecompressedCacheBody int64 = 512 << 20 // 512 MiB

func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	defer func() { _ = reader.Close() }()

	return safeio.ReadAllLimit(reader, maxDecompressedCacheBody)
}

func getExtensionForContentType(contentType string) string {
	contentType = strings.ToLower(strings.TrimSpace(contentType))

	extensions := map[string]string{
		"text/html": ".html", "text/css": ".css",
		"text/javascript": ".js", "application/javascript": ".js",
		"application/json": ".json", "image/png": ".png",
		"image/jpeg": ".jpg", "image/gif": ".gif",
		"image/webp": ".webp", "image/svg+xml": ".svg",
		"application/xml": ".xml", "text/xml": ".xml",
		"text/plain": ".txt", "application/pdf": ".pdf",
		"font/woff": ".woff", "font/woff2": ".woff2",
		"application/font-woff": ".woff", "application/font-woff2": ".woff2",
	}
	if ext, ok := extensions[contentType]; ok {
		return ext
	}

	return ""
}

func detectFileType(data []byte) string {
	if len(data) < 4 {
		return ".bin"
	}

	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG")):
		return ".png"
	case bytes.HasPrefix(data, []byte("\xff\xd8\xff")):
		return ".jpg"
	case bytes.HasPrefix(data, []byte("GIF8")):
		return ".gif"
	case bytes.HasPrefix(data, []byte("RIFF")) && len(data) > 12 && string(data[8:12]) == "WEBP":
		return ".webp"
	case bytes.HasPrefix(data, []byte("%PDF")):
		return ".pdf"
	case bytes.HasPrefix(data, []byte("<!DOCTYPE")) || bytes.HasPrefix(data, []byte("<html")):
		return ".html"
	case bytes.HasPrefix(data, []byte("{")):
		return ".json"
	case bytes.HasPrefix(data, []byte("<?xml")):
		return ".xml"
	case bytes.HasPrefix(data, []byte("wOFF")):
		return ".woff"
	case bytes.HasPrefix(data, []byte("wOF2")):
		return ".woff2"
	default:
		if http.DetectContentType(data) == "text/plain; charset=utf-8" {
			return ".txt"
		}

		return ".bin"
	}
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	return len(s) > 0
}

func organizeResults(result *ParseResult) {
	for _, entry := range result.Entries {
		if entry.URL != "" {
			domain := extractDomain(entry.URL)
			result.ByDomain[domain]++
		}

		contentType := entry.ContentType
		if contentType == "" {
			contentType = "unknown"
		}

		result.ByType[contentType]++
	}
}

func extractDomain(url string) string {
	url = strings.TrimPrefix(url, "http://")

	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx > 0 {
		url = url[:idx]
	}

	if idx := strings.Index(url, ":"); idx > 0 {
		url = url[:idx]
	}

	return url
}

// FormatSummary returns a human-readable summary string.
func FormatSummary(result *ParseResult) string {
	var buf bytes.Buffer

	buf.WriteString("Chromium Cache Parse Summary\n")
	buf.WriteString("============================\n\n")
	buf.WriteString(fmt.Sprintf("Source: %s\n", result.SourcePath))
	buf.WriteString(fmt.Sprintf("Format: %s\n", result.CacheFormat))
	buf.WriteString(fmt.Sprintf("Parsed At: %s\n\n", result.ParsedAt))

	buf.WriteString(fmt.Sprintf("Total Entries: %d\n", result.Stats.TotalEntries))
	buf.WriteString(fmt.Sprintf("Valid Entries: %d\n", result.Stats.ValidEntries))
	buf.WriteString(fmt.Sprintf("Bodies Extracted: %d\n", result.Stats.ExtractedBodies))
	buf.WriteString(fmt.Sprintf("Total Body Size: %s\n\n", FormatBytes(result.Stats.TotalBodySize)))

	buf.WriteString("Entries by Domain\n-----------------\n")

	domains := make([]string, 0, len(result.ByDomain))
	for domain := range result.ByDomain {
		domains = append(domains, domain)
	}

	sort.Strings(domains)

	for _, domain := range domains {
		buf.WriteString(fmt.Sprintf("  %s: %d\n", domain, result.ByDomain[domain]))
	}

	return buf.String()
}

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}

	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
