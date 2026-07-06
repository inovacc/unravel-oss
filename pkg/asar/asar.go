/*
Copyright (c) 2026 Security Research
*/
package asar

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// FileEntry represents a single file or directory inside an ASAR archive.
type FileEntry struct {
	Offset     string                `json:"offset,omitempty"`
	Size       int64                 `json:"size"`
	Executable bool                  `json:"executable,omitempty"`
	Unpacked   bool                  `json:"unpacked,omitempty"`
	Integrity  map[string]any        `json:"integrity,omitempty"`
	Files      map[string]*FileEntry `json:"files,omitempty"`
}

// Header is the top-level structure of an ASAR archive.
type Header struct {
	Files map[string]*FileEntry `json:"files"`
}

// ExtractedFile describes a file collected from the ASAR header.
type ExtractedFile struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Offset     int64  `json:"offset"`
	Executable bool   `json:"executable"`
	Unpacked   bool   `json:"unpacked"`
	IsDir      bool   `json:"is_dir"`
}

// ExtractReport is the result of extracting an ASAR archive.
type ExtractReport struct {
	Source      string   `json:"source"`
	Output      string   `json:"output"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	TotalSize   int64    `json:"total_size"`
	Errors      []string `json:"errors"`
}

// SearchMatch represents a single pattern match inside an ASAR file.
type SearchMatch struct {
	FilePath string         `json:"file_path"`
	FileSize int64          `json:"file_size"`
	Contexts []MatchContext `json:"contexts"`
}

// MatchContext is a context line around a match.
type MatchContext struct {
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// SearchResult holds all matches from an ASAR search.
type SearchResult struct {
	Pattern string        `json:"pattern"`
	Matches []SearchMatch `json:"matches"`
	Total   int           `json:"total"`
}

// OpenAndParse opens an ASAR file, parses its header, and returns
// the open file handle, header, header size, and data offset.
// The caller is responsible for closing the returned file.
func OpenAndParse(path string) (*os.File, *Header, int, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("failed to open: %w", err)
	}

	headerPrefix := make([]byte, 16)
	if _, err := file.Read(headerPrefix); err != nil {
		_ = file.Close()
		return nil, nil, 0, 0, fmt.Errorf("failed to read header: %w", err)
	}

	totalHeaderSize := binary.LittleEndian.Uint32(headerPrefix[4:8])
	headerStrSize := binary.LittleEndian.Uint32(headerPrefix[12:16])

	// SEC: headerStrSize is attacker-controlled (4 raw bytes from the file).
	// A 16-byte file claiming 0xFFFFFFFF would make() ~4 GiB before any read.
	// Reject sizes that exceed the actual file or an absolute cap, and use a
	// bounded read so a lying-but-plausible size cannot be over-materialized.
	if fi, statErr := file.Stat(); statErr == nil {
		if int64(headerStrSize) > fi.Size() {
			_ = file.Close()
			return nil, nil, 0, 0, fmt.Errorf("header size %d exceeds archive size %d", headerStrSize, fi.Size())
		}
	}
	if err := safeio.CheckSize(int64(headerStrSize), maxASARHeaderBytes); err != nil {
		_ = file.Close()
		return nil, nil, 0, 0, fmt.Errorf("invalid header size: %w", err)
	}

	headerJSON := make([]byte, headerStrSize)
	if _, err := io.ReadFull(file, headerJSON); err != nil {
		_ = file.Close()
		return nil, nil, 0, 0, fmt.Errorf("failed to read header JSON: %w", err)
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		_ = file.Close()
		return nil, nil, 0, 0, fmt.Errorf("failed to parse header: %w", err)
	}

	dataOffset := int64(8 + totalHeaderSize)
	if dataOffset%4 != 0 {
		dataOffset += 4 - (dataOffset % 4)
	}

	return file, &header, int(headerStrSize), dataOffset, nil
}

// CollectFiles walks an ASAR header recursively and returns a flat list of files.
func CollectFiles(files map[string]*FileEntry, prefix string) []ExtractedFile {
	var result []ExtractedFile
	collectFiles(files, prefix, &result)
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })

	return result
}

func collectFiles(files map[string]*FileEntry, prefix string, result *[]ExtractedFile) {
	for name, entry := range files {
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}

		if entry.Files != nil {
			*result = append(*result, ExtractedFile{Path: path, IsDir: true})
			collectFiles(entry.Files, path, result)
		} else {
			offset := int64(0)
			if entry.Offset != "" {
				_, _ = fmt.Sscanf(entry.Offset, "%d", &offset)
			}

			*result = append(*result, ExtractedFile{
				Path:       path,
				Size:       entry.Size,
				Offset:     offset,
				Executable: entry.Executable,
				Unpacked:   entry.Unpacked,
			})
		}
	}
}

const (
	maxExtractedFileBytes = 256 << 20      // 256 MiB per-file cap
	maxASARTotalBytes     = 8 * 1024 << 20 // 8 GiB cumulative cap
	// maxASARHeaderBytes caps the header-JSON allocation. Real ASAR headers
	// are small (KB to low MB even for huge apps); 256 MiB is a generous ceiling.
	maxASARHeaderBytes = 256 << 20
)

// Extract extracts an ASAR archive to the given output directory.
func Extract(file *os.File, header *Header, dataOffset int64, outDir, srcPath string, verbose bool) *ExtractReport {
	report := &ExtractReport{
		Source: srcPath,
		Output: outDir,
		Errors: make([]string, 0),
	}

	_ = os.MkdirAll(outDir, 0755)

	// Obtain the archive file size for bounds-checking declared entry sizes.
	var archiveSize int64
	if fi, err := file.Stat(); err == nil {
		archiveSize = fi.Size()
	}

	var totalExtracted int64

	files := CollectFiles(header.Files, "")

	for _, f := range files {
		outPath := filepath.Join(outDir, filepath.FromSlash(f.Path))

		// Zip-slip guard: reject entries that escape the output directory.
		if filepath.IsAbs(f.Path) {
			report.Errors = append(report.Errors, fmt.Sprintf("unsafe archive path (absolute): %s", f.Path))
			continue
		}
		rel, err := filepath.Rel(outDir, outPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			report.Errors = append(report.Errors, fmt.Sprintf("unsafe archive path (traversal): %s", f.Path))
			continue
		}

		if f.IsDir {
			if err := os.MkdirAll(outPath, 0755); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("mkdir %s: %v", f.Path, err))
			} else {
				report.Directories++
			}
		} else if f.Unpacked {
			unpackedPath := srcPath + ".unpacked"

			unpackedSrc := filepath.Join(unpackedPath, filepath.FromSlash(f.Path))
			// Zip-slip guard for the unpacked source path too.
			if relU, errU := filepath.Rel(unpackedPath, unpackedSrc); errU != nil || relU == ".." || strings.HasPrefix(relU, ".."+string(os.PathSeparator)) {
				report.Errors = append(report.Errors, fmt.Sprintf("unsafe unpacked path: %s", f.Path))
				continue
			}
			if err := copyFileContents(unpackedSrc, outPath); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("copy %s: %v", f.Path, err))
			} else {
				report.Files++

				report.TotalSize += f.Size
				if verbose {
					fmt.Printf("Copied: %s\n", f.Path)
				}
			}
		} else {
			// Bounds-check: verify the declared entry region lies within the
			// archive file so io.CopyN cannot read past the end of the file.
			if archiveSize > 0 {
				entryEnd := dataOffset + f.Offset + f.Size
				if f.Size < 0 || f.Offset < 0 || entryEnd > archiveSize {
					report.Errors = append(report.Errors, fmt.Sprintf("entry %s has out-of-bounds region (offset=%d size=%d archiveSize=%d)", f.Path, f.Offset, f.Size, archiveSize))
					continue
				}
			}
			if err := extractFile(file, dataOffset, f.Offset, f.Size, outPath); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("extract %s: %v", f.Path, err))
			} else {
				report.Files++
				report.TotalSize += f.Size
				totalExtracted += f.Size
				if totalExtracted > maxASARTotalBytes {
					report.Errors = append(report.Errors, fmt.Sprintf("total extracted size exceeds %d-byte cap; aborting remaining entries", maxASARTotalBytes))
					break
				}
				if verbose {
					fmt.Printf("Extracted: %s\n", f.Path)
				}
			}
		}
	}

	return report
}

// ReadFileContent reads a single file's content from the ASAR archive.
func ReadFileContent(archive *os.File, dataOffset, fileOffset, size int64) ([]byte, error) {
	// SEC (parser-panic): Size/Offset come straight from attacker-controlled
	// header JSON. A negative size reaches make([]byte, size) -> makeslice panic.
	// Reject negative bounds before the high-side cap and the allocation.
	if size < 0 || fileOffset < 0 || dataOffset < 0 {
		return nil, fmt.Errorf("asar: invalid entry bounds (offset=%d size=%d)", fileOffset, size)
	}
	maxSize := int64(10 * 1024 * 1024)
	if size > maxSize {
		size = maxSize
	}

	if _, err := archive.Seek(dataOffset+fileOffset, io.SeekStart); err != nil {
		return nil, err
	}

	content := make([]byte, size)
	_, err := io.ReadFull(archive, content)

	return content, err
}

// Search searches all files in the ASAR archive for the given pattern.
func Search(archive *os.File, header *Header, dataOffset int64, pattern string) *SearchResult {
	result := &SearchResult{
		Pattern: pattern,
		Matches: make([]SearchMatch, 0),
	}

	files := CollectFiles(header.Files, "")
	patternLower := strings.ToLower(pattern)

	for _, f := range files {
		if f.IsDir || f.Unpacked {
			continue
		}

		content, err := ReadFileContent(archive, dataOffset, f.Offset, f.Size)
		if err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(string(content)), patternLower) {
			match := SearchMatch{
				FilePath: f.Path,
				FileSize: f.Size,
				Contexts: extractContexts(string(content), pattern, 3),
			}
			result.Matches = append(result.Matches, match)
			result.Total++
		}
	}

	return result
}

func extractContexts(content, pattern string, maxContexts int) []MatchContext {
	var contexts []MatchContext

	contentLower := strings.ToLower(content)
	patternLower := strings.ToLower(pattern)

	idx := 0
	for range maxContexts {
		pos := strings.Index(contentLower[idx:], patternLower)
		if pos == -1 {
			break
		}

		pos += idx

		start := max(pos-40, 0)

		end := min(pos+len(pattern)+40, len(content))
		if start > end || start > len(content) || end > len(content) {
			break
		}

		ctx := strings.ReplaceAll(content[start:end], "\n", " ")
		ctx = strings.ReplaceAll(ctx, "\r", "")
		lineNum := strings.Count(content[:pos], "\n") + 1
		contexts = append(contexts, MatchContext{Line: lineNum, Snippet: ctx})
		idx = pos + len(pattern)
	}

	return contexts
}

func extractFile(archive *os.File, dataOffset, fileOffset, size int64, outPath string) error {
	if size > maxExtractedFileBytes {
		return fmt.Errorf("entry too large (%d bytes): %s", size, outPath)
	}

	_ = os.MkdirAll(filepath.Dir(outPath), 0755)

	if _, err := archive.Seek(dataOffset+fileOffset, io.SeekStart); err != nil {
		return err
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return err
	}

	defer func() { _ = outFile.Close() }()

	_, err = io.CopyN(outFile, archive, size)

	return err
}

func copyFileContents(src, dst string) error {
	_ = os.MkdirAll(filepath.Dir(dst), 0755)

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}

	defer func() { _ = srcFile.Close() }()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer func() { _ = dstFile.Close() }()

	_, err = io.Copy(dstFile, srcFile)

	return err
}

// FormatBytes returns a human-readable byte size string.
func FormatBytes(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case size >= GB:
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	case size >= MB:
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	case size >= KB:
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	default:
		return fmt.Sprintf("%d B", size)
	}
}
