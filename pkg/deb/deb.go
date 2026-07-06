/*
Copyright (c) 2026 Security Research
*/
package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

const arMagic = "!<arch>\n"
const arEntryMagic = "`\n"

// maxExtractedFileBytes is the per-file decompressed cap. An entry exceeding it
// is SKIPPED (dropped + warned), never written as a silently truncated partial.
// A var (not a const) so tests can inject a small cap.
var maxExtractedFileBytes int64 = 512 << 20 // 512 MiB per-file cap

// SEC: bounds for untrusted .deb input. These are vars (not consts) so tests
// can shrink them without writing GiB. Defaults are generous so legitimate
// packages are never rejected; only egregious bombs trip them.
var (
	// maxArMemberBytes caps a single ar member allocation (compressed
	// control.tar/data.tar blob). 512 MiB matches the historical per-file cap.
	maxArMemberBytes int64 = maxExtractedFileBytes
	// maxArMembers caps the ar member count. A real .deb has exactly 3
	// members (debian-binary, control.tar.*, data.tar.*); 16 is generous.
	maxArMembers = 16
	// maxControlBytes caps the decompressed control file read. Control files
	// are KB-scale; 16 MiB is a generous ceiling.
	maxControlBytes int64 = 16 << 20
	// maxDebTotalBytes caps aggregate decompressed bytes written by extractTar.
	maxDebTotalBytes int64 = 4 << 30 // 4 GiB
	// maxDebEntries caps the number of tar entries extractTar will process.
	maxDebEntries int64 = 100_000
)

// ControlField represents a single field from the control file.
type ControlField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Control represents parsed Debian control file metadata.
type Control struct {
	Package       string         `json:"package"`
	Version       string         `json:"version"`
	Architecture  string         `json:"architecture"`
	Maintainer    string         `json:"maintainer"`
	Description   string         `json:"description"`
	Section       string         `json:"section,omitempty"`
	Priority      string         `json:"priority,omitempty"`
	Homepage      string         `json:"homepage,omitempty"`
	Depends       string         `json:"depends,omitempty"`
	PreDepends    string         `json:"pre_depends,omitempty"`
	Recommends    string         `json:"recommends,omitempty"`
	Suggests      string         `json:"suggests,omitempty"`
	Conflicts     string         `json:"conflicts,omitempty"`
	Replaces      string         `json:"replaces,omitempty"`
	Provides      string         `json:"provides,omitempty"`
	InstalledSize string         `json:"installed_size,omitempty"`
	AllFields     []ControlField `json:"all_fields"`
}

// ArEntry represents a member of the ar archive.
type ArEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"`
	Mode    int64  `json:"mode"`
	Data    []byte `json:"-"`
}

// FileEntry represents a file inside the data archive.
type FileEntry struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Mode       string `json:"mode"`
	IsDir      bool   `json:"is_dir"`
	IsLink     bool   `json:"is_link"`
	LinkTarget string `json:"link_target,omitempty"`
}

// InfoResult contains metadata about a DEB package.
type InfoResult struct {
	Path           string      `json:"path"`
	FileName       string      `json:"file_name"`
	Size           int64       `json:"size"`
	FormatVersion  string      `json:"format_version"`
	Control        *Control    `json:"control"`
	ControlArchive string      `json:"control_archive"`
	DataArchive    string      `json:"data_archive"`
	HasSignature   bool        `json:"has_signature"`
	SignatureFiles []string    `json:"signature_files,omitempty"`
	Scripts        []string    `json:"scripts,omitempty"`
	FileCount      int         `json:"file_count"`
	DirCount       int         `json:"dir_count"`
	TotalSize      int64       `json:"total_size"`
	Files          []FileEntry `json:"files,omitempty"`
}

// ExtractReport summarizes a DEB extraction.
type ExtractReport struct {
	Source      string   `json:"source"`
	Output      string   `json:"output"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	TotalSize   int64    `json:"total_size"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifyResult contains signature verification results.
type VerifyResult struct {
	Path           string   `json:"path"`
	FileName       string   `json:"file_name"`
	HasSignature   bool     `json:"has_signature"`
	SignatureFiles []string `json:"signature_files,omitempty"`
	SignatureType  string   `json:"signature_type,omitempty"`
}

// Info parses a DEB package and returns metadata.
func Info(debPath string, includeFiles bool) (*InfoResult, error) {
	absPath, err := filepath.Abs(debPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	stat, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	entries, err := readArArchive(absPath)
	if err != nil {
		return nil, err
	}

	result := &InfoResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
		Size:     stat.Size(),
	}

	for _, entry := range entries {
		switch {
		case entry.Name == "debian-binary":
			result.FormatVersion = strings.TrimSpace(string(entry.Data))

		case strings.HasPrefix(entry.Name, "control.tar"):
			result.ControlArchive = entry.Name

			ctrl, scripts, err := parseControlArchive(entry.Data, entry.Name)
			if err == nil {
				result.Control = ctrl
				result.Scripts = scripts
			}

		case strings.HasPrefix(entry.Name, "data.tar"):
			result.DataArchive = entry.Name

			files, err := listTarContents(entry.Data, entry.Name)
			if err == nil {
				for _, f := range files {
					if f.IsDir {
						result.DirCount++
					} else {
						result.FileCount++
						result.TotalSize += f.Size
					}
				}

				if includeFiles {
					result.Files = files
				}
			}

		case strings.HasPrefix(entry.Name, "_gpg"):
			result.HasSignature = true
			result.SignatureFiles = append(result.SignatureFiles, entry.Name)
		}
	}

	return result, nil
}

// Extract extracts a DEB package contents to disk.
func Extract(debPath, outputDir string) (*ExtractReport, error) {
	absPath, err := filepath.Abs(debPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	entries, err := readArArchive(absPath)
	if err != nil {
		return nil, err
	}

	if outputDir == "" {
		base := filepath.Base(absPath)
		outputDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
	}

	report := &ExtractReport{
		Source: absPath,
		Output: outputDir,
	}

	for _, entry := range entries {
		switch {
		case entry.Name == "debian-binary":
			// Write the version file
			target := filepath.Join(outputDir, "debian-binary")
			if err := os.MkdirAll(outputDir, 0o755); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("mkdir: %v", err))
				continue
			}

			if err := os.WriteFile(target, entry.Data, 0o644); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("write debian-binary: %v", err))
			}

			report.Files++

		case strings.HasPrefix(entry.Name, "control.tar"):
			dir := filepath.Join(outputDir, "control")
			f, d, sz, errs := extractTar(entry.Data, entry.Name, dir)
			report.Files += f
			report.Directories += d
			report.TotalSize += sz
			report.Errors = append(report.Errors, errs...)

		case strings.HasPrefix(entry.Name, "data.tar"):
			dir := filepath.Join(outputDir, "data")
			f, d, sz, errs := extractTar(entry.Data, entry.Name, dir)
			report.Files += f
			report.Directories += d
			report.TotalSize += sz
			report.Errors = append(report.Errors, errs...)

		case strings.HasPrefix(entry.Name, "_gpg"):
			target := filepath.Join(outputDir, entry.Name)
			if err := os.MkdirAll(outputDir, 0o755); err == nil {
				if err := os.WriteFile(target, entry.Data, 0o644); err != nil {
					report.Errors = append(report.Errors, fmt.Sprintf("write %s: %v", entry.Name, err))
				}
			}

			report.Files++
		}
	}

	return report, nil
}

// Verify checks a DEB package for signatures.
func Verify(debPath string) (*VerifyResult, error) {
	absPath, err := filepath.Abs(debPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	entries, err := readArArchive(absPath)
	if err != nil {
		return nil, err
	}

	result := &VerifyResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, "_gpg") {
			result.HasSignature = true
			result.SignatureFiles = append(result.SignatureFiles, entry.Name)

			// Detect signature type
			content := string(entry.Data)
			switch {
			case strings.Contains(content, "Role:"):
				result.SignatureType = "dpkg-sig"
			case strings.Contains(content, "BEGIN PGP SIGNATURE"):
				result.SignatureType = "debsigs"
			default:
				result.SignatureType = "unknown"
			}
		}
	}

	return result, nil
}

// readArArchive reads all entries from an ar archive.
func readArArchive(path string) ([]ArEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	// Verify ar magic
	magic := make([]byte, 8)
	if _, err := io.ReadFull(f, magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}

	if string(magic) != arMagic {
		return nil, fmt.Errorf("not an ar archive (bad magic: %q)", string(magic))
	}

	var entries []ArEntry

	for {
		// SEC: cap the ar member count so a hostile archive cannot make us
		// buffer an unbounded number of members in memory.
		if int64(len(entries)) >= int64(maxArMembers) {
			return entries, fmt.Errorf("ar archive declares more than %d members", maxArMembers)
		}

		entry, err := readArEntry(f)
		if err == io.EOF {
			break
		}

		if err != nil {
			return entries, fmt.Errorf("read ar entry: %w", err)
		}

		entries = append(entries, *entry)
	}

	return entries, nil
}

// readArEntry reads a single ar archive entry.
func readArEntry(r io.ReadSeeker) (*ArEntry, error) {
	header := make([]byte, 60)

	_, err := io.ReadFull(r, header)
	if err != nil {
		return nil, err
	}

	// Validate entry magic
	if string(header[58:60]) != arEntryMagic {
		return nil, fmt.Errorf("invalid ar entry magic: %q", string(header[58:60]))
	}

	name := strings.TrimRight(string(header[0:16]), " ")
	name = strings.TrimSuffix(name, "/")

	modTime, _ := strconv.ParseInt(strings.TrimSpace(string(header[16:28])), 10, 64)
	mode, _ := strconv.ParseInt(strings.TrimSpace(string(header[40:48])), 8, 64)
	size, _ := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)

	// SEC: size is the attacker-declared ar header field. Validate it against
	// the member cap before allocating so a huge claim cannot pre-allocate GiB.
	data, err := safeio.MakeBounded(size, maxArMemberBytes)
	if err != nil {
		return nil, fmt.Errorf("ar entry %s: %w", name, err)
	}
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read entry data for %s: %w", name, err)
	}

	// Skip padding byte if size is odd
	if size%2 != 0 {
		if _, err := r.Seek(1, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("skip padding: %w", err)
		}
	}

	return &ArEntry{
		Name:    name,
		Size:    size,
		ModTime: modTime,
		Mode:    mode,
		Data:    data,
	}, nil
}

// decompressReader wraps data in the appropriate decompressor.
func decompressReader(data []byte, archiveName string) (io.Reader, error) {
	r := bytes.NewReader(data)

	switch {
	case strings.HasSuffix(archiveName, ".gz"):
		return gzip.NewReader(r)
	case strings.HasSuffix(archiveName, ".bz2"):
		return bzip2.NewReader(r), nil
	case strings.HasSuffix(archiveName, ".xz"):
		return xz.NewReader(r)
	case strings.HasSuffix(archiveName, ".zst"):
		return zstd.NewReader(r)
	default:
		// Assume uncompressed tar
		return r, nil
	}
}

// parseControlArchive extracts the control file and script names from the control archive.
func parseControlArchive(data []byte, archiveName string) (*Control, []string, error) {
	reader, err := decompressReader(data, archiveName)
	if err != nil {
		return nil, nil, err
	}

	tr := tar.NewReader(reader)

	var (
		ctrl    *Control
		scripts []string
	)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			break
		}

		base := filepath.Base(hdr.Name)
		switch base {
		case "control":
			// SEC: the control member is decompressed from an unbounded
			// gzip/xz/zstd/bzip2 stream. Bound the read so a multi-GiB
			// "control" file cannot OOM the host; treat overflow as malformed.
			content, err := safeio.ReadAllLimit(tr, maxControlBytes)
			if err != nil {
				continue
			}

			ctrl = parseControlFile(string(content))
		case "preinst", "postinst", "prerm", "postrm", "config", "triggers":
			scripts = append(scripts, base)
		}
	}

	return ctrl, scripts, nil
}

// parseControlFile parses an RFC 822-style control file.
func parseControlFile(content string) *Control {
	ctrl := &Control{}
	scanner := bufio.NewScanner(strings.NewReader(content))

	var currentKey, currentValue string

	flush := func() {
		if currentKey == "" {
			return
		}

		val := strings.TrimSpace(currentValue)
		ctrl.AllFields = append(ctrl.AllFields, ControlField{Key: currentKey, Value: val})

		switch strings.ToLower(currentKey) {
		case "package":
			ctrl.Package = val
		case "version":
			ctrl.Version = val
		case "architecture":
			ctrl.Architecture = val
		case "maintainer":
			ctrl.Maintainer = val
		case "description":
			ctrl.Description = val
		case "section":
			ctrl.Section = val
		case "priority":
			ctrl.Priority = val
		case "homepage":
			ctrl.Homepage = val
		case "depends":
			ctrl.Depends = val
		case "pre-depends":
			ctrl.PreDepends = val
		case "recommends":
			ctrl.Recommends = val
		case "suggests":
			ctrl.Suggests = val
		case "conflicts":
			ctrl.Conflicts = val
		case "replaces":
			ctrl.Replaces = val
		case "provides":
			ctrl.Provides = val
		case "installed-size":
			ctrl.InstalledSize = val
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			// Continuation line
			currentValue += "\n" + line
			continue
		}
		// New field
		flush()

		idx := strings.Index(line, ":")
		if idx > 0 {
			currentKey = line[:idx]
			currentValue = line[idx+1:]
		}
	}

	flush()

	return ctrl
}

// listTarContents lists files in a tar archive.
func listTarContents(data []byte, archiveName string) ([]FileEntry, error) {
	reader, err := decompressReader(data, archiveName)
	if err != nil {
		return nil, err
	}

	tr := tar.NewReader(reader)

	var files []FileEntry

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			break
		}

		entry := FileEntry{
			Name: hdr.Name,
			Size: hdr.Size,
			Mode: hdr.FileInfo().Mode().String(),
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			entry.IsDir = true
		case tar.TypeSymlink:
			entry.IsLink = true
			entry.LinkTarget = hdr.Linkname
		}

		files = append(files, entry)
	}

	return files, nil
}

// extractTar extracts a tar archive to a directory.
func extractTar(data []byte, archiveName, outputDir string) (files, dirs int, totalSize int64, errors []string) {
	reader, err := decompressReader(data, archiveName)
	if err != nil {
		return 0, 0, 0, []string{fmt.Sprintf("decompress %s: %v", archiveName, err)}
	}

	tr := tar.NewReader(reader)

	// SEC: bound aggregate extraction. The per-file LimitReader below resets
	// every entry, so without a running budget a tiny xz/zst can write TB to
	// disk or flood inodes with millions of entries. Track actual bytes
	// written (not the attacker-supplied hdr.Size) and entry count.
	var (
		entryCount   int64
		writtenTotal int64
	)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			errors = append(errors, fmt.Sprintf("read tar: %v", err))
			break
		}

		// Account every entry against the count cap (dirs/symlinks/files).
		entryCount++
		if entryCount > maxDebEntries {
			errors = append(errors, fmt.Sprintf("aggregate extraction limit: entry count exceeds %d", maxDebEntries))
			break
		}

		target := filepath.Join(outputDir, hdr.Name)

		// Prevent path traversal
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(outputDir)+string(os.PathSeparator)) &&
			filepath.Clean(target) != filepath.Clean(outputDir) {
			errors = append(errors, fmt.Sprintf("skipped (path traversal): %s", hdr.Name))
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				errors = append(errors, fmt.Sprintf("mkdir %s: %v", hdr.Name, err))
			}

			dirs++

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				errors = append(errors, fmt.Sprintf("mkdir parent %s: %v", hdr.Name, err))
				continue
			}

			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
			if err != nil {
				errors = append(errors, fmt.Sprintf("create %s: %v", hdr.Name, err))
				continue
			}

			// SEC: copy at most cap+1 so an over-cap entry is DETECTED (n > cap)
			// rather than silently truncated to the cap. On over-cap, drop the
			// partial file and SKIP the entry (warn + record), so analysis output
			// is never corrupted by a truncated partial. The whole archive must
			// not abort for one over-cap entry.
			n, err := io.Copy(out, io.LimitReader(tr, maxExtractedFileBytes+1))
			if err != nil {
				_ = out.Close()

				errors = append(errors, fmt.Sprintf("write %s: %v", hdr.Name, err))

				continue
			}

			if n > maxExtractedFileBytes {
				_ = out.Close()
				_ = os.Remove(target)
				slog.Warn("skipping over-cap deb entry (would truncate)", "name", hdr.Name, "cap_bytes", maxExtractedFileBytes)
				errors = append(errors, fmt.Sprintf("skipped (exceeds %d-byte per-file cap): %s", maxExtractedFileBytes, hdr.Name))

				continue
			}

			_ = out.Close()
			files++
			totalSize += hdr.Size

			// SEC: charge the ACTUAL bytes written (hdr.Size is unverified) and
			// hard-stop the whole extraction once the aggregate cap is exceeded.
			writtenTotal += n
			if writtenTotal > maxDebTotalBytes {
				errors = append(errors, fmt.Sprintf("aggregate extraction limit: total bytes exceed %d", maxDebTotalBytes))
				return files, dirs, totalSize, errors
			}

		case tar.TypeSymlink:
			// String-level check: reject absolute link targets and targets
			// whose clean path escapes outputDir.
			resolvedLink := filepath.Join(filepath.Dir(target), hdr.Linkname)
			if relSym, errSym := filepath.Rel(outputDir, resolvedLink); errSym != nil ||
				relSym == ".." || strings.HasPrefix(relSym, ".."+string(os.PathSeparator)) ||
				filepath.IsAbs(hdr.Linkname) {
				errors = append(errors, fmt.Sprintf("skipped (unsafe symlink target): %s -> %s", hdr.Name, hdr.Linkname))
				continue
			}

			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				errors = append(errors, fmt.Sprintf("mkdir parent %s: %v", hdr.Name, err))
				continue
			}

			// TOCTOU check: resolve the real on-disk parent so that a
			// previously-extracted directory-level symlink cannot redirect
			// the write outside outputDir (symlink-chaining attack).
			realParent, errEval := filepath.EvalSymlinks(filepath.Dir(target))
			if errEval != nil {
				errors = append(errors, fmt.Sprintf("skipped (cannot eval parent): %s: %v", hdr.Name, errEval))
				continue
			}
			if !strings.HasPrefix(realParent+string(os.PathSeparator), filepath.Clean(outputDir)+string(os.PathSeparator)) {
				errors = append(errors, fmt.Sprintf("skipped (parent escapes outputDir after symlink resolution): %s", hdr.Name))
				continue
			}

			_ = os.Remove(target) // remove if exists
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				errors = append(errors, fmt.Sprintf("symlink %s: %v", hdr.Name, err))
				continue
			}

			files++
		}
	}

	return files, dirs, totalSize, errors
}

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(size int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case size >= gb:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(gb))
	case size >= mb:
		return fmt.Sprintf("%.1f MB", float64(size)/float64(mb))
	case size >= kb:
		return fmt.Sprintf("%.1f KB", float64(size)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}
