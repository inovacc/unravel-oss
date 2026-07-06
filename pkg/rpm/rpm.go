/*
Copyright (c) 2026 Security Research
*/
package rpm

import (
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// Magic bytes and constants.
var rpmMagic = [4]byte{0xED, 0xAB, 0xEE, 0xDB}
var headerMagic = [3]byte{0x8E, 0xAD, 0xE8}

const maxExtractedFileBytes = 512 << 20 // 512 MiB per-file cap

// Aggregate CPIO extraction caps for untrusted .rpm payloads. These are vars
// (not consts) so tests can shrink them without writing GB. Defaults are
// generous: legitimate large RPMs (kernels, LibreOffice) extract well over
// 1 GiB, so an 8 GiB aggregate budget and 200k-entry cap reject only bombs.
var (
	// maxRPMTotalBytes bounds cumulative uncompressed bytes across all CPIO
	// entries, and also caps the decompressed payload reader.
	maxRPMTotalBytes int64 = 8 << 30 // 8 GiB
	// maxRPMEntries bounds the number of CPIO entries processed.
	maxRPMEntries int64 = 200_000
	// maxRPMEntryBytes is the per-entry uncompressed cap. Defaults to the
	// per-file const; a var so tests can shrink it without a 512 MiB fixture.
	maxRPMEntryBytes int64 = maxExtractedFileBytes
)

// RPM header tag IDs (main header).
const (
	tagName              = 1000
	tagVersion           = 1001
	tagRelease           = 1002
	tagEpoch             = 1003
	tagSummary           = 1004
	tagDescription       = 1005
	tagBuildTime         = 1006
	tagBuildHost         = 1007
	tagSize              = 1009
	tagDistribution      = 1010
	tagVendor            = 1011
	tagLicense           = 1014
	tagPackager          = 1015
	tagGroup             = 1016
	tagURL               = 1020
	tagOS                = 1021
	tagArch              = 1022
	tagSourceRPM         = 1044
	tagPayloadFormat     = 1124
	tagPayloadCompressor = 1125
)

// Signature header tag IDs.
const (
	sigTagMD5    = 1004
	sigTagSHA1   = 269
	sigTagSHA256 = 273
	sigTagRSA    = 268
	sigTagDSA    = 267
	sigTagPGP    = 1002
	sigTagGPG    = 1005
)

// Data type constants.
const (
	typeNull       = 0
	typeChar       = 1
	typeInt8       = 2
	typeInt16      = 3
	typeInt32      = 4
	typeInt64      = 5
	typeString     = 6
	typeBin        = 7
	typeStringArr  = 8
	typeI18NString = 9
)

// Lead is the 96-byte RPM lead structure.
type Lead struct {
	Magic         [4]byte
	Major         uint8
	Minor         uint8
	Type          uint16
	ArchNum       uint16
	Name          [66]byte
	OSNum         uint16
	SignatureType uint16
	Reserved      [16]byte
}

// IndexEntry is a 16-byte header index entry.
type IndexEntry struct {
	Tag    int32
	Type   uint32
	Offset uint32
	Count  uint32
}

// HeaderSection represents a parsed RPM header section.
type HeaderSection struct {
	Entries []IndexEntry
	Data    []byte
}

// InfoResult contains metadata about an RPM package.
type InfoResult struct {
	Path              string            `json:"path"`
	FileName          string            `json:"file_name"`
	Size              int64             `json:"size"`
	RPMVersion        string            `json:"rpm_version"`
	Type              string            `json:"type"`
	LeadName          string            `json:"lead_name"`
	Name              string            `json:"name"`
	Version           string            `json:"version"`
	Release           string            `json:"release"`
	Epoch             string            `json:"epoch,omitempty"`
	Arch              string            `json:"arch"`
	OS                string            `json:"os"`
	Summary           string            `json:"summary"`
	Description       string            `json:"description"`
	License           string            `json:"license"`
	Vendor            string            `json:"vendor,omitempty"`
	Packager          string            `json:"packager,omitempty"`
	Group             string            `json:"group,omitempty"`
	URL               string            `json:"url,omitempty"`
	Distribution      string            `json:"distribution,omitempty"`
	SourceRPM         string            `json:"source_rpm,omitempty"`
	BuildHost         string            `json:"build_host,omitempty"`
	BuildTime         int64             `json:"build_time,omitempty"`
	InstalledSize     int64             `json:"installed_size"`
	PayloadFormat     string            `json:"payload_format"`
	PayloadCompressor string            `json:"payload_compressor"`
	HasSignature      bool              `json:"has_signature"`
	SignatureInfo     map[string]string `json:"signature_info,omitempty"`
	HeaderTagCount    int               `json:"header_tag_count"`
	SigTagCount       int               `json:"sig_tag_count"`
}

// ExtractReport summarizes an RPM extraction.
type ExtractReport struct {
	Source      string   `json:"source"`
	Output      string   `json:"output"`
	Compressor  string   `json:"compressor"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	TotalSize   int64    `json:"total_size"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifyResult contains signature/hash verification results.
type VerifyResult struct {
	Path         string            `json:"path"`
	FileName     string            `json:"file_name"`
	HasSignature bool              `json:"has_signature"`
	Hashes       map[string]string `json:"hashes,omitempty"`
	Signatures   []string          `json:"signatures,omitempty"`
}

// Info parses an RPM file and returns metadata.
func Info(rpmPath string) (*InfoResult, error) {
	absPath, err := filepath.Abs(rpmPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	stat, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	lead, err := readLead(f)
	if err != nil {
		return nil, err
	}

	sigHeader, err := readHeaderSection(f)
	if err != nil {
		return nil, fmt.Errorf("read signature header: %w", err)
	}

	// Align to 8-byte boundary after signature
	pos, _ := f.Seek(0, io.SeekCurrent)

	padding := (8 - (pos % 8)) % 8
	if padding > 0 {
		if _, err := f.Seek(padding, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("align after signature: %w", err)
		}
	}

	mainHeader, err := readHeaderSection(f)
	if err != nil {
		return nil, fmt.Errorf("read main header: %w", err)
	}

	rpmType := "binary"
	if lead.Type == 1 {
		rpmType = "source"
	}

	leadName := strings.TrimRight(string(lead.Name[:]), "\x00")

	result := &InfoResult{
		Path:           absPath,
		FileName:       filepath.Base(absPath),
		Size:           stat.Size(),
		RPMVersion:     fmt.Sprintf("%d.%d", lead.Major, lead.Minor),
		Type:           rpmType,
		LeadName:       leadName,
		HeaderTagCount: len(mainHeader.Entries),
		SigTagCount:    len(sigHeader.Entries),
	}

	// Parse main header tags
	result.Name = getString(mainHeader, tagName)
	result.Version = getString(mainHeader, tagVersion)
	result.Release = getString(mainHeader, tagRelease)
	result.Arch = getString(mainHeader, tagArch)
	result.OS = getString(mainHeader, tagOS)
	result.Summary = getString(mainHeader, tagSummary)
	result.Description = getString(mainHeader, tagDescription)
	result.License = getString(mainHeader, tagLicense)
	result.Vendor = getString(mainHeader, tagVendor)
	result.Packager = getString(mainHeader, tagPackager)
	result.Group = getString(mainHeader, tagGroup)
	result.URL = getString(mainHeader, tagURL)
	result.Distribution = getString(mainHeader, tagDistribution)
	result.SourceRPM = getString(mainHeader, tagSourceRPM)
	result.BuildHost = getString(mainHeader, tagBuildHost)
	result.PayloadFormat = getString(mainHeader, tagPayloadFormat)
	result.PayloadCompressor = getString(mainHeader, tagPayloadCompressor)

	if epoch := getInt32(mainHeader, tagEpoch); epoch != 0 {
		result.Epoch = fmt.Sprintf("%d", epoch)
	}

	result.BuildTime = int64(getInt32(mainHeader, tagBuildTime))
	result.InstalledSize = int64(getInt32(mainHeader, tagSize))

	// Parse signature info
	result.SignatureInfo = make(map[string]string)

	for _, entry := range sigHeader.Entries {
		switch entry.Tag {
		case sigTagMD5:
			data := getBin(sigHeader, entry.Tag)
			if len(data) > 0 {
				result.SignatureInfo["md5"] = hex.EncodeToString(data)
				result.HasSignature = true
			}
		case sigTagSHA1:
			val := getString(sigHeader, int32(entry.Tag))
			if val != "" {
				result.SignatureInfo["sha1"] = val
				result.HasSignature = true
			}
		case sigTagSHA256:
			val := getString(sigHeader, int32(entry.Tag))
			if val != "" {
				result.SignatureInfo["sha256"] = val
				result.HasSignature = true
			}
		case sigTagRSA:
			result.SignatureInfo["rsa_header_sig"] = "present"
			result.HasSignature = true
		case sigTagDSA:
			result.SignatureInfo["dsa_header_sig"] = "present"
			result.HasSignature = true
		case sigTagPGP:
			result.SignatureInfo["pgp_sig"] = "present"
			result.HasSignature = true
		case sigTagGPG:
			result.SignatureInfo["gpg_sig"] = "present"
			result.HasSignature = true
		}
	}

	return result, nil
}

// Extract extracts the RPM payload to disk.
func Extract(rpmPath, outputDir string) (*ExtractReport, error) {
	absPath, err := filepath.Abs(rpmPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	// Skip lead
	if _, err := readLead(f); err != nil {
		return nil, err
	}

	// Skip signature header
	if _, err := readHeaderSection(f); err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}

	// Align to 8-byte boundary
	pos, _ := f.Seek(0, io.SeekCurrent)

	padding := (8 - (pos % 8)) % 8
	if padding > 0 {
		if _, err := f.Seek(padding, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("align: %w", err)
		}
	}

	// Read main header to get compressor
	mainHeader, err := readHeaderSection(f)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	compressor := getString(mainHeader, tagPayloadCompressor)
	if compressor == "" {
		compressor = "gzip" // default
	}

	if outputDir == "" {
		base := filepath.Base(absPath)
		outputDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
	}

	report := &ExtractReport{
		Source:     absPath,
		Output:     outputDir,
		Compressor: compressor,
	}

	// Decompress payload
	var reader io.Reader

	switch compressor {
	case "gzip":
		gz, err := gzip.NewReader(f)
		if err != nil {
			return report, fmt.Errorf("gzip decompress: %w", err)
		}

		defer func() { _ = gz.Close() }()

		reader = gz
	case "bzip2":
		reader = bzip2.NewReader(f)
	case "xz":
		xzr, err := xz.NewReader(f)
		if err != nil {
			return report, fmt.Errorf("xz decompress: %w", err)
		}

		reader = xzr
	case "zstd":
		zstdr, err := zstd.NewReader(f)
		if err != nil {
			return report, fmt.Errorf("zstd decompress: %w", err)
		}
		defer zstdr.Close()

		reader = zstdr
	case "lzma":
		return report, fmt.Errorf("lzma payload compression not supported (use rpm2cpio)")
	default:
		reader = f
	}

	// SEC: bound the decompressed payload so a high-ratio gz/xz/zstd bomb in a
	// tiny .rpm cannot expand to terabytes. The per-entry caps inside
	// extractCPIO do not bound the aggregate stream on their own.
	reader = io.LimitReader(reader, maxRPMTotalBytes+1)

	// Parse CPIO from decompressed stream
	files, dirs, totalSize, errs := extractCPIO(reader, outputDir)
	report.Files = files
	report.Directories = dirs
	report.TotalSize = totalSize
	report.Errors = errs

	return report, nil
}

// Verify checks RPM signatures and hashes.
func Verify(rpmPath string) (*VerifyResult, error) {
	absPath, err := filepath.Abs(rpmPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	if _, err := readLead(f); err != nil {
		return nil, err
	}

	sigHeader, err := readHeaderSection(f)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}

	result := &VerifyResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
		Hashes:   make(map[string]string),
	}

	for _, entry := range sigHeader.Entries {
		switch entry.Tag {
		case sigTagMD5:
			data := getBin(sigHeader, entry.Tag)
			if len(data) > 0 {
				result.Hashes["md5"] = hex.EncodeToString(data)
			}
		case sigTagSHA1:
			val := getString(sigHeader, int32(entry.Tag))
			if val != "" {
				result.Hashes["sha1"] = val
			}
		case sigTagSHA256:
			val := getString(sigHeader, int32(entry.Tag))
			if val != "" {
				result.Hashes["sha256"] = val
			}
		case sigTagRSA:
			result.HasSignature = true
			result.Signatures = append(result.Signatures, "RSA (header-only)")
		case sigTagDSA:
			result.HasSignature = true
			result.Signatures = append(result.Signatures, "DSA (header-only)")
		case sigTagPGP:
			result.HasSignature = true
			result.Signatures = append(result.Signatures, "PGP (header+payload)")
		case sigTagGPG:
			result.HasSignature = true
			result.Signatures = append(result.Signatures, "GPG (header+payload)")
		}
	}

	return result, nil
}

// readLead reads and validates the 96-byte RPM lead.
func readLead(r io.Reader) (*Lead, error) {
	var lead Lead
	if err := binary.Read(r, binary.BigEndian, &lead); err != nil {
		return nil, fmt.Errorf("read lead: %w", err)
	}

	if lead.Magic != rpmMagic {
		return nil, fmt.Errorf("not an RPM file (bad magic: %x)", lead.Magic)
	}

	return &lead, nil
}

// readHeaderSection reads a header section (signature or main header).
func readHeaderSection(r io.Reader) (*HeaderSection, error) {
	// Read 16-byte preamble
	var magic [3]byte
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, fmt.Errorf("read header magic: %w", err)
	}

	if magic != headerMagic {
		return nil, fmt.Errorf("bad header magic: %x", magic)
	}

	var version uint8
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, fmt.Errorf("read header version: %w", err)
	}

	var reserved uint32
	if err := binary.Read(r, binary.BigEndian, &reserved); err != nil {
		return nil, fmt.Errorf("read header reserved: %w", err)
	}

	var nindex, hsize uint32
	if err := binary.Read(r, binary.BigEndian, &nindex); err != nil {
		return nil, fmt.Errorf("read nindex: %w", err)
	}

	if err := binary.Read(r, binary.BigEndian, &hsize); err != nil {
		return nil, fmt.Errorf("read hsize: %w", err)
	}

	if nindex > 100000 || hsize > 100*1024*1024 {
		return nil, fmt.Errorf("header too large: %d entries, %d bytes", nindex, hsize)
	}

	// Read index entries
	entries := make([]IndexEntry, nindex)
	for i := uint32(0); i < nindex; i++ {
		if err := binary.Read(r, binary.BigEndian, &entries[i]); err != nil {
			return nil, fmt.Errorf("read index entry %d: %w", i, err)
		}
	}

	// Read data store
	data := make([]byte, hsize)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("read data store: %w", err)
	}

	return &HeaderSection{
		Entries: entries,
		Data:    data,
	}, nil
}

// getString reads a string tag value from a header section.
func getString(h *HeaderSection, tag int32) string {
	for _, e := range h.Entries {
		if e.Tag != tag {
			continue
		}

		if e.Type != typeString && e.Type != typeI18NString {
			continue
		}

		if int(e.Offset) >= len(h.Data) {
			return ""
		}
		// Find null terminator
		end := int(e.Offset)
		for end < len(h.Data) && h.Data[end] != 0 {
			end++
		}

		return string(h.Data[e.Offset:end])
	}

	return ""
}

// getInt32 reads an INT32 tag value from a header section.
func getInt32(h *HeaderSection, tag int32) int32 {
	for _, e := range h.Entries {
		if e.Tag != tag || e.Type != typeInt32 {
			continue
		}

		if int(e.Offset)+4 > len(h.Data) {
			return 0
		}

		return int32(binary.BigEndian.Uint32(h.Data[e.Offset:]))
	}

	return 0
}

// getBin reads a binary tag value from a header section.
func getBin(h *HeaderSection, tag int32) []byte {
	for _, e := range h.Entries {
		if e.Tag != tag || e.Type != typeBin {
			continue
		}

		end := int(e.Offset) + int(e.Count)
		if end > len(h.Data) {
			return nil
		}

		result := make([]byte, e.Count)
		copy(result, h.Data[e.Offset:end])

		return result
	}

	return nil
}

// extractCPIO parses a CPIO newc archive and extracts files.
func extractCPIO(r io.Reader, outputDir string) (files, dirs int, totalSize int64, errors []string) {
	buf := make([]byte, 110)

	// SEC: bound aggregate uncompressed bytes and entry count so a CPIO with
	// many large or many tiny entries cannot exhaust disk/inodes.
	budget := safeio.NewBudget()
	budget.MaxTotalBytes = maxRPMTotalBytes
	budget.MaxEntries = maxRPMEntries
	budget.MaxEntryBytes = maxRPMEntryBytes

	for {
		// Read 110-byte CPIO header
		if _, err := io.ReadFull(r, buf); err != nil {
			if err != io.EOF { //nolint:errorlint // io.ReadFull returns io.EOF unwrapped; named return shadows errors pkg
				errors = append(errors, fmt.Sprintf("read cpio header: %v", err))
			}

			break
		}

		magic := string(buf[0:6])
		if magic != "070701" && magic != "070702" {
			errors = append(errors, fmt.Sprintf("bad cpio magic: %s", magic))
			break
		}

		mode, _ := strconv.ParseUint(string(buf[14:22]), 16, 32)
		filesize, _ := strconv.ParseUint(string(buf[54:62]), 16, 64)
		namesize, _ := strconv.ParseUint(string(buf[94:102]), 16, 32)

		// SEC: an over-cap namesize means the name itself cannot be safely read
		// to stay aligned, so abort with a clear error.
		if namesize > 4096 {
			errors = append(errors, fmt.Sprintf("cpio entry namesize %d exceeds 4096, aborting extraction", namesize))
			break
		}

		// Read filename
		nameBuf := make([]byte, namesize)
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			errors = append(errors, fmt.Sprintf("read cpio name: %v", err))
			break
		}

		name := strings.TrimRight(string(nameBuf), "\x00")

		// Align to 4-byte boundary (from start of header)
		headerAndName := 110 + int(namesize)

		namePad := (4 - (headerAndName % 4)) % 4
		if namePad > 0 {
			discard := make([]byte, namePad)
			if _, err := io.ReadFull(r, discard); err != nil {
				break
			}
		}

		// Check for trailer
		if name == "TRAILER!!!" {
			break
		}

		// SEC: an over-cap filesize is a per-entry bomb. Rather than aborting the
		// whole archive (which lets a hostile leading entry hide everything
		// after it), skip just this entry: discard its body + padding so the
		// CPIO stream stays aligned and benign trailing entries still extract.
		if int64(filesize) < 0 || int64(filesize) > maxRPMEntryBytes {
			errors = append(errors, fmt.Sprintf("cpio entry %q filesize %d exceeds cap, skipping entry", name, filesize))
			dataPad := (4 - (int64(filesize) % 4)) % 4
			if _, err := io.CopyN(io.Discard, r, int64(filesize)+dataPad); err != nil {
				errors = append(errors, fmt.Sprintf("desync skipping oversized entry %q: %v", name, err))
				break
			}
			continue
		}

		// SEC: account this entry against the aggregate budget before doing any
		// further work; a poisoned entry count/total aborts extraction.
		if err := budget.Add(int64(filesize)); err != nil {
			errors = append(errors, fmt.Sprintf("cpio aggregate limit reached at %q: %v", name, err))
			break
		}

		// Read file data. filesize is already validated against the per-entry
		// cap above, so the allocation is bounded.
		data, err := safeio.MakeBounded(int64(filesize), maxRPMEntryBytes)
		if err != nil {
			errors = append(errors, fmt.Sprintf("cpio entry %q: %v", name, err))
			break
		}
		if filesize > 0 {
			if _, err := io.ReadFull(r, data); err != nil {
				errors = append(errors, fmt.Sprintf("read cpio data for %s: %v", name, err))
				break
			}
		}

		// Align to 4-byte boundary after file data
		dataPad := (4 - (int(filesize) % 4)) % 4
		if dataPad > 0 {
			discard := make([]byte, dataPad)
			if _, err := io.ReadFull(r, discard); err != nil {
				break
			}
		}

		// Clean path
		name = strings.TrimPrefix(name, "./")

		name = strings.TrimPrefix(name, "/")
		if name == "" || name == "." {
			continue
		}

		target := filepath.Join(outputDir, name)

		// Prevent path traversal
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(outputDir)+string(os.PathSeparator)) &&
			filepath.Clean(target) != filepath.Clean(outputDir) {
			errors = append(errors, fmt.Sprintf("skipped (path traversal): %s", name))
			continue
		}

		isDir := (mode & 0o170000) == 0o040000
		isSymlink := (mode & 0o170000) == 0o120000

		if isDir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				errors = append(errors, fmt.Sprintf("mkdir %s: %v", name, err))
			}

			dirs++
		} else if isSymlink {
			linkTarget := string(data)

			// String-level check: reject absolute link targets and targets
			// whose clean path escapes outputDir.
			resolvedLink := filepath.Join(filepath.Dir(target), linkTarget)
			if relSym, errSym := filepath.Rel(outputDir, resolvedLink); errSym != nil ||
				relSym == ".." || strings.HasPrefix(relSym, ".."+string(os.PathSeparator)) ||
				filepath.IsAbs(linkTarget) {
				errors = append(errors, fmt.Sprintf("skipped (unsafe symlink target): %s -> %s", name, linkTarget))
				continue
			}

			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				errors = append(errors, fmt.Sprintf("mkdir parent %s: %v", name, err))
				continue
			}

			// TOCTOU check: resolve the real on-disk parent so that a
			// previously-extracted directory-level symlink cannot redirect
			// the write outside outputDir (symlink-chaining attack).
			realParent, errEval := filepath.EvalSymlinks(filepath.Dir(target))
			if errEval != nil {
				errors = append(errors, fmt.Sprintf("skipped (cannot eval parent): %s: %v", name, errEval))
				continue
			}
			if !strings.HasPrefix(realParent+string(os.PathSeparator), filepath.Clean(outputDir)+string(os.PathSeparator)) {
				errors = append(errors, fmt.Sprintf("skipped (parent escapes outputDir after symlink resolution): %s", name))
				continue
			}

			_ = os.Remove(target)
			if err := os.Symlink(linkTarget, target); err != nil {
				errors = append(errors, fmt.Sprintf("symlink %s: %v", name, err))
			}

			files++
		} else if filesize > 0 {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				errors = append(errors, fmt.Sprintf("mkdir parent %s: %v", name, err))
				continue
			}

			if err := os.WriteFile(target, data, os.FileMode(mode&0o777)); err != nil {
				errors = append(errors, fmt.Sprintf("write %s: %v", name, err))
				continue
			}

			files++
			totalSize += int64(filesize)
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
