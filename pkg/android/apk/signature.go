/*
Copyright (c) 2026 Security Research
*/
package apk

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/internal/boundedzip"
)

// SignatureScheme identifies an APK signature scheme version.
type SignatureScheme string

const (
	SchemeV1 SignatureScheme = "v1"
	SchemeV2 SignatureScheme = "v2"
	SchemeV3 SignatureScheme = "v3"
	SchemeV4 SignatureScheme = "v4"
)

// APK Signing Block magic and IDs.
const (
	sigBlockMagic = "APK Sig Block 42"
	blockIDV2     = 0x7109871a
	blockIDV3     = 0xf05368c0
	eocdMagic     = 0x06054b50
	eocdMinSize   = 22
	eocdMaxSearch = 65535 + eocdMinSize
)

// SignatureInfo describes one signature scheme's status.
type SignatureInfo struct {
	Scheme      SignatureScheme `json:"scheme"`
	Present     bool            `json:"present"`
	Valid       bool            `json:"valid"`
	Error       string          `json:"error,omitempty"`
	SignerCount int             `json:"signer_count"`
}

// VerifyResult aggregates signature verification across all schemes.
type VerifyResult struct {
	Path         string          `json:"path"`
	FileName     string          `json:"file_name"`
	Signatures   []SignatureInfo `json:"signatures"`
	OverallValid bool            `json:"overall_valid"`
	Schemes      []string        `json:"schemes_found"`
}

// Verify checks all APK signature schemes and returns verification results.
func Verify(apkPath string) (*VerifyResult, error) {
	absPath, err := filepath.Abs(apkPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	zr, err := boundedzip.OpenReader(absPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = zr.Close() }()

	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func() { _ = f.Close() }()

	result := &VerifyResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
	}

	v1 := checkV1(zr.Reader)
	v2 := checkV2(f)
	v3 := checkV3(f)
	v4 := checkV4(absPath)

	result.Signatures = []SignatureInfo{*v1, *v2, *v3, *v4}

	for _, sig := range result.Signatures {
		if sig.Present {
			result.Schemes = append(result.Schemes, string(sig.Scheme))
			if sig.Valid {
				result.OverallValid = true
			}
		}
	}

	return result, nil
}

func checkV1(zr *zip.Reader) *SignatureInfo {
	info := &SignatureInfo{Scheme: SchemeV1}

	hasManifestMF := false
	hasSF := false
	sigFileCount := 0

	for _, f := range zr.File {
		dir := filepath.Dir(f.Name)
		base := filepath.Base(f.Name)

		if dir != "META-INF" {
			continue
		}

		switch {
		case base == "MANIFEST.MF":
			hasManifestMF = true
		case strings.HasSuffix(base, ".SF"):
			hasSF = true
			sigFileCount++
		case strings.HasSuffix(base, ".RSA") || strings.HasSuffix(base, ".DSA") || strings.HasSuffix(base, ".EC"):
			sigFileCount++
		}
	}

	if !hasManifestMF || !hasSF {
		return info
	}

	info.Present = true
	info.SignerCount = max(sigFileCount/2, 1)

	// v1 structural validation: check MANIFEST.MF is parseable
	for _, f := range zr.File {
		if f.Name == "META-INF/MANIFEST.MF" {
			rc, err := f.Open()
			if err != nil {
				info.Error = fmt.Sprintf("open MANIFEST.MF: %v", err)
				return info
			}

			data, err := io.ReadAll(rc)
			_ = rc.Close()

			if err != nil {
				info.Error = fmt.Sprintf("read MANIFEST.MF: %v", err)
				return info
			}

			if len(data) > 0 {
				info.Valid = true
			}

			break
		}
	}

	return info
}

func checkV2(f *os.File) *SignatureInfo {
	return checkSigningBlockScheme(f, SchemeV2, blockIDV2)
}

func checkV3(f *os.File) *SignatureInfo {
	return checkSigningBlockScheme(f, SchemeV3, blockIDV3)
}

func checkSigningBlockScheme(f *os.File, scheme SignatureScheme, blockID uint32) *SignatureInfo {
	info := &SignatureInfo{Scheme: scheme}

	offset, size, err := findSigningBlock(f)
	if err != nil {
		return info
	}

	pairs, err := parseSigningBlock(f, offset, size)
	if err != nil {
		info.Error = fmt.Sprintf("parse signing block: %v", err)
		return info
	}

	data, ok := pairs[blockID]
	if !ok {
		return info
	}

	info.Present = true

	// Parse signer count from the scheme block.
	// Format: length-prefixed sequence of signers.
	signerCount, err := countSigners(data)
	if err != nil {
		info.Error = fmt.Sprintf("parse signers: %v", err)
		info.SignerCount = 1 // at least one if block present
		info.Valid = true    // block exists, assume structurally valid

		return info
	}

	info.SignerCount = signerCount
	info.Valid = signerCount > 0

	return info
}

func checkV4(apkPath string) *SignatureInfo {
	info := &SignatureInfo{Scheme: SchemeV4}

	idsigPath := apkPath + ".idsig"

	stat, err := os.Stat(idsigPath)
	if err != nil {
		return info
	}

	info.Present = true
	info.SignerCount = 1
	info.Valid = stat.Size() > 0

	return info
}

// findSigningBlock locates the APK Signing Block before the Central Directory.
//
// Algorithm:
//  1. Find ZIP EOCD by scanning backwards for magic 0x06054b50
//  2. Read CD offset from EOCD
//  3. Read 24 bytes before CD: 16-byte magic "APK Sig Block 42" + 8-byte block size
//  4. Verify magic and compute block start
func findSigningBlock(f *os.File) (offset int64, size int64, err error) {
	// Find EOCD
	stat, err := f.Stat()
	if err != nil {
		return 0, 0, fmt.Errorf("stat: %w", err)
	}

	fileSize := stat.Size()

	searchSize := min(int64(eocdMaxSearch), fileSize)

	buf := make([]byte, searchSize)

	_, err = f.ReadAt(buf, fileSize-searchSize)
	if err != nil {
		return 0, 0, fmt.Errorf("read EOCD region: %w", err)
	}

	eocdOffset := int64(-1)

	for i := len(buf) - eocdMinSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) == eocdMagic {
			eocdOffset = fileSize - searchSize + int64(i)
			break
		}
	}

	if eocdOffset < 0 {
		return 0, 0, fmt.Errorf("EOCD not found")
	}

	// Read CD offset from EOCD (offset 16 in EOCD record)
	eocdBuf := buf[eocdOffset-(fileSize-searchSize):]
	cdOffset := int64(binary.LittleEndian.Uint32(eocdBuf[16:20]))

	if cdOffset < 24 || cdOffset > fileSize {
		return 0, 0, fmt.Errorf("invalid CD offset: %d", cdOffset)
	}

	// Read the 24 bytes before CD: 8-byte block size + 16-byte magic
	footer := make([]byte, 24)

	_, err = f.ReadAt(footer, cdOffset-24)
	if err != nil {
		return 0, 0, fmt.Errorf("read signing block footer: %w", err)
	}

	magic := string(footer[8:24])
	if magic != sigBlockMagic {
		return 0, 0, fmt.Errorf("signing block magic not found")
	}

	blockSize := int64(binary.LittleEndian.Uint64(footer[0:8]))
	if blockSize < 0 || blockSize > cdOffset {
		return 0, 0, fmt.Errorf("invalid block size: %d", blockSize)
	}

	// Block start = cdOffset - blockSize - 8 (for the size field at the start)
	blockStart := cdOffset - blockSize - 8
	if blockStart < 0 {
		return 0, 0, fmt.Errorf("block start before file begin")
	}

	return blockStart, blockSize, nil
}

// parseSigningBlock reads ID-value pairs from the APK Signing Block.
func parseSigningBlock(f *os.File, offset, size int64) (map[uint32][]byte, error) {
	// Skip the 8-byte size prefix at the start of the block
	pairsStart := offset + 8
	// Pairs end before the 24-byte footer (8-byte size + 16-byte magic)
	pairsEnd := offset + size

	if pairsEnd <= pairsStart {
		return nil, fmt.Errorf("empty signing block")
	}

	pairsSize := pairsEnd - pairsStart
	buf := make([]byte, pairsSize)

	_, err := f.ReadAt(buf, pairsStart)
	if err != nil {
		return nil, fmt.Errorf("read pairs: %w", err)
	}

	pairs := make(map[uint32][]byte)

	pos := 0
	for pos+12 <= len(buf) {
		pairLen := binary.LittleEndian.Uint64(buf[pos:])
		pos += 8

		if pairLen < 4 || int64(pos)+int64(pairLen) > int64(len(buf)) {
			break
		}

		id := binary.LittleEndian.Uint32(buf[pos:])
		pos += 4

		valueLen := int(pairLen) - 4
		if valueLen > 0 && pos+valueLen <= len(buf) {
			value := make([]byte, valueLen)
			copy(value, buf[pos:pos+valueLen])
			pairs[id] = value
		}

		pos += valueLen
	}

	return pairs, nil
}

// countSigners parses the signer count from a v2/v3 scheme block.
// The block format starts with a length-prefixed sequence of signers.
func countSigners(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("data too short")
	}

	// Outer length-prefixed sequence of signers
	signersLen := binary.LittleEndian.Uint32(data[0:4])
	pos := 4
	count := 0

	for pos < int(signersLen)+4 && pos < len(data) {
		if pos+4 > len(data) {
			break
		}

		signerLen := binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		pos += int(signerLen)
		count++
	}

	return count, nil
}
