/*
Copyright (c) 2026 Security Research
*/
package dex

import (
	"archive/zip"
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/garble"
	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// maxDexBytes bounds the decompressed read of a single classes*.dex entry.
// Real DEX files are well under 1 GiB; the cap defeats DEFLATE bombs. It is a
// var so tests can shrink it.
var maxDexBytes int64 = 1 << 30 // 1 GiB

// ScanAPK opens an APK as a ZIP archive, parses all classes*.dex entries,
// and returns aggregated results with risk analysis and high-entropy strings.
func ScanAPK(apkPath string) (*ParseResult, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("dex: opening APK: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// minDexSize is the minimum valid DEX file size (header = 112 bytes).
	// Packer stubs and decoy files are often < 200 bytes.
	const minDexSize = 200

	var dexEntries []*zip.File
	for _, f := range zr.File {
		if isDexEntry(f.Name) && f.UncompressedSize64 >= minDexSize {
			dexEntries = append(dexEntries, f)
		}
	}

	if len(dexEntries) == 0 {
		return nil, fmt.Errorf("dex: no DEX files found in APK")
	}

	sort.Slice(dexEntries, func(i, j int) bool {
		return dexEntries[i].Name < dexEntries[j].Name
	})

	result := &ParseResult{
		MultiDex: len(dexEntries) > 1,
	}

	for _, entry := range dexEntries {
		dex, err := parseDexEntry(entry)
		if err != nil {
			// Skip malformed DEX entries (packer stubs, corrupted files)
			// instead of aborting the entire scan.
			result.ParseErrors = append(result.ParseErrors, fmt.Sprintf("%s: %v", entry.Name, err))
			continue
		}
		dex.Name = entry.Name

		result.DexFiles = append(result.DexFiles, *dex)
		result.TotalClasses += len(dex.Classes)
		result.TotalMethods += len(dex.Methods)
		result.TotalFields += len(dex.Fields)
		result.TotalStrings += len(dex.Strings)

		result.HighEntropyStrings = append(result.HighEntropyStrings,
			findHighEntropyStrings(dex)...)
		result.RiskFindings = append(result.RiskFindings, AnalyzeRisk(dex)...)
	}

	return result, nil
}

func isDexEntry(name string) bool {
	if name == "classes.dex" {
		return true
	}
	// Match classes2.dex, classes3.dex, etc.
	if strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex") {
		return true
	}
	return false
}

func parseDexEntry(f *zip.File) (*DexFile, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	data, err := safeio.ReadAllLimit(rc, maxDexBytes)
	if err != nil {
		return nil, err
	}

	return Parse(bytes.NewReader(data), int64(len(data)))
}

func findHighEntropyStrings(dex *DexFile) []HighEntropyString {
	var results []HighEntropyString

	for _, s := range dex.Strings {
		if len(s) < 16 {
			continue
		}
		entropy := garble.ShannonEntropy(s)
		if entropy > 4.5 {
			results = append(results, HighEntropyString{
				Value:   s,
				Entropy: entropy,
				Source:  dex.Name,
			})
		}
	}

	return results
}
