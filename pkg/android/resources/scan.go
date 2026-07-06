/*
Copyright (c) 2026 Security Research
*/

package resources

import (
	"archive/zip"
	"fmt"
	"io"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// maxARSCBytes bounds the decompressed resources.arsc read. Real arsc tables
// are well under this even for large apps; the cap defeats DEFLATE bombs that
// inflate a tiny entry to multiple GB. It is a var so tests can shrink it.
var maxARSCBytes int64 = 512 << 20 // 512 MiB

// ScanAPK performs a complete scan of an APK's resources and assets.
func ScanAPK(apkPath string) (*ScanResult, error) {
	result := &ScanResult{
		Assets:     []AssetInfo{},
		Categories: make(map[AssetCategory]int),
	}

	zipReader, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open APK: %w", err)
	}
	defer zipReader.Close()

	for _, f := range zipReader.File {
		if f.Name == "resources.arsc" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open resources.arsc: %w", err)
			}

			data, err := safeio.ReadAllLimit(rc, maxARSCBytes)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("read resources.arsc: %w", err)
			}

			readerAt := &bytesReaderAt{data: data}
			stringPool, packageName, typeNames, err := ParseARSC(readerAt, int64(len(data)))
			if err != nil {
				return nil, fmt.Errorf("parse resources.arsc: %w", err)
			}

			result.StringPool = stringPool
			result.PackageName = packageName
			result.TypeNames = typeNames
			break
		}
	}

	assets, err := ScanAssets(apkPath)
	if err != nil {
		return nil, fmt.Errorf("scan assets: %w", err)
	}

	result.Assets = assets
	result.TotalAssets = len(assets)

	for _, asset := range assets {
		result.TotalSize += asset.Size
		result.Categories[asset.Category]++

		if asset.IsSQLite {
			result.HasDatabases = true
		}
		if asset.IsWebView {
			result.HasWebView = true
		}
	}

	return result, nil
}

type bytesReaderAt struct {
	data []byte
}

func (r *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return n, err
}
