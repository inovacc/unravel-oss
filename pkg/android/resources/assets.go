/*
Copyright (c) 2026 Security Research
*/

package resources

import (
	"archive/zip"
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

var sqliteMagic = []byte("SQLite format 3\x00")

var categoryExtensions = map[string]AssetCategory{
	".db":         AssetDatabase,
	".sqlite":     AssetDatabase,
	".sqlite3":    AssetDatabase,
	".json":       AssetConfig,
	".xml":        AssetConfig,
	".yaml":       AssetConfig,
	".yml":        AssetConfig,
	".properties": AssetConfig,
	".toml":       AssetConfig,
	".cfg":        AssetConfig,
	".conf":       AssetConfig,
	".ini":        AssetConfig,
	".pem":        AssetCertificate,
	".cer":        AssetCertificate,
	".crt":        AssetCertificate,
	".der":        AssetCertificate,
	".p12":        AssetCertificate,
	".pfx":        AssetCertificate,
	".bks":        AssetCertificate,
	".jks":        AssetCertificate,
	".so":         AssetNative,
	".png":        AssetMedia,
	".jpg":        AssetMedia,
	".jpeg":       AssetMedia,
	".gif":        AssetMedia,
	".webp":       AssetMedia,
	".svg":        AssetMedia,
	".mp3":        AssetMedia,
	".mp4":        AssetMedia,
	".ogg":        AssetMedia,
	".wav":        AssetMedia,
	".aac":        AssetMedia,
	".3gp":        AssetMedia,
	".ttf":        AssetFont,
	".otf":        AssetFont,
	".woff":       AssetFont,
	".woff2":      AssetFont,
}

// ScanAssets scans the assets/ directory in an APK and categorizes files.
func ScanAssets(apkPath string) ([]AssetInfo, error) {
	zipReader, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open APK: %w", err)
	}
	defer zipReader.Close()

	var assets []AssetInfo
	var htmlFiles []int
	var jsFiles []int
	var cssFiles []int

	for _, f := range zipReader.File {
		if !strings.HasPrefix(f.Name, "assets/") || f.FileInfo().IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(f.Name))
		category, known := categoryExtensions[ext]

		if !known {
			category = AssetData
		}

		asset := AssetInfo{
			Path:     f.Name,
			Size:     int64(f.UncompressedSize64),
			Category: category,
		}

		if category == AssetDatabase || (!known && shouldCheckSQLite(ext)) {
			if isSQLite, err := checkSQLiteFile(f); err == nil && isSQLite {
				asset.IsSQLite = true
				asset.Category = AssetDatabase
			}
		}

		if ext == ".html" {
			htmlFiles = append(htmlFiles, len(assets))
		} else if ext == ".js" {
			jsFiles = append(jsFiles, len(assets))
		} else if ext == ".css" {
			cssFiles = append(cssFiles, len(assets))
		}

		assets = append(assets, asset)
	}

	if len(htmlFiles) > 0 && (len(jsFiles) > 0 || len(cssFiles) > 0) {
		for _, idx := range htmlFiles {
			assets[idx].IsWebView = true
			assets[idx].Category = AssetWebView
		}
		for _, idx := range jsFiles {
			assets[idx].IsWebView = true
			assets[idx].Category = AssetWebView
		}
		for _, idx := range cssFiles {
			assets[idx].IsWebView = true
			assets[idx].Category = AssetWebView
		}
	}

	return assets, nil
}

func shouldCheckSQLite(ext string) bool {
	return ext == "" || ext == ".dat" || ext == ".bin"
}

func checkSQLiteFile(f *zip.File) (bool, error) {
	if f.UncompressedSize64 < 16 {
		return false, nil
	}

	rc, err := f.Open()
	if err != nil {
		return false, err
	}
	defer rc.Close()

	header := make([]byte, 16)
	n, err := rc.Read(header)
	if err != nil || n < 16 {
		return false, err
	}

	return bytes.Equal(header, sqliteMagic), nil
}

func categorizeAsset(path string) AssetCategory {
	ext := strings.ToLower(filepath.Ext(path))
	if category, ok := categoryExtensions[ext]; ok {
		return category
	}
	return AssetData
}
