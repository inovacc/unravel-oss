/*
Copyright (c) 2026 Security Research
*/
package protobuf

import (
	"archive/zip"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// ScanAPK detects protobuf/gRPC usage by combining DEX analysis with APK asset scanning.
func ScanAPK(apkPath string, dexResult *dex.ParseResult) (*ScanResult, error) {
	result := DetectProtobuf(dexResult)

	// Open APK as ZIP and scan for .proto and .pb files in assets
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return result, nil // Return DEX-only results on ZIP error
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		name := f.Name

		if strings.HasSuffix(name, ".proto") {
			if len(result.ProtoFiles) < maxProtoFiles {
				result.ProtoFiles = append(result.ProtoFiles, ProtoFileRef{
					Name:   name,
					Source: "asset_file",
				})
			}

			result.HasProtobuf = true
			result.TotalProtoRefs++
		}

		if strings.HasSuffix(name, ".pb") {
			result.HasProtobuf = true
			result.TotalProtoRefs++
		}
	}

	return result, nil
}
