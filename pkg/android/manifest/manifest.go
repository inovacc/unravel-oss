/*
Copyright (c) 2026 Security Research
*/
package manifest

import (
	"archive/zip"
	"fmt"
	"io"
)

// ParseAPK opens an APK file, locates AndroidManifest.xml, and decodes it.
func ParseAPK(apkPath string) (*Manifest, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk: %w", err)
	}

	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if f.Name == "AndroidManifest.xml" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open manifest: %w", err)
			}

			defer func() { _ = rc.Close() }()

			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("read manifest: %w", err)
			}

			return ParseAXML(data)
		}
	}

	return nil, fmt.Errorf("AndroidManifest.xml not found in %s", apkPath)
}
