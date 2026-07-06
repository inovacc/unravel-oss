/*
Copyright (c) 2026 Security Research
*/
package obfuscation

import (
	"archive/zip"
	"strings"
)

// packerSO maps known native library names to their packer identification.
var packerSO = map[string]string{
	"libsecexe.so":        "Bangcle",
	"libjiagu.so":         "Qihoo 360",
	"libtosprotection.so": "Tencent Legu",
	"libDexHelper.so":     "DEXProtector",
}

// packerSOPrefixes maps library name prefixes to their packer identification.
var packerSOPrefixes = map[string]string{
	"libshella": "Bangcle Shell",
}

// packerAssets maps known asset paths to their packer identification.
var packerAssets = map[string]string{
	"assets/classes.dex.dat": "Generic DEX packer",
	"assets/libjiagu.so":     "Qihoo 360",
}

// packerAssetPrefixes maps asset path prefixes to their packer identification.
var packerAssetPrefixes = map[string]string{
	"assets/ijiami": "Ijiami",
}

// DetectPacker opens the APK at the given path and checks for known packer
// libraries and assets. Returns nil if no packer is detected.
func DetectPacker(apkPath string) *PackerInfo {
	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		// Check native libraries in lib/ directories
		if strings.HasPrefix(f.Name, "lib/") {
			name := f.Name[strings.LastIndex(f.Name, "/")+1:]

			if packer, ok := packerSO[name]; ok {
				return &PackerInfo{
					Name:       packer,
					Confidence: 90,
					Evidence:   f.Name,
				}
			}

			for prefix, packer := range packerSOPrefixes {
				if strings.HasPrefix(name, prefix) {
					return &PackerInfo{
						Name:       packer,
						Confidence: 85,
						Evidence:   f.Name,
					}
				}
			}
		}

		// Check known packer assets
		if packer, ok := packerAssets[f.Name]; ok {
			return &PackerInfo{
				Name:       packer,
				Confidence: 80,
				Evidence:   f.Name,
			}
		}

		for prefix, packer := range packerAssetPrefixes {
			if strings.HasPrefix(f.Name, prefix) {
				return &PackerInfo{
					Name:       packer,
					Confidence: 75,
					Evidence:   f.Name,
				}
			}
		}
	}

	return nil
}
