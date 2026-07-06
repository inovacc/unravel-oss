package ios

import (
	"archive/zip"
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// IPAInfo contains metadata extracted from an iOS IPA file.
type IPAInfo struct {
	Path            string            `json:"path"`
	BundleID        string            `json:"bundle_id"`
	BundleName      string            `json:"bundle_name"`
	Version         string            `json:"version"`
	BuildVersion    string            `json:"build_version"`
	MinimumOS       string            `json:"minimum_os"`
	Platform        string            `json:"platform"`
	Executable      string            `json:"executable"`
	DeviceFamily    []string          `json:"device_family,omitempty"`
	Architectures   []string          `json:"architectures,omitempty"`
	Frameworks      []string          `json:"frameworks,omitempty"`
	URLSchemes      []string          `json:"url_schemes,omitempty"`
	Permissions     []PermissionEntry `json:"permissions,omitempty"`
	Entitlements    map[string]any    `json:"entitlements,omitempty"`
	HasProvisioning bool              `json:"has_provisioning"`
	SigningInfo     *SigningInfo      `json:"signing_info,omitempty"`
	MachO           *MachOInfo        `json:"macho,omitempty"`
	CodeSign        *CodeSignInfo     `json:"code_sign,omitempty"`
	FileCount       int               `json:"file_count"`
	TotalSize       int64             `json:"total_size"`
}

// PermissionEntry describes a single iOS privacy permission found in Info.plist.
type PermissionEntry struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	Usage       string `json:"usage,omitempty"`
}

// SigningInfo holds code signing metadata.
type SigningInfo struct {
	HasCodeSignature bool   `json:"has_code_signature"`
	TeamID           string `json:"team_id,omitempty"`
	SigningIdentity  string `json:"signing_identity,omitempty"`
}

// Info parses an IPA file and extracts metadata.
func Info(ipaPath string) (*IPAInfo, error) {
	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, fmt.Errorf("open IPA: %w", err)
	}
	defer func() { _ = zr.Close() }()

	info := &IPAInfo{
		Path:        ipaPath,
		SigningInfo: &SigningInfo{},
	}

	// Find the .app bundle and gather file inventory
	var appPrefix string
	frameworkSet := make(map[string]bool)

	for _, f := range zr.File {
		info.FileCount++
		info.TotalSize += int64(f.UncompressedSize64)

		// Detect .app bundle root: Payload/AppName.app/
		if appPrefix == "" {
			if parts := strings.SplitN(f.Name, "/", 3); len(parts) >= 2 {
				if strings.EqualFold(parts[0], "Payload") && strings.HasSuffix(parts[1], ".app") {
					appPrefix = parts[0] + "/" + parts[1] + "/"
				}
			}
		}

		if appPrefix == "" {
			continue
		}

		rel := strings.TrimPrefix(f.Name, appPrefix)
		if rel == f.Name {
			continue // not under .app bundle
		}

		// Check for _CodeSignature
		if strings.HasPrefix(rel, "_CodeSignature/") {
			info.SigningInfo.HasCodeSignature = true
		}

		// Check for provisioning profile
		if rel == "embedded.mobileprovision" {
			info.HasProvisioning = true
		}

		// Collect frameworks
		if strings.HasPrefix(rel, "Frameworks/") {
			parts := strings.SplitN(rel, "/", 3)
			if len(parts) >= 2 && strings.HasSuffix(parts[1], ".framework") {
				name := strings.TrimSuffix(parts[1], ".framework")
				frameworkSet[name] = true
			}
		}
	}

	for fw := range frameworkSet {
		info.Frameworks = append(info.Frameworks, fw)
	}

	if appPrefix == "" {
		return nil, fmt.Errorf("no .app bundle found in IPA (expected Payload/AppName.app/)")
	}

	// Parse Info.plist
	plistData, err := readZipFile(zr, appPrefix+"Info.plist", maxMetadataBytes)
	if err != nil {
		return info, fmt.Errorf("read Info.plist: %w", err)
	}

	plist, err := ParseXMLPlist(plistData)
	if err != nil {
		return info, fmt.Errorf("parse Info.plist: %w", err)
	}

	info.BundleID = plistString(plist, "CFBundleIdentifier")
	info.BundleName = plistString(plist, "CFBundleDisplayName")
	if info.BundleName == "" {
		info.BundleName = plistString(plist, "CFBundleName")
	}
	info.Version = plistString(plist, "CFBundleShortVersionString")
	info.BuildVersion = plistString(plist, "CFBundleVersion")
	info.MinimumOS = plistString(plist, "MinimumOSVersion")
	info.Executable = plistString(plist, "CFBundleExecutable")

	// Platform detection
	info.Platform = detectPlatform(plist)

	// Device families
	info.DeviceFamily = resolveDeviceFamilies(plist)

	// URL schemes
	info.URLSchemes = extractURLSchemes(plist)

	// Privacy permissions
	info.Permissions = extractPermissions(plist)

	// Parse the main Mach-O executable from the .app bundle inside the ZIP.
	if info.Executable != "" {
		execPath := appPrefix + info.Executable
		if execData, err := readZipFile(zr, execPath, maxExecutableBytes); err == nil {
			r := bytes.NewReader(execData)
			if machoInfo, err := ParseMachOFromReader(r); err == nil {
				info.MachO = machoInfo
			}
		}
	}

	// Verify code signing.
	if cs, err := VerifyCodeSign(ipaPath); err == nil {
		info.CodeSign = cs
	}

	return info, nil
}

// maxMetadataBytes caps plist/manifest reads at 16 MiB — no real IPA metadata
// file is legitimately larger than a few hundred KB. It is a var (not a const)
// so tests can shrink the cap to assert bounded reads without allocating GiB.
var maxMetadataBytes int64 = 16 << 20 // 16 MiB

// maxExecutableBytes caps the main Mach-O executable read at 2 GiB (matching
// safeio.DefaultMaxEntryBytes). Real iOS app binaries are routinely 50-200+ MiB,
// so the 16 MiB metadata cap would silently truncate them and break Mach-O
// analysis; this generous cap leaves legitimate apps intact while still ERRORING
// (via safeio.ReadAllLimit) on a true multi-GiB bomb instead of truncating it.
// A var (not a const) so tests can shrink the cap.
var maxExecutableBytes int64 = 2 << 30 // 2 GiB

// readZipFile reads the named archive entry, bounded by max bytes. It returns
// safeio.ErrLimitExceeded if the entry is larger than max, so an over-cap entry
// is rejected rather than silently truncated.
func readZipFile(zr *zip.ReadCloser, name string, max int64) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			return safeio.ReadAllLimit(rc, max)
		}
	}
	return nil, fmt.Errorf("file %q not found in archive", name)
}

func plistString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func detectPlatform(plist map[string]any) string {
	// Check DTPlatformName first
	if p := plistString(plist, "DTPlatformName"); p != "" {
		return p
	}
	// Check LSRequiresIPhoneOS
	if v, ok := plist["LSRequiresIPhoneOS"]; ok {
		if b, ok := v.(bool); ok && b {
			return "iphoneos"
		}
	}
	// Check UIDeviceFamily for iPad-only
	if families := plistIntArray(plist, "UIDeviceFamily"); len(families) == 1 && families[0] == 2 {
		return "ipados"
	}
	return "iphoneos"
}

func resolveDeviceFamilies(plist map[string]any) []string {
	families := plistIntArray(plist, "UIDeviceFamily")
	familyNames := map[int64]string{
		1: "iPhone",
		2: "iPad",
		3: "Apple TV",
		4: "Apple Watch",
		6: "Mac (Catalyst)",
		7: "Apple Vision Pro",
	}
	var result []string
	for _, f := range families {
		if name, ok := familyNames[f]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("Unknown (%d)", f))
		}
	}
	return result
}

func plistIntArray(m map[string]any, key string) []int64 {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var result []int64
	for _, item := range arr {
		switch n := item.(type) {
		case int64:
			result = append(result, n)
		case float64:
			result = append(result, int64(n))
		}
	}
	return result
}

func extractURLSchemes(plist map[string]any) []string {
	urlTypes, ok := plist["CFBundleURLTypes"]
	if !ok {
		return nil
	}
	arr, ok := urlTypes.([]any)
	if !ok {
		return nil
	}
	var schemes []string
	for _, item := range arr {
		dict, ok := item.(map[string]any)
		if !ok {
			continue
		}
		schemeArr, ok := dict["CFBundleURLSchemes"]
		if !ok {
			continue
		}
		sArr, ok := schemeArr.([]any)
		if !ok {
			continue
		}
		for _, s := range sArr {
			if str, ok := s.(string); ok {
				schemes = append(schemes, str)
			}
		}
	}
	return schemes
}

func extractPermissions(plist map[string]any) []PermissionEntry {
	var perms []PermissionEntry
	for key, val := range plist {
		if !strings.HasPrefix(key, "NS") || !strings.HasSuffix(key, "UsageDescription") {
			// Also check NFC
			if key != "NFCReaderUsageDescription" {
				continue
			}
		}
		entry := PermissionEntry{
			Key:         key,
			Description: DescribePermission(key),
		}
		if s, ok := val.(string); ok {
			entry.Usage = s
		}
		perms = append(perms, entry)
	}

	// Also check for dict-based permissions (e.g. NSLocationTemporaryUsageDescriptionDictionary)
	for key, val := range plist {
		if key == "NSLocationTemporaryUsageDescriptionDictionary" {
			if _, ok := val.(map[string]any); ok {
				entry := PermissionEntry{
					Key:         key,
					Description: DescribePermission(key),
					Usage:       "(dictionary-based permission)",
				}
				perms = append(perms, entry)
			}
		}
	}

	return perms
}

// appBundleName extracts the .app directory name from a path like "Payload/MyApp.app/..."
func appBundleName(appPrefix string) string {
	parts := strings.Split(strings.TrimSuffix(appPrefix, "/"), "/")
	if len(parts) >= 2 {
		return strings.TrimSuffix(path.Base(parts[1]), ".app")
	}
	return ""
}
