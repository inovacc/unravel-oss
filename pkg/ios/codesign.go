package ios

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// CodeSignInfo holds code signing metadata extracted from an IPA.
type CodeSignInfo struct {
	IsSigned            bool              `json:"is_signed"`
	HasEntitlements     bool              `json:"has_entitlements"`
	TeamID              string            `json:"team_id,omitempty"`
	SigningAuthority    string            `json:"signing_authority,omitempty"`
	Entitlements        map[string]any    `json:"entitlements,omitempty"`
	ProvisioningProfile *ProvisionProfile `json:"provisioning_profile,omitempty"`
}

// ProvisionProfile represents a parsed embedded.mobileprovision file.
type ProvisionProfile struct {
	Name       string   `json:"name,omitempty"`
	TeamName   string   `json:"team_name,omitempty"`
	AppIDName  string   `json:"app_id_name,omitempty"`
	Expiration string   `json:"expiration,omitempty"`
	Devices    []string `json:"devices,omitempty"`
	IsWildcard bool     `json:"is_wildcard"`
}

// VerifyCodeSign checks code signing of a Mach-O binary within an IPA.
func VerifyCodeSign(ipaPath string) (*CodeSignInfo, error) {
	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, fmt.Errorf("open IPA: %w", err)
	}
	defer func() { _ = zr.Close() }()

	result := &CodeSignInfo{}
	var appPrefix string

	// Find the .app bundle prefix.
	for _, f := range zr.File {
		if appPrefix != "" {
			break
		}
		parts := strings.SplitN(f.Name, "/", 3)
		if len(parts) >= 2 && strings.EqualFold(parts[0], "Payload") && strings.HasSuffix(parts[1], ".app") {
			appPrefix = parts[0] + "/" + parts[1] + "/"
		}
	}

	if appPrefix == "" {
		return nil, fmt.Errorf("no .app bundle found in IPA")
	}

	// Check for code signature.
	for _, f := range zr.File {
		rel := strings.TrimPrefix(f.Name, appPrefix)
		if rel == f.Name {
			continue
		}
		if strings.HasPrefix(rel, "_CodeSignature/") {
			result.IsSigned = true
			break
		}
	}

	// Try to read entitlements from archived-expanded-entitlements.xcent.
	entData, err := readZipFileByName(zr, appPrefix+"archived-expanded-entitlements.xcent")
	if err == nil {
		if ents, parseErr := ParseXMLPlist(entData); parseErr == nil {
			result.HasEntitlements = true
			result.Entitlements = ents
			// Extract team ID from entitlements if present.
			if teamID, ok := ents["com.apple.developer.team-identifier"]; ok {
				if s, ok := teamID.(string); ok {
					result.TeamID = s
				}
			}
		}
	}

	// Parse embedded.mobileprovision (PKCS7 wrapper around XML plist).
	provData, err := readZipFileByName(zr, appPrefix+"embedded.mobileprovision")
	if err == nil {
		profile := parseProvisioningProfile(provData)
		if profile != nil {
			result.ProvisioningProfile = profile
			// Fill team ID from profile if not already set.
			if result.TeamID == "" && profile.TeamName != "" {
				result.TeamID = profile.TeamName
			}
			// Extract entitlements from provisioning profile if not already found.
			if !result.HasEntitlements {
				ents := extractEntitlementsFromProfile(provData)
				if ents != nil {
					result.HasEntitlements = true
					result.Entitlements = ents
					if result.TeamID == "" {
						if teamID, ok := ents["com.apple.developer.team-identifier"]; ok {
							if s, ok := teamID.(string); ok {
								result.TeamID = s
							}
						}
					}
				}
			}
		}
	}

	return result, nil
}

func readZipFileByName(zr *zip.ReadCloser, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer func() { _ = rc.Close() }()
			// SEC: cap the read — a malicious IPA can ship a high-ratio DEFLATE
			// entry that inflates to gigabytes and OOMs the host. Mirrors the
			// bound in readZipFile. Truncation is safe: downstream plist parsers
			// tolerate truncated/malformed input.
			return io.ReadAll(io.LimitReader(rc, maxMetadataBytes))
		}
	}
	return nil, fmt.Errorf("file %q not found", name)
}

// parseProvisioningProfile extracts the XML plist from a PKCS7-wrapped
// mobileprovision file and returns parsed profile data.
func parseProvisioningProfile(data []byte) *ProvisionProfile {
	plist := extractPlistFromProvision(data)
	if plist == nil {
		return nil
	}

	profile := &ProvisionProfile{}

	if v, ok := plist["Name"]; ok {
		if s, ok := v.(string); ok {
			profile.Name = s
		}
	}
	if v, ok := plist["TeamName"]; ok {
		if s, ok := v.(string); ok {
			profile.TeamName = s
		}
	}
	if v, ok := plist["AppIDName"]; ok {
		if s, ok := v.(string); ok {
			profile.AppIDName = s
		}
	}
	if v, ok := plist["ExpirationDate"]; ok {
		if s, ok := v.(string); ok {
			profile.Expiration = s
		}
	}

	// Devices (only present for development profiles).
	if v, ok := plist["ProvisionedDevices"]; ok {
		if arr, ok := v.([]any); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					profile.Devices = append(profile.Devices, s)
				}
			}
		}
	}

	// Check for wildcard app ID.
	if v, ok := plist["Entitlements"]; ok {
		if ents, ok := v.(map[string]any); ok {
			if appID, ok := ents["application-identifier"]; ok {
				if s, ok := appID.(string); ok {
					if strings.HasSuffix(s, ".*") {
						profile.IsWildcard = true
					}
				}
			}
		}
	}

	return profile
}

// extractPlistFromProvision finds and parses the XML plist embedded
// in a PKCS7/CMS signed mobileprovision file.
func extractPlistFromProvision(data []byte) map[string]any {
	// The mobileprovision is a DER-encoded PKCS7 SignedData structure.
	// The XML plist is embedded as the signed content.
	// We find it by searching for the plist markers.
	startMarker := []byte("<?xml")
	endMarker := []byte("</plist>")

	startIdx := bytes.Index(data, startMarker)
	if startIdx < 0 {
		// Try alternate marker.
		startMarker = []byte("<plist")
		startIdx = bytes.Index(data, startMarker)
	}
	if startIdx < 0 {
		return nil
	}

	endIdx := bytes.Index(data[startIdx:], endMarker)
	if endIdx < 0 {
		return nil
	}
	endIdx += startIdx + len(endMarker)

	xmlData := data[startIdx:endIdx]
	plist, err := ParseXMLPlist(xmlData)
	if err != nil {
		return nil
	}
	return plist
}

// extractEntitlementsFromProfile extracts the Entitlements dict from the
// provisioning profile's XML plist.
func extractEntitlementsFromProfile(data []byte) map[string]any {
	plist := extractPlistFromProvision(data)
	if plist == nil {
		return nil
	}
	if v, ok := plist["Entitlements"]; ok {
		if ents, ok := v.(map[string]any); ok {
			return ents
		}
	}
	return nil
}
