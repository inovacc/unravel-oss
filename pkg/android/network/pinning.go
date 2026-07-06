/*
Copyright (c) 2026 Security Research
*/

package network

import (
	"slices"
	"strings"
)

// DetectPinning detects certificate pinning from multiple sources
func DetectPinning(apkPath string, dexStrings []string) *CertPinResult {
	result := &CertPinResult{
		HasPinning:    false,
		Sources:       []string{},
		PinnedDomains: []PinnedDomain{},
	}

	// Source 1: Network security config
	configData, err := FindNetworkSecConfig(apkPath)
	if err == nil && configData != nil {
		config, err := ParseNetworkSecurityConfig(configData)
		if err == nil && config != nil {
			for _, dc := range config.DomainConfigs {
				if dc.PinSet != nil && len(dc.PinSet.Pins) > 0 {
					result.HasPinning = true
					if !contains(result.Sources, "netsec_config") {
						result.Sources = append(result.Sources, "netsec_config")
					}

					// Add pinned domain
					for _, domain := range dc.Domains {
						result.PinnedDomains = append(result.PinnedDomains, PinnedDomain{
							Domain: domain.Domain,
							Pins:   dc.PinSet.Pins,
							Source: "netsec_config",
						})
					}
				}
			}
		}
	}

	// Source 2: OkHttp patterns in DEX strings
	okhttpPatterns := []string{
		"CertificatePinner",
		"sha256/",
		"pin-sha256",
		"okhttp3/CertificatePinner",
	}

	for _, str := range dexStrings {
		for _, pattern := range okhttpPatterns {
			if strings.Contains(str, pattern) {
				result.HasPinning = true
				if !contains(result.Sources, "okhttp") {
					result.Sources = append(result.Sources, "okhttp")
				}
				break
			}
		}
	}

	// Source 3: TrustManager patterns in DEX strings
	trustManagerPatterns := []string{
		"TrustManagerFactory",
		"X509TrustManager",
	}

	for _, str := range dexStrings {
		for _, pattern := range trustManagerPatterns {
			if strings.Contains(str, pattern) {
				result.HasPinning = true
				if !contains(result.Sources, "trustmanager") {
					result.Sources = append(result.Sources, "trustmanager")
				}
				break
			}
		}
	}

	return result
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	return slices.Contains(slice, value)
}
