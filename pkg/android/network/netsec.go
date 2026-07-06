/*
Copyright (c) 2026 Security Research
*/

package network

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// xmlNetworkSecurityConfig represents the XML structure of network_security_config.xml
type xmlNetworkSecurityConfig struct {
	XMLName       xml.Name          `xml:"network-security-config"`
	BaseConfig    *xmlBaseConfig    `xml:"base-config"`
	DomainConfigs []xmlDomainConfig `xml:"domain-config"`
}

type xmlBaseConfig struct {
	CleartextPermitted string           `xml:"cleartextTrafficPermitted,attr"`
	TrustAnchors       *xmlTrustAnchors `xml:"trust-anchors"`
}

type xmlDomainConfig struct {
	CleartextPermitted string           `xml:"cleartextTrafficPermitted,attr"`
	Domains            []xmlDomain      `xml:"domain"`
	PinSet             *xmlPinSet       `xml:"pin-set"`
	TrustAnchors       *xmlTrustAnchors `xml:"trust-anchors"`
}

type xmlDomain struct {
	Domain            string `xml:",chardata"`
	IncludeSubdomains string `xml:"includeSubdomains,attr"`
}

type xmlPinSet struct {
	Expiration string   `xml:"expiration,attr"`
	Pins       []xmlPin `xml:"pin"`
}

type xmlPin struct {
	Digest string `xml:"digest,attr"`
	Value  string `xml:",chardata"`
}

type xmlTrustAnchors struct {
	Certificates []xmlCertificate `xml:"certificates"`
}

type xmlCertificate struct {
	Src string `xml:"src,attr"`
}

// FindNetworkSecConfig opens an APK and extracts network_security_config.xml
func FindNetworkSecConfig(apkPath string) ([]byte, error) {
	reader, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open APK: %w", err)
	}
	defer func() { _ = reader.Close() }()

	for _, file := range reader.File {
		if file.Name == "res/xml/network_security_config.xml" {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open network security config: %w", err)
			}
			defer func() { _ = rc.Close() }()

			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("failed to read network security config: %w", err)
			}

			return data, nil
		}
	}

	return nil, nil // Not found is not an error
}

// ParseNetworkSecurityConfig parses network_security_config.xml data
func ParseNetworkSecurityConfig(data []byte) (*NetworkSecConfig, error) {
	var xmlConfig xmlNetworkSecurityConfig

	if err := xml.Unmarshal(data, &xmlConfig); err != nil {
		// Binary XML (AXML) cannot be parsed with standard XML parser
		// Return nil without error to indicate unsupported format
		return nil, nil
	}

	config := &NetworkSecConfig{
		Present: true,
	}

	// Parse base config
	if xmlConfig.BaseConfig != nil {
		config.BaseConfig = &BaseConfig{}

		if xmlConfig.BaseConfig.CleartextPermitted != "" {
			permitted := strings.ToLower(xmlConfig.BaseConfig.CleartextPermitted) == "true"
			config.BaseConfig.CleartextPermitted = &permitted
		}

		if xmlConfig.BaseConfig.TrustAnchors != nil {
			for _, cert := range xmlConfig.BaseConfig.TrustAnchors.Certificates {
				config.BaseConfig.TrustAnchors = append(config.BaseConfig.TrustAnchors, cert.Src)
			}
		}
	}

	// Parse domain configs
	for _, dc := range xmlConfig.DomainConfigs {
		domainConfig := DomainConfig{}

		// Parse domains
		for _, d := range dc.Domains {
			includeSubdomains := strings.ToLower(d.IncludeSubdomains) == "true"
			domainConfig.Domains = append(domainConfig.Domains, DomainEntry{
				Domain:            strings.TrimSpace(d.Domain),
				IncludeSubdomains: includeSubdomains,
			})
		}

		// Parse cleartext permission
		if dc.CleartextPermitted != "" {
			permitted := strings.ToLower(dc.CleartextPermitted) == "true"
			domainConfig.CleartextPermitted = &permitted
		}

		// Parse pin set
		if dc.PinSet != nil {
			domainConfig.PinSet = &PinSet{
				Expiration: dc.PinSet.Expiration,
			}
			for _, pin := range dc.PinSet.Pins {
				domainConfig.PinSet.Pins = append(domainConfig.PinSet.Pins,
					fmt.Sprintf("%s:%s", pin.Digest, strings.TrimSpace(pin.Value)))
			}
		}

		// Parse trust anchors
		if dc.TrustAnchors != nil {
			for _, cert := range dc.TrustAnchors.Certificates {
				domainConfig.TrustAnchors = append(domainConfig.TrustAnchors, cert.Src)
			}
		}

		config.DomainConfigs = append(config.DomainConfigs, domainConfig)
	}

	return config, nil
}
