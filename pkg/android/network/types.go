/*
Copyright (c) 2026 Security Research
*/

package network

// DomainCategory classifies a domain.
type DomainCategory string

const (
	CategoryAPI       DomainCategory = "api"
	CategoryCDN       DomainCategory = "cdn"
	CategoryAnalytics DomainCategory = "analytics"
	CategoryAds       DomainCategory = "ads"
	CategorySocial    DomainCategory = "social"
	CategoryCloud     DomainCategory = "cloud"
	CategoryInternal  DomainCategory = "internal"
	CategoryUnknown   DomainCategory = "unknown"
)

type ScanResult struct {
	Endpoints        []EndpointInfo    `json:"endpoints"`
	Domains          []DomainInfo      `json:"domains"`
	CertPinning      *CertPinResult    `json:"cert_pinning,omitempty"`
	NetworkSecConfig *NetworkSecConfig `json:"network_security_config,omitempty"`
	TotalURLs        int               `json:"total_urls"`
	TotalDomains     int               `json:"total_domains"`
	CleartextAllowed bool              `json:"cleartext_allowed"`
}

type EndpointInfo struct {
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Source string `json:"source"` // "dex_strings", "assets", "resources"
}

type DomainInfo struct {
	Domain   string         `json:"domain"`
	Category DomainCategory `json:"category"`
	Count    int            `json:"count"`
	Schemes  []string       `json:"schemes"`
}

type CertPinResult struct {
	HasPinning    bool           `json:"has_pinning"`
	Sources       []string       `json:"sources"` // "netsec_config", "okhttp", "trustmanager"
	PinnedDomains []PinnedDomain `json:"pinned_domains,omitempty"`
}

type PinnedDomain struct {
	Domain string   `json:"domain"`
	Pins   []string `json:"pins"`
	Source string   `json:"source"`
}

type NetworkSecConfig struct {
	Present       bool           `json:"present"`
	DomainConfigs []DomainConfig `json:"domain_configs,omitempty"`
	BaseConfig    *BaseConfig    `json:"base_config,omitempty"`
}

type BaseConfig struct {
	CleartextPermitted *bool    `json:"cleartext_permitted,omitempty"`
	TrustAnchors       []string `json:"trust_anchors,omitempty"`
}

type DomainConfig struct {
	Domains            []DomainEntry `json:"domains"`
	CleartextPermitted *bool         `json:"cleartext_permitted,omitempty"`
	PinSet             *PinSet       `json:"pin_set,omitempty"`
	TrustAnchors       []string      `json:"trust_anchors,omitempty"`
}

type DomainEntry struct {
	Domain            string `json:"domain"`
	IncludeSubdomains bool   `json:"include_subdomains"`
}

type PinSet struct {
	Expiration string   `json:"expiration,omitempty"`
	Pins       []string `json:"pins"`
}
