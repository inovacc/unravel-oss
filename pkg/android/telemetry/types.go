/*
Copyright (c) 2026 Security Research
*/

package telemetry

type SDKCategory string

const (
	CategoryAnalytics   SDKCategory = "analytics"
	CategoryAds         SDKCategory = "ads"
	CategoryAttribution SDKCategory = "attribution"
	CategoryCrash       SDKCategory = "crash"
	CategoryPush        SDKCategory = "push"
	CategoryStealth     SDKCategory = "stealth"
)

type ScanResult struct {
	SDKs            []SDKInfo        `json:"sdks"`
	StealthFeatures []StealthFeature `json:"stealth_features"`
	TotalSDKs       int              `json:"total_sdks"`
	HasAnalytics    bool             `json:"has_analytics"`
	HasAds          bool             `json:"has_ads"`
	HasStealth      bool             `json:"has_stealth"`
}

type SDKInfo struct {
	Name       string      `json:"name"`
	Category   SDKCategory `json:"category"`
	Package    string      `json:"package"`
	Version    string      `json:"version,omitempty"`
	Confidence float64     `json:"confidence"`
	Evidence   []string    `json:"evidence"`
}

type StealthFeature struct {
	Type        string `json:"type"`
	Component   string `json:"component"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}
