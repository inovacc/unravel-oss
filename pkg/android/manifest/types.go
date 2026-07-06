/*
Copyright (c) 2026 Security Research
*/
package manifest

// Manifest represents a parsed AndroidManifest.xml.
type Manifest struct {
	Package     string        `json:"package"`
	VersionCode int64         `json:"version_code"`
	VersionName string        `json:"version_name"`
	MinSDK      int           `json:"min_sdk"`
	TargetSDK   int           `json:"target_sdk"`
	Permissions []Permission  `json:"permissions"`
	Components  []Component   `json:"components"`
	Security    SecurityFlags `json:"security_flags"`
	Features    []string      `json:"features,omitempty"`
}

// Permission represents a single uses-permission declaration.
type Permission struct {
	Name      string `json:"name"`
	RiskLevel string `json:"risk_level"` // "dangerous", "normal", "signature", "unknown"
}

// ComponentType identifies an Android component kind.
type ComponentType string

const (
	ComponentActivity ComponentType = "activity"
	ComponentService  ComponentType = "service"
	ComponentReceiver ComponentType = "receiver"
	ComponentProvider ComponentType = "provider"
)

// Component represents an Android manifest component (activity, service, etc.).
type Component struct {
	Name          string         `json:"name"`
	Type          ComponentType  `json:"type"`
	Exported      *bool          `json:"exported,omitempty"`
	Permission    string         `json:"permission,omitempty"`
	IntentFilters []IntentFilter `json:"intent_filters,omitempty"`
}

// IntentFilter represents an intent-filter declaration.
type IntentFilter struct {
	Actions    []string           `json:"actions,omitempty"`
	Categories []string           `json:"categories,omitempty"`
	Data       []IntentFilterData `json:"data,omitempty"`
}

// IntentFilterData represents a data element in an intent-filter.
type IntentFilterData struct {
	Scheme   string `json:"scheme,omitempty"`
	Host     string `json:"host,omitempty"`
	Path     string `json:"path,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
}

// SecurityFlags holds security-relevant application attributes.
type SecurityFlags struct {
	Debuggable            bool `json:"debuggable"`
	AllowBackup           bool `json:"allow_backup"`
	UsesCleartextTraffic  bool `json:"uses_cleartext_traffic"`
	NetworkSecurityConfig bool `json:"network_security_config"`
}
