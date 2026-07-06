/*
Copyright (c) 2026 Security Research
*/
package schema

import "time"

// ApplicationSchema is a taxonomic blueprint of an application's architecture,
// communication patterns, and security posture. It is designed to be machine-readable
// so another AI can replicate the application in a different framework.
type ApplicationSchema struct {
	// Metadata
	AppName      string    `json:"app_name"`
	FileName     string    `json:"file_name,omitempty"`
	Framework    string    `json:"framework"` // "electron", "tauri", "android", "pwa", etc.
	Version      string    `json:"version,omitempty"`
	AnalysisDate time.Time `json:"analysis_date"`
	SourcePath   string    `json:"source_path"`

	// Communication Layer
	Communication CommunicationSchema `json:"communication"`

	// Authentication & Authorization
	Auth AuthSchema `json:"auth"`

	// Data Storage & Persistence
	Storage StorageSchema `json:"storage"`

	// Inter-Process Communication
	IPC IPCSchema `json:"ipc"`

	// Stealth & Anti-Analysis
	Stealth StealthSchema `json:"stealth"`

	// Telemetry & Analytics
	Telemetry TelemetrySchema `json:"telemetry"`

	// Security Configuration
	Security SecuritySchema `json:"security"`

	// AI Metadata
	AIPrompt      string  `json:"ai_prompt,omitempty"`
	AIRawAnalysis string  `json:"ai_raw_analysis,omitempty"`
	Confidence    float64 `json:"confidence"` // 0.0–1.0 overall confidence
}

// CommunicationSchema describes all network communication patterns.
type CommunicationSchema struct {
	Endpoints          []Endpoint `json:"endpoints"`
	Protocols          []string   `json:"protocols"`    // "https", "wss", "grpc", etc.
	DataFormats        []string   `json:"data_formats"` // "json", "protobuf", "msgpack"
	CertificatePinning bool       `json:"certificate_pinning"`
	CleartextAllowed   bool       `json:"cleartext_allowed"`
}

// Endpoint describes a single network endpoint.
type Endpoint struct {
	URL        string   `json:"url"`
	Methods    []string `json:"methods,omitempty"`     // HTTP methods
	Purpose    string   `json:"purpose"`               // "api", "telemetry", "auth", "cdn", "websocket"
	AuthType   string   `json:"auth_type,omitempty"`   // "bearer", "api_key", "none"
	DataFormat string   `json:"data_format,omitempty"` // "json", "protobuf"
}

// AuthSchema describes authentication mechanisms.
type AuthSchema struct {
	Methods      []AuthMethod `json:"methods"`
	TokenStorage string       `json:"token_storage,omitempty"` // "localStorage", "keychain", "memory"
	MFA          bool         `json:"mfa"`
}

// AuthMethod describes a single authentication method.
type AuthMethod struct {
	Type           string `json:"type"` // "bearer", "oauth2", "api_key", "basic", "mtls"
	HeaderName     string `json:"header_name,omitempty"`
	Implementation string `json:"implementation"` // "custom", "firebase", "auth0", etc.
}

// StorageSchema describes data persistence.
type StorageSchema struct {
	Databases     []Database     `json:"databases"`
	LocalStorage  []StorageEntry `json:"local_storage"`
	Encrypted     bool           `json:"encrypted"`
	KeyManagement string         `json:"key_management,omitempty"` // "dpapi", "keychain", "tpm", "plaintext"
}

// Database describes a database storage mechanism.
type Database struct {
	Type      string   `json:"type"` // "sqlite", "leveldb", "realm", "indexeddb"
	Purpose   string   `json:"purpose"`
	Tables    []string `json:"tables,omitempty"`
	Encrypted bool     `json:"encrypted"`
}

// StorageEntry describes a non-database storage mechanism.
type StorageEntry struct {
	Type          string `json:"type"` // "file", "registry", "prefs", "localstorage"
	Location      string `json:"location"`
	SensitiveData bool   `json:"sensitive_data"`
}

// IPCSchema describes inter-process communication.
type IPCSchema struct {
	Channels  []IPCChannel `json:"channels"`
	Protocols []string     `json:"protocols"` // "electron-ipc", "tauri-invoke", "intent", "binder"
}

// IPCChannel describes a single IPC channel.
type IPCChannel struct {
	Name         string   `json:"name"`
	Direction    string   `json:"direction"` // "bidirectional", "renderer-to-main", "main-to-renderer"
	MessageTypes []string `json:"message_types,omitempty"`
	Privileged   bool     `json:"privileged"` // requires elevated access
}

// StealthSchema describes anti-analysis and stealth features.
type StealthSchema struct {
	ScreenCaptureBlock  bool     `json:"screen_capture_block"`
	ScreenShareHide     bool     `json:"screen_share_hide"`
	ProcessHiding       bool     `json:"process_hiding"`
	AntiDebugging       []string `json:"anti_debugging"`
	AntiInstrumentation []string `json:"anti_instrumentation"`       // frida detection, etc.
	CodeObfuscation     string   `json:"code_obfuscation,omitempty"` // "proguard", "r8", "garble", "webpack", "none"
}

// TelemetrySchema describes analytics and tracking.
type TelemetrySchema struct {
	Services        []TelemetryService `json:"services"`
	EventTracking   bool               `json:"event_tracking"`
	CrashReporting  bool               `json:"crash_reporting"`
	ConsentRequired bool               `json:"consent_required"`
}

// TelemetryService describes a single telemetry/analytics service.
type TelemetryService struct {
	Name      string   `json:"name"`
	Endpoint  string   `json:"endpoint,omitempty"`
	DataTypes []string `json:"data_types,omitempty"` // "session", "crash", "user_id", "events"
}

// SecuritySchema describes security configuration.
type SecuritySchema struct {
	Debuggable           bool     `json:"debuggable"`
	SandboxEnabled       bool     `json:"sandbox_enabled"`
	ContentProtection    bool     `json:"content_protection"`
	CSP                  string   `json:"csp,omitempty"`
	Permissions          []string `json:"permissions"`
	DangerousPermissions []string `json:"dangerous_permissions"`
	RiskScore            int      `json:"risk_score"` // 0-100
}
