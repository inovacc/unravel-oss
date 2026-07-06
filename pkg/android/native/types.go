/*
Copyright (c) 2026 Security Research
*/
package native

// Finding represents a security-relevant finding in a native library.
type Finding struct {
	Library     string `json:"library"`
	ABI         string `json:"abi"`
	Category    string `json:"category"` // "anti-debug", "root-detection", "emulator-detection", "packer", "crypto"
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"` // "high", "medium", "low", "info"
	Description string `json:"description"`
}

// JNIExport represents a JNI native method export.
type JNIExport struct {
	Library  string `json:"library"`
	ABI      string `json:"abi"`
	Symbol   string `json:"symbol"`
	JavaName string `json:"java_name"` // decoded Java class.method
}

// LibraryInfo holds metadata about a single native library.
type LibraryInfo struct {
	Name       string      `json:"name"`
	ABI        string      `json:"abi"`
	Size       int64       `json:"size"`
	Machine    string      `json:"machine"` // e.g. "ARM", "AARCH64", "386", "AMD64"
	Linked     []string    `json:"linked,omitempty"`
	JNIExports []JNIExport `json:"jni_exports,omitempty"`
	Findings   []Finding   `json:"findings,omitempty"`
}

// ABISummary summarizes libraries per ABI.
type ABISummary struct {
	ABI       string `json:"abi"`
	Count     int    `json:"count"`
	TotalSize int64  `json:"total_size"`
}

// ScanResult holds all native library analysis results.
type ScanResult struct {
	Libraries      []LibraryInfo `json:"libraries"`
	ABIs           []ABISummary  `json:"abis"`
	TotalLibs      int           `json:"total_libs"`
	JNIExports     []JNIExport   `json:"jni_exports,omitempty"`
	Findings       []Finding     `json:"findings,omitempty"`
	PackerDetected string        `json:"packer_detected,omitempty"`
}
