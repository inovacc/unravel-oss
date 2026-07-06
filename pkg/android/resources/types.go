/*
Copyright (c) 2026 Security Research
*/

package resources

type AssetCategory string

const (
	AssetWebView     AssetCategory = "webview"
	AssetDatabase    AssetCategory = "database"
	AssetConfig      AssetCategory = "config"
	AssetCertificate AssetCategory = "certificate"
	AssetNative      AssetCategory = "native"
	AssetMedia       AssetCategory = "media"
	AssetFont        AssetCategory = "font"
	AssetData        AssetCategory = "data"
)

type ScanResult struct {
	StringPool   *StringPoolInfo       `json:"string_pool,omitempty"`
	PackageName  string                `json:"package_name,omitempty"`
	TypeNames    []string              `json:"type_names,omitempty"`
	Assets       []AssetInfo           `json:"assets"`
	TotalAssets  int                   `json:"total_assets"`
	TotalSize    int64                 `json:"total_size"`
	HasWebView   bool                  `json:"has_webview"`
	HasDatabases bool                  `json:"has_databases"`
	Categories   map[AssetCategory]int `json:"categories"`
}

type StringPoolInfo struct {
	TotalStrings  int      `json:"total_strings"`
	UTF8          bool     `json:"utf8"`
	SampleStrings []string `json:"sample_strings,omitempty"` // first 50 non-empty strings
}

type AssetInfo struct {
	Path      string        `json:"path"`
	Size      int64         `json:"size"`
	Category  AssetCategory `json:"category"`
	IsSQLite  bool          `json:"is_sqlite,omitempty"`
	IsWebView bool          `json:"is_webview,omitempty"`
}
