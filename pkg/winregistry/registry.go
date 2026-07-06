/*
Copyright (c) 2026 Security Research
*/
package winregistry

// DumpOptions controls a registry walk.
type DumpOptions struct {
	// Keys is the explicit list of root paths to dump, e.g.
	//   HKLM\SOFTWARE\Microsoft\Windows NT
	//   HKCU\Software\Microsoft\Office\16.0
	// Each must start with a recognised hive abbreviation
	// (HKLM, HKCU, HKCR, HKU, HKCC).
	Keys []string

	// MaxDepth caps recursion into subkeys (default 3, max 20).
	// Protects against runaway recursion through HKLM\SOFTWARE\Classes.
	MaxDepth int

	// MaxValuesPerKey caps how many values to capture under each key
	// (default 256, max 4096). Wide keys like
	// HKLM\SYSTEM\CurrentControlSet\Enum\PCI get truncated and flagged
	// so the dump bounds memory + output size predictably.
	MaxValuesPerKey int

	// DryRun: when true, walks subkeys but skips value reads — used to
	// preview the surface a real dump would touch.
	DryRun bool
}

// KeyDump is a single key's snapshot.
type KeyDump struct {
	Path           string       `json:"path"`            // full hive-prefixed path
	LastWriteTime  string       `json:"last_write_time"` // RFC3339
	Values         []ValueEntry `json:"values"`
	SubKeyCount    int          `json:"subkey_count"`
	ValueTruncated bool         `json:"value_truncated,omitempty"` // hit MaxValuesPerKey
	Err            string       `json:"err,omitempty"`             // open / read error, non-fatal
}

// ValueEntry is a single (name, type, payload) triple.
type ValueEntry struct {
	Name string `json:"name"` // "" = (Default)
	Type string `json:"type"` // REG_SZ / REG_DWORD / REG_BINARY / ...
	// Exactly one of String / DWORD / QWORD / Binary / Strings is set,
	// matching Type. Binary is base64-encoded.
	String  string   `json:"string,omitempty"`
	DWORD   *uint32  `json:"dword,omitempty"`
	QWORD   *uint64  `json:"qword,omitempty"`
	Binary  string   `json:"binary,omitempty"`  // base64
	Strings []string `json:"strings,omitempty"` // REG_MULTI_SZ
}

// Result is the top-level dump envelope.
type Result struct {
	GeneratedAt string     `json:"generated_at"` // RFC3339
	Platform    string     `json:"platform"`     // GOOS
	Keys        []*KeyDump `json:"keys"`
	Errors      []string   `json:"errors,omitempty"`
}

// Sentinel for the cross-platform "this build can't dump" branch.
const ErrNotSupported = registryNotSupported("registry dump not supported on this platform")

type registryNotSupported string

func (e registryNotSupported) Error() string { return string(e) }
