/*
Copyright (c) 2026 Security Research
*/
package dex

// DexHeader represents the 0x70-byte DEX file header.
type DexHeader struct {
	Magic         [8]byte  `json:"magic"`
	Checksum      uint32   `json:"checksum"`
	Signature     [20]byte `json:"-"`
	FileSize      uint32   `json:"file_size"`
	HeaderSize    uint32   `json:"header_size"`
	EndianTag     uint32   `json:"endian_tag"`
	LinkSize      uint32   `json:"-"`
	LinkOff       uint32   `json:"-"`
	MapOff        uint32   `json:"-"`
	StringIDsSize uint32   `json:"string_ids_size"`
	StringIDsOff  uint32   `json:"-"`
	TypeIDsSize   uint32   `json:"type_ids_size"`
	TypeIDsOff    uint32   `json:"-"`
	ProtoIDsSize  uint32   `json:"proto_ids_size"`
	ProtoIDsOff   uint32   `json:"-"`
	FieldIDsSize  uint32   `json:"field_ids_size"`
	FieldIDsOff   uint32   `json:"-"`
	MethodIDsSize uint32   `json:"method_ids_size"`
	MethodIDsOff  uint32   `json:"-"`
	ClassDefsSize uint32   `json:"class_defs_size"`
	ClassDefsOff  uint32   `json:"-"`
	DataSize      uint32   `json:"-"`
	DataOff       uint32   `json:"-"`
}

// ClassDef represents a class definition in the DEX file.
type ClassDef struct {
	TypeIdx         uint32 `json:"-"`
	AccessFlags     uint32 `json:"access_flags"`
	SuperclassIdx   uint32 `json:"-"`
	InterfacesOff   uint32 `json:"-"`
	SourceFileIdx   uint32 `json:"-"`
	AnnotationsOff  uint32 `json:"-"`
	ClassDataOff    uint32 `json:"-"`
	StaticValuesOff uint32 `json:"-"`
	ClassName       string `json:"class_name"`
	Superclass      string `json:"superclass,omitempty"`
	SourceFile      string `json:"source_file,omitempty"`
}

// MethodRef represents a method reference.
type MethodRef struct {
	ClassIdx   uint16 `json:"-"`
	ProtoIdx   uint16 `json:"-"`
	NameIdx    uint32 `json:"-"`
	ClassName  string `json:"class_name"`
	Name       string `json:"name"`
	Descriptor string `json:"descriptor,omitempty"` // JVM method descriptor e.g. "(Landroid/content/Context;)V"
}

// FieldRef represents a field reference.
type FieldRef struct {
	ClassIdx  uint16 `json:"-"`
	TypeIdx   uint16 `json:"-"`
	NameIdx   uint32 `json:"-"`
	ClassName string `json:"class_name"`
	Name      string `json:"name"`
	TypeName  string `json:"type_name"`
}

// DexFile holds the parsed content of a single DEX file.
type DexFile struct {
	Name    string      `json:"name"`
	Header  DexHeader   `json:"header"`
	Version string      `json:"version"`
	Strings []string    `json:"strings,omitempty"`
	Types   []string    `json:"types,omitempty"`
	Classes []ClassDef  `json:"classes,omitempty"`
	Methods []MethodRef `json:"methods,omitempty"`
	Fields  []FieldRef  `json:"fields,omitempty"`
}

// HighEntropyString is a string with high Shannon entropy.
type HighEntropyString struct {
	Value   string  `json:"value"`
	Entropy float64 `json:"entropy"`
	Source  string  `json:"source"`
}

// RiskFinding represents a dangerous API usage found in DEX.
type RiskFinding struct {
	Category    string `json:"category"`
	API         string `json:"api"`
	ClassName   string `json:"class_name,omitempty"`
	MethodName  string `json:"method_name,omitempty"`
	Severity    string `json:"severity"` // "high", "medium", "low"
	Description string `json:"description"`
}

// ParseResult holds the aggregated results from parsing all DEX files.
type ParseResult struct {
	DexFiles           []DexFile           `json:"dex_files"`
	TotalClasses       int                 `json:"total_classes"`
	TotalMethods       int                 `json:"total_methods"`
	TotalFields        int                 `json:"total_fields"`
	TotalStrings       int                 `json:"total_strings"`
	MultiDex           bool                `json:"multi_dex"`
	HighEntropyStrings []HighEntropyString `json:"high_entropy_strings,omitempty"`
	RiskFindings       []RiskFinding       `json:"risk_findings,omitempty"`
	ParseErrors        []string            `json:"parse_errors,omitempty"`
}

// StripHeavyTables clears the per-DEX string/type/class/method/field tables,
// which dominate the serialized output on real apps (e.g. ~184 MB / 85k classes)
// and bury the summary + risk findings the command exists to surface. The
// top-level Totals, HighEntropyStrings, RiskFindings, and ParseErrors — plus
// each DexFile's name/header/version — are preserved. Callers that need the full
// tables (e.g. `dex --json --full`) simply skip this.
func (r *ParseResult) StripHeavyTables() {
	for i := range r.DexFiles {
		r.DexFiles[i].Strings = nil
		r.DexFiles[i].Types = nil
		r.DexFiles[i].Classes = nil
		r.DexFiles[i].Methods = nil
		r.DexFiles[i].Fields = nil
	}
}
