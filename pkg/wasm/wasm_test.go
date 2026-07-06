/*
Copyright (c) 2026 Security Research
*/
package wasm

import (
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalWASM builds the smallest valid WASM module: magic + version, no sections.
func buildMinimalWASM() []byte {
	return []byte{
		0x00, 0x61, 0x73, 0x6D, // magic: \x00asm
		0x01, 0x00, 0x00, 0x00, // version: 1
	}
}

// buildWASMWithExport builds a WASM module with a Type section, Function section,
// Export section, and Code section that exports a function "add" (i32, i32) -> i32.
func buildWASMWithExport() []byte {
	module := []byte{
		0x00, 0x61, 0x73, 0x6D, // magic
		0x01, 0x00, 0x00, 0x00, // version 1
	}

	// Type section: 1 func type (i32, i32) -> (i32)
	typeSection := []byte{
		0x01,       // section ID: Type
		0x07,       // section size: 7 bytes
		0x01,       // count: 1 type
		0x60,       // func type marker
		0x02,       // 2 params
		0x7F, 0x7F, // i32, i32
		0x01, // 1 result
		0x7F, // i32
	}
	module = append(module, typeSection...)

	// Function section: 1 function referencing type 0
	funcSection := []byte{
		0x03, // section ID: Function
		0x02, // section size: 2 bytes
		0x01, // count: 1 function
		0x00, // type index 0
	}
	module = append(module, funcSection...)

	// Export section: export function 0 as "add"
	exportSection := []byte{
		0x07,             // section ID: Export
		0x07,             // section size: 7 bytes
		0x01,             // count: 1 export
		0x03,             // name length: 3
		0x61, 0x64, 0x64, // "add"
		0x00, // kind: func
		0x00, // index: 0
	}
	module = append(module, exportSection...)

	// Code section: 1 function body (local.get 0, local.get 1, i32.add, end)
	codeSection := []byte{
		0x0A,       // section ID: Code
		0x09,       // section size: 9 bytes
		0x01,       // count: 1 body
		0x07,       // body size: 7 bytes
		0x00,       // local count: 0
		0x20, 0x00, // local.get 0
		0x20, 0x01, // local.get 1
		0x6A, // i32.add
		0x0B, // end
	}
	module = append(module, codeSection...)

	return module
}

// buildWASMWithImport builds a WASM module that imports a function from "env".
func buildWASMWithImport() []byte {
	module := []byte{
		0x00, 0x61, 0x73, 0x6D, // magic
		0x01, 0x00, 0x00, 0x00, // version 1
	}

	// Type section: 1 func type (i32) -> ()
	typeSection := []byte{
		0x01, // section ID: Type
		0x05, // section size
		0x01, // count: 1 type
		0x60, // func type marker
		0x01, // 1 param
		0x7F, // i32
		0x00, // 0 results
	}
	module = append(module, typeSection...)

	// Import section: import "env"."log" as func type 0
	importSection := []byte{
		0x02,             // section ID: Import
		0x0B,             // section size: 11 bytes
		0x01,             // count: 1 import
		0x03,             // module name length: 3
		0x65, 0x6E, 0x76, // "env"
		0x03,             // field name length: 3
		0x6C, 0x6F, 0x67, // "log"
		0x00, // kind: func
		0x00, // type index: 0
	}
	module = append(module, importSection...)

	return module
}

// buildWASMWithMemoryAndCustom builds a WASM module with a memory section and custom section.
func buildWASMWithMemoryAndCustom() []byte {
	module := []byte{
		0x00, 0x61, 0x73, 0x6D, // magic
		0x01, 0x00, 0x00, 0x00, // version 1
	}

	// Custom section named "producers"
	customName := []byte("producers")
	customPayload := append([]byte{byte(len(customName))}, customName...)
	customPayload = append(customPayload, 0x00) // some dummy data

	customSection := []byte{0x00} // section ID: Custom
	customSection = append(customSection, byte(len(customPayload)))
	customSection = append(customSection, customPayload...)
	module = append(module, customSection...)

	// Memory section: 1 memory with min=1 page
	memSection := []byte{
		0x05, // section ID: Memory
		0x03, // section size: 3 bytes
		0x01, // count: 1 memory
		0x00, // flags: no max
		0x01, // min: 1 page
	}
	module = append(module, memSection...)

	return module
}

func TestParseMinimal(t *testing.T) {
	data := buildMinimalWASM()
	info, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("ParseBytes minimal: %v", err)
	}

	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if len(info.Sections) != 0 {
		t.Errorf("Sections = %d, want 0", len(info.Sections))
	}
	if info.Functions != 0 {
		t.Errorf("Functions = %d, want 0", info.Functions)
	}
}

func TestParseWithExport(t *testing.T) {
	data := buildWASMWithExport()
	info, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("ParseBytes with export: %v", err)
	}

	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if len(info.Sections) != 4 {
		t.Errorf("Sections = %d, want 4", len(info.Sections))
	}
	if info.Functions != 1 {
		t.Errorf("Functions = %d, want 1", info.Functions)
	}
	if len(info.Exports) != 1 {
		t.Fatalf("Exports = %d, want 1", len(info.Exports))
	}
	if info.Exports[0].Name != "add" {
		t.Errorf("Export name = %q, want %q", info.Exports[0].Name, "add")
	}
	if info.Exports[0].Kind != "func" {
		t.Errorf("Export kind = %q, want %q", info.Exports[0].Kind, "func")
	}
	if info.CodeSize == 0 {
		t.Error("CodeSize = 0, want > 0")
	}
}

func TestParseWithImport(t *testing.T) {
	data := buildWASMWithImport()
	info, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("ParseBytes with import: %v", err)
	}

	if len(info.Imports) != 1 {
		t.Fatalf("Imports = %d, want 1", len(info.Imports))
	}
	if info.Imports[0].Module != "env" {
		t.Errorf("Import module = %q, want %q", info.Imports[0].Module, "env")
	}
	if info.Imports[0].Field != "log" {
		t.Errorf("Import field = %q, want %q", info.Imports[0].Field, "log")
	}
	if info.Imports[0].Kind != "func" {
		t.Errorf("Import kind = %q, want %q", info.Imports[0].Kind, "func")
	}
	// Imported function should count toward Functions
	if info.Functions != 1 {
		t.Errorf("Functions = %d, want 1 (imported)", info.Functions)
	}
}

func TestParseWithMemoryAndCustom(t *testing.T) {
	data := buildWASMWithMemoryAndCustom()
	info, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("ParseBytes with memory+custom: %v", err)
	}

	if info.Memories != 1 {
		t.Errorf("Memories = %d, want 1", info.Memories)
	}
	if len(info.CustomNames) != 1 {
		t.Fatalf("CustomNames = %d, want 1", len(info.CustomNames))
	}
	if info.CustomNames[0] != "producers" {
		t.Errorf("CustomNames[0] = %q, want %q", info.CustomNames[0], "producers")
	}
}

func TestParseFile(t *testing.T) {
	// Write a minimal WASM to a temp file and parse it
	dir := t.TempDir()
	path := filepath.Join(dir, "test.wasm")
	if err := os.WriteFile(path, buildWASMWithExport(), 0o644); err != nil {
		t.Fatalf("write temp wasm: %v", err)
	}

	info, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse file: %v", err)
	}
	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
	if len(info.Exports) != 1 {
		t.Errorf("Exports = %d, want 1", len(info.Exports))
	}
}

func TestParseInvalidMagic(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	_, err := ParseBytes(data)
	if err == nil {
		t.Fatal("expected error for invalid magic, got nil")
	}
}

func TestParseTruncated(t *testing.T) {
	// Only magic, no version
	data := []byte{0x00, 0x61, 0x73, 0x6D}
	_, err := ParseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated data, got nil")
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := ParseBytes(nil)
	if err == nil {
		t.Fatal("expected error for empty data, got nil")
	}
}

func TestIsWASM(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		want   bool
	}{
		{"valid", []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00}, true},
		{"magic only", []byte{0x00, 0x61, 0x73, 0x6D}, true},
		{"invalid", []byte{0x00, 0x00, 0x00, 0x00}, false},
		{"too short", []byte{0x00, 0x61}, false},
		{"empty", nil, false},
		{"elf", []byte{0x7F, 0x45, 0x4C, 0x46}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsWASM(tt.header)
			if got != tt.want {
				t.Errorf("IsWASM(%v) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

func TestSectionNames(t *testing.T) {
	tests := []struct {
		id   uint8
		want string
	}{
		{0, "Custom"},
		{1, "Type"},
		{2, "Import"},
		{3, "Function"},
		{4, "Table"},
		{5, "Memory"},
		{6, "Global"},
		{7, "Export"},
		{8, "Start"},
		{9, "Element"},
		{10, "Code"},
		{11, "Data"},
		{12, "DataCount"},
		{255, "Unknown(255)"},
	}

	for _, tt := range tests {
		got := sectionName(tt.id)
		if got != tt.want {
			t.Errorf("sectionName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestLEB128Overflow(t *testing.T) {
	// 5 bytes with continuation bits set -> overflow
	data := []byte{0x80, 0x80, 0x80, 0x80, 0x80}
	r := &bytesReader{data: data}
	_, err := readLEB128u32(r)
	if err == nil {
		t.Fatal("expected leb128 overflow error, got nil")
	}
}
