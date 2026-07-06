/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"debug/pe"
)

// COMDescriptor is the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR index in the PE
// optional header DataDirectory array. ECMA-335 II.25.3.3.
const COMDescriptor = 14

// IsManagedPE returns true when path is a PE binary with a non-empty
// IMAGE_COR20_HEADER (CLR header) data directory entry.
//
// Returns false on any error or panic (D-20). Mirrors the peImportsQuiet
// pattern from pkg/dissect/analyze_webview2.go.
func IsManagedPE(path string) (managed bool) {
	defer func() {
		if r := recover(); r != nil {
			managed = false
		}
	}()

	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	var dd []pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory[:]
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory[:]
	default:
		return false
	}

	if len(dd) <= COMDescriptor {
		return false
	}

	return dd[COMDescriptor].VirtualAddress != 0 && dd[COMDescriptor].Size != 0
}
