// gen_synthetic_pe emits a minimal valid PE32+ DLL with an import directory
// referencing Crypt32.dll and Bcrypt.dll. Used to generate the cross-platform
// fixture pkg/knowledge/scorecard/testdata/synthetic_pe.bin (B3 of P64 SCRG-04).
//
// The output is parseable by Go's debug/pe.File.ImportedLibraries() on
// Linux/macOS/Windows with NO platform-specific Win32 calls — proving that
// the SCRG-04 PE walker is cross-platform.
//
// Run (from repo root):
//
//	go run ./internal/devtools/gen_synthetic_pe > pkg/knowledge/scorecard/testdata/synthetic_pe.bin
//
// File layout (PE32+):
//
//	[0x000] DOS header (60B) + e_lfanew=0x40 + DOS stub (4B padding)
//	[0x040] PE signature "PE\0\0"
//	[0x044] COFF header (20B): machine=AMD64, NumberOfSections=1, SizeOfOptionalHeader=240
//	[0x058] Optional header PE32+ (240B)
//	[0x148] Section table (40B): name=".idata", VirtualAddress=0x1000,
//	         VirtualSize=imports area size, RawData at 0x200
//	[0x200] Imports area:
//	         IMAGE_IMPORT_DESCRIPTOR x2 + null terminator
//	         ILT/IAT (uint64 RVAs) + Hint/Name entries + DLL name strings
//
// All offsets cross-checked against Microsoft PE COFF spec rev. 11 (§II.25).
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	imageBase     uint64 = 0x180000000
	sectionRVA    uint32 = 0x1000
	sectionRaw    uint32 = 0x200
	sectionRawLen uint32 = 0x200
	fileAlign            = 0x200
	sectionAlign         = 0x1000
)

func main() {
	// --- Build the .idata payload first (we need its size for headers) ---
	idata, importDirRVA, importDirSize := buildIdata()
	if uint32(len(idata)) > sectionRawLen {
		fmt.Fprintf(os.Stderr, "idata too large: %d > %d\n", len(idata), sectionRawLen)
		os.Exit(2)
	}

	// --- Pad idata up to fileAlign so the section is exactly sectionRawLen ---
	for uint32(len(idata)) < sectionRawLen {
		idata = append(idata, 0)
	}

	// --- Headers ---
	var buf bytes.Buffer

	// DOS header: MZ at 0, e_lfanew at 0x3C
	dos := make([]byte, 0x40)
	dos[0] = 'M'
	dos[1] = 'Z'
	binary.LittleEndian.PutUint32(dos[0x3C:], 0x40)
	buf.Write(dos)

	// PE signature
	buf.Write([]byte{'P', 'E', 0, 0})

	// COFF header (20B)
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)  // Machine = AMD64
	binary.LittleEndian.PutUint16(coff[2:], 1)       // NumberOfSections
	binary.LittleEndian.PutUint32(coff[4:], 0)       // TimeDateStamp
	binary.LittleEndian.PutUint32(coff[8:], 0)       // PointerToSymbolTable
	binary.LittleEndian.PutUint32(coff[12:], 0)      // NumberOfSymbols
	binary.LittleEndian.PutUint16(coff[16:], 240)    // SizeOfOptionalHeader (PE32+ standard)
	binary.LittleEndian.PutUint16(coff[18:], 0x2022) // Characteristics: EXECUTABLE_IMAGE | DLL | LARGE_ADDRESS_AWARE
	buf.Write(coff)

	// Optional header PE32+ (240B = 112 standard + 128 data dirs)
	opt := make([]byte, 240)
	binary.LittleEndian.PutUint16(opt[0:], 0x20B)   // Magic = PE32+
	opt[2] = 14                                     // MajorLinkerVersion
	opt[3] = 0                                      // MinorLinkerVersion
	binary.LittleEndian.PutUint32(opt[4:], 0x200)   // SizeOfCode
	binary.LittleEndian.PutUint32(opt[8:], 0)       // SizeOfInitializedData
	binary.LittleEndian.PutUint32(opt[12:], 0)      // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(opt[16:], 0)      // AddressOfEntryPoint (0 — no code)
	binary.LittleEndian.PutUint32(opt[20:], 0x1000) // BaseOfCode
	binary.LittleEndian.PutUint64(opt[24:], imageBase)
	binary.LittleEndian.PutUint32(opt[32:], sectionAlign)
	binary.LittleEndian.PutUint32(opt[36:], fileAlign)
	binary.LittleEndian.PutUint16(opt[40:], 6) // MajorOSVersion
	binary.LittleEndian.PutUint16(opt[42:], 0) // MinorOSVersion
	binary.LittleEndian.PutUint16(opt[44:], 0) // MajorImageVersion
	binary.LittleEndian.PutUint16(opt[46:], 0) // MinorImageVersion
	binary.LittleEndian.PutUint16(opt[48:], 6) // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(opt[50:], 0)
	binary.LittleEndian.PutUint32(opt[52:], 0)        // Win32VersionValue
	binary.LittleEndian.PutUint32(opt[56:], 0x2000)   // SizeOfImage (1 section, 4KB aligned)
	binary.LittleEndian.PutUint32(opt[60:], 0x400)    // SizeOfHeaders (DOS+PE+OPT+section table, fileAlign-padded)
	binary.LittleEndian.PutUint32(opt[64:], 0)        // CheckSum
	binary.LittleEndian.PutUint16(opt[68:], 3)        // Subsystem = WINDOWS_CUI (any non-0 works)
	binary.LittleEndian.PutUint16(opt[70:], 0x40)     // DllCharacteristics = NX_COMPAT
	binary.LittleEndian.PutUint64(opt[72:], 0x100000) // SizeOfStackReserve
	binary.LittleEndian.PutUint64(opt[80:], 0x1000)   // SizeOfStackCommit
	binary.LittleEndian.PutUint64(opt[88:], 0x100000) // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(opt[96:], 0x1000)   // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(opt[104:], 0)
	binary.LittleEndian.PutUint32(opt[108:], 16) // NumberOfRvaAndSizes

	// Data directories: index 1 = Import Table
	binary.LittleEndian.PutUint32(opt[112+1*8:], importDirRVA)
	binary.LittleEndian.PutUint32(opt[112+1*8+4:], importDirSize)
	buf.Write(opt)

	// Section table (40B): single section ".idata"
	sec := make([]byte, 40)
	copy(sec[0:8], ".idata\x00\x00")
	binary.LittleEndian.PutUint32(sec[8:], sectionRawLen)  // VirtualSize
	binary.LittleEndian.PutUint32(sec[12:], sectionRVA)    // VirtualAddress
	binary.LittleEndian.PutUint32(sec[16:], sectionRawLen) // SizeOfRawData
	binary.LittleEndian.PutUint32(sec[20:], sectionRaw)    // PointerToRawData
	binary.LittleEndian.PutUint32(sec[24:], 0)             // PointerToRelocations
	binary.LittleEndian.PutUint32(sec[28:], 0)             // PointerToLinenumbers
	binary.LittleEndian.PutUint16(sec[32:], 0)             // NumberOfRelocations
	binary.LittleEndian.PutUint16(sec[34:], 0)             // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(sec[36:], 0xC0000040)    // INITIALIZED_DATA | READ | WRITE
	buf.Write(sec)

	// Pad headers to SizeOfHeaders (0x400)
	for buf.Len() < int(sectionRaw) {
		buf.WriteByte(0)
	}

	// Section raw data
	buf.Write(idata)

	if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(2)
	}
}

// buildIdata constructs the .idata section payload and returns the
// import-directory RVA + total directory size.
//
// Layout (offsets relative to section start):
//
//	0x00  IMAGE_IMPORT_DESCRIPTOR for Crypt32.dll
//	0x14  IMAGE_IMPORT_DESCRIPTOR for Bcrypt.dll
//	0x28  IMAGE_IMPORT_DESCRIPTOR null terminator
//	0x3C  ILT for Crypt32 — 2 uint64 (1 entry + null)
//	0x4C  ILT for Bcrypt   — 2 uint64
//	0x5C  IAT for Crypt32  — 2 uint64
//	0x6C  IAT for Bcrypt   — 2 uint64
//	0x7C  Hint/Name CryptAcquireContextW (Hint=0 + name + pad)
//	      Hint/Name BCryptOpenAlgorithmProvider
//	      DLL name "Crypt32.dll\0"
//	      DLL name "Bcrypt.dll\0"
func buildIdata() (data []byte, dirRVA, dirSize uint32) {
	// We position the directory at the very start of the section.
	dirRVA = sectionRVA
	const descSize = 20
	dirSize = 3 * descSize // 2 imports + 1 null terminator

	// Pre-compute layout offsets.
	const (
		offDir1     = 0
		offDir2     = 20
		offDirNull  = 40
		offILT1     = 60  // 0x3C
		offILT2     = 76  // 0x4C
		offIAT1     = 92  // 0x5C
		offIAT2     = 108 // 0x6C
		offHN1      = 124 // 0x7C — Hint(2) + name + pad
		hn1Len      = 32
		offHN2      = offHN1 + hn1Len
		hn2Len      = 32
		offDLL1     = offHN2 + hn2Len // Crypt32.dll
		dll1Len     = 16
		offDLL2     = offDLL1 + dll1Len // Bcrypt.dll
		dll2Len     = 16
		idataExtent = offDLL2 + dll2Len
	)

	d := make([]byte, idataExtent)

	// Descriptor 1: Crypt32.dll
	binary.LittleEndian.PutUint32(d[offDir1+0:], sectionRVA+offILT1)  // OriginalFirstThunk
	binary.LittleEndian.PutUint32(d[offDir1+4:], 0)                   // TimeDateStamp
	binary.LittleEndian.PutUint32(d[offDir1+8:], 0)                   // ForwarderChain
	binary.LittleEndian.PutUint32(d[offDir1+12:], sectionRVA+offDLL1) // Name
	binary.LittleEndian.PutUint32(d[offDir1+16:], sectionRVA+offIAT1) // FirstThunk

	// Descriptor 2: Bcrypt.dll
	binary.LittleEndian.PutUint32(d[offDir2+0:], sectionRVA+offILT2)
	binary.LittleEndian.PutUint32(d[offDir2+4:], 0)
	binary.LittleEndian.PutUint32(d[offDir2+8:], 0)
	binary.LittleEndian.PutUint32(d[offDir2+12:], sectionRVA+offDLL2)
	binary.LittleEndian.PutUint32(d[offDir2+16:], sectionRVA+offIAT2)

	// Descriptor null terminator already zero.

	// ILT1: 1 entry pointing at HN1, then null
	binary.LittleEndian.PutUint64(d[offILT1+0:], uint64(sectionRVA+offHN1))
	binary.LittleEndian.PutUint64(d[offILT1+8:], 0)
	// ILT2 → HN2
	binary.LittleEndian.PutUint64(d[offILT2+0:], uint64(sectionRVA+offHN2))
	binary.LittleEndian.PutUint64(d[offILT2+8:], 0)
	// IAT1 mirrors ILT1 pre-bind
	binary.LittleEndian.PutUint64(d[offIAT1+0:], uint64(sectionRVA+offHN1))
	binary.LittleEndian.PutUint64(d[offIAT1+8:], 0)
	binary.LittleEndian.PutUint64(d[offIAT2+0:], uint64(sectionRVA+offHN2))
	binary.LittleEndian.PutUint64(d[offIAT2+8:], 0)

	// Hint/Name 1: Hint=0 + "CryptAcquireContextW\0"
	copy(d[offHN1+2:], "CryptAcquireContextW\x00")
	// Hint/Name 2: Hint=0 + "BCryptOpenAlgorithmProvider\0"
	copy(d[offHN2+2:], "BCryptOpenAlgorithmProvider\x00")

	// DLL names
	copy(d[offDLL1:], "Crypt32.dll\x00")
	copy(d[offDLL2:], "Bcrypt.dll\x00")

	return d, dirRVA, dirSize
}
