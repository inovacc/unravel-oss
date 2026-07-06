/*
Copyright (c) 2026 Security Research
*/
package nodeaddon

import "testing"

// TestExtractPEExportNames_NamesRVAUnderflow feeds an export directory whose
// AddressOfNames (namesRVA) is just below the section's VirtualAddress
// (sectionRVA-4). The old uint32 math computed namesOffset=0xFFFFFFFC and the
// guard `namesOffset+numNames*4` wrapped to 0, slipping past the bound and
// indexing sectionData[0xFFFFFFFC] -> panic. The widened uint64 math + the
// >= sectionRVA precondition must instead return nil without panicking.
// Finding #7.
func TestExtractPEExportNames_NamesRVAUnderflow(t *testing.T) {
	const sectionRVA = uint32(0x1000)
	sectionData := make([]byte, 64)

	// Export directory at the start of the section (exportRVA == sectionRVA).
	// NumberOfNames (offset 24) = 1; AddressOfNames (offset 32) = sectionRVA-4.
	sectionData[24] = 1 // numNames = 1
	namesRVA := sectionRVA - 4
	sectionData[32] = byte(namesRVA)
	sectionData[33] = byte(namesRVA >> 8)
	sectionData[34] = byte(namesRVA >> 16)
	sectionData[35] = byte(namesRVA >> 24)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("extractPEExportNames panicked on sub-section namesRVA: %v", r)
		}
	}()

	got := extractPEExportNames(sectionData, sectionRVA, sectionRVA, 0x28)
	if got != nil {
		t.Fatalf("expected nil for underflowing namesRVA, got %v", got)
	}
}

// TestExtractPEExportNames_Valid sanity-checks that a well-formed export
// directory still yields names after the hardening.
func TestExtractPEExportNames_Valid(t *testing.T) {
	const sectionRVA = uint32(0x1000)
	sectionData := make([]byte, 80)

	// Export directory at section start. numNames=1, AddressOfNames points at a
	// names-array entry inside the section.
	sectionData[24] = 1 // numNames

	// names array at section offset 40 (RVA sectionRVA+40), one 4-byte RVA.
	namesArrayRVA := sectionRVA + 40
	sectionData[32] = byte(namesArrayRVA)
	sectionData[33] = byte(namesArrayRVA >> 8)
	sectionData[34] = byte(namesArrayRVA >> 16)
	sectionData[35] = byte(namesArrayRVA >> 24)

	// The single name RVA points at the string at section offset 50.
	nameStrRVA := sectionRVA + 50
	sectionData[40] = byte(nameStrRVA)
	sectionData[41] = byte(nameStrRVA >> 8)
	sectionData[42] = byte(nameStrRVA >> 16)
	sectionData[43] = byte(nameStrRVA >> 24)

	copy(sectionData[50:], []byte("foo\x00"))

	got := extractPEExportNames(sectionData, sectionRVA, sectionRVA, 0x28)
	if len(got) != 1 || got[0] != "foo" {
		t.Fatalf("expected [foo], got %v", got)
	}
}
