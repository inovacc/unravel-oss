/*
Copyright (c) 2026 Security Research
*/
package clr

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// COMDescriptorDir is the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR index in the PE
// optional-header DataDirectory array (ECMA-335 II.25.3.3).
const COMDescriptorDir = 14

// Sentinel errors.
var (
	ErrNotManaged     = errors.New("not a managed pe")
	ErrBadMetadataSig = errors.New("bad metadata signature")
)

// DataDir is a PE/CLI (RVA, Size) data-directory pair.
type DataDir struct{ RVA, Size uint32 }

// COR20Header is the IMAGE_COR20_HEADER / CLI header (ECMA-335 II.25.3.3),
// little-endian, 72 bytes.
type COR20Header struct {
	Cb                      uint32
	MajorRuntimeVersion     uint16
	MinorRuntimeVersion     uint16
	MetaData                DataDir
	Flags                   uint32
	EntryPointToken         uint32
	Resources               DataDir
	StrongNameSignature     DataDir
	CodeManagerTable        DataDir
	VTableFixups            DataDir
	ExportAddressTableJumps DataDir
	ManagedNativeHeader     DataDir
}

type secMap struct {
	virtAddr uint32
	virtSize uint32
	rawPtr   uint32
	rawSize  uint32
}

// Image is an opened managed PE: the section map plus the slurped metadata
// region. The raw file bytes are retained as an io.ReaderAt for M1 body reads.
type Image struct {
	ra       io.ReaderAt
	size     int64
	cor20    COR20Header
	meta     []byte
	sections []secMap
}

// Open opens a managed PE at path. It is panic-safe: a malformed input
// surfaces as an error, never a panic.
func Open(path string) (img *Image, err error) {
	defer func() {
		if r := recover(); r != nil {
			img, err = nil, fmt.Errorf("clr: recovered from panic opening %s: %v", path, r)
		}
	}()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return openBytes(data, int64(len(data)))
}

// OpenReaderAt opens a managed PE from an io.ReaderAt of known size.
func OpenReaderAt(ra io.ReaderAt, size int64) (img *Image, err error) {
	defer func() {
		if r := recover(); r != nil {
			img, err = nil, fmt.Errorf("clr: recovered from panic opening reader: %v", r)
		}
	}()
	data := make([]byte, size)
	if _, err := io.ReadFull(io.NewSectionReader(ra, 0, size), data); err != nil {
		return nil, fmt.Errorf("read image bytes: %w", err)
	}
	return openBytes(data, size)
}

func openBytes(data []byte, size int64) (*Image, error) {
	ra := bytesReaderAt(data)
	f, err := pe.NewFile(ra)
	if err != nil {
		return nil, fmt.Errorf("parse pe: %w", err)
	}
	defer func() { _ = f.Close() }()

	dd, ok := comDescriptor(f)
	if !ok || dd.VirtualAddress == 0 || dd.Size == 0 {
		return nil, ErrNotManaged
	}

	img := &Image{ra: ra, size: size, sections: buildSecMap(f)}

	off, ok := img.RVAToOffset(dd.VirtualAddress)
	if !ok || off+72 > len(data) {
		return nil, fmt.Errorf("cor20 header rva %#x: %w", dd.VirtualAddress, ErrNotManaged)
	}
	if err := img.cor20.unmarshal(data[off : off+72]); err != nil {
		return nil, err
	}
	if err := img.slurpMetadata(data); err != nil {
		return nil, err
	}
	return img, nil
}

func comDescriptor(f *pe.File) (pe.DataDirectory, bool) {
	var dds []pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		dds = oh.DataDirectory[:]
	case *pe.OptionalHeader32:
		dds = oh.DataDirectory[:]
	default:
		return pe.DataDirectory{}, false
	}
	if len(dds) <= COMDescriptorDir {
		return pe.DataDirectory{}, false
	}
	return dds[COMDescriptorDir], true
}

func buildSecMap(f *pe.File) []secMap {
	out := make([]secMap, 0, len(f.Sections))
	for _, s := range f.Sections {
		out = append(out, secMap{
			virtAddr: s.VirtualAddress,
			virtSize: s.VirtualSize,
			rawPtr:   s.Offset,
			rawSize:  s.Size,
		})
	}
	return out
}

// RVAToOffset maps a virtual address to a file offset via the section table.
// It is bounds-checked: an RVA outside every section, or inside a section's
// virtual extent but beyond that section's raw data, returns (0, false).
func (i *Image) RVAToOffset(rva uint32) (int, bool) {
	for _, s := range i.sections {
		if rva < s.virtAddr {
			continue
		}
		delta := rva - s.virtAddr
		// Within the virtual span?
		span := s.virtSize
		if span == 0 || delta < span {
			// Must also be inside the section's raw data.
			if delta >= s.rawSize {
				return 0, false
			}
			off := int64(s.rawPtr) + int64(delta)
			if off < 0 || off >= i.size {
				return 0, false
			}
			return int(off), true
		}
	}
	return 0, false
}

func (c *COR20Header) unmarshal(b []byte) error {
	if len(b) < 72 {
		return fmt.Errorf("cor20 header too short: %d bytes", len(b))
	}
	le := binary.LittleEndian
	c.Cb = le.Uint32(b[0:])
	c.MajorRuntimeVersion = le.Uint16(b[4:])
	c.MinorRuntimeVersion = le.Uint16(b[6:])
	c.MetaData = DataDir{le.Uint32(b[8:]), le.Uint32(b[12:])}
	c.Flags = le.Uint32(b[16:])
	c.EntryPointToken = le.Uint32(b[20:])
	c.Resources = DataDir{le.Uint32(b[24:]), le.Uint32(b[28:])}
	c.StrongNameSignature = DataDir{le.Uint32(b[32:]), le.Uint32(b[36:])}
	c.CodeManagerTable = DataDir{le.Uint32(b[40:]), le.Uint32(b[44:])}
	c.VTableFixups = DataDir{le.Uint32(b[48:]), le.Uint32(b[52:])}
	c.ExportAddressTableJumps = DataDir{le.Uint32(b[56:]), le.Uint32(b[60:])}
	c.ManagedNativeHeader = DataDir{le.Uint32(b[64:]), le.Uint32(b[68:])}
	return nil
}

// metaSig is the BSJB metadata-root signature (ECMA-335 II.24.2.1), LE.
const metaSig = 0x424A5342

// slurpMetadata maps the COR20 MetaData RVA to a file offset, copies exactly
// MetaData.Size bytes, and validates the BSJB root signature.
func (i *Image) slurpMetadata(data []byte) error {
	d := i.cor20.MetaData
	off, ok := i.RVAToOffset(d.RVA)
	if !ok {
		return fmt.Errorf("metadata rva %#x: %w", d.RVA, ErrNotManaged)
	}
	end := off + int(d.Size)
	if d.Size < 4 || end > len(data) {
		return fmt.Errorf("metadata region [%d:%d] out of bounds (len %d): %w", off, end, len(data), ErrBadMetadataSig)
	}
	region := make([]byte, d.Size)
	copy(region, data[off:end])
	if binary.LittleEndian.Uint32(region) != metaSig {
		return ErrBadMetadataSig
	}
	i.meta = region
	return nil
}

// Metadata returns the slurped metadata region (BSJB root + streams), bounded
// by COR20.MetaData.Size. The returned slice is owned by the Image; callers
// must not mutate it.
func (i *Image) Metadata() []byte { return i.meta }

// ReaderAt returns the raw image bytes as an io.ReaderAt. M1 reads method
// bodies through this together with RVAToOffset; the two are fed to the locked
// M0->M1 seam contract il.ReadMethodBody(img.ReaderAt(), img.RVAToOffset, rva,
// implFlags). (This 4-arg form supersedes spec §2's 3-arg sketch; implFlags was
// added for the M1-T2 native-method gate.) The returned reader is read-only and
// safe to share.
func (i *Image) ReaderAt() io.ReaderAt { return i.ra }

// bytesReaderAt adapts a byte slice to io.ReaderAt (avoids retaining *os.File).
type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
