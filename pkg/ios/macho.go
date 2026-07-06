package ios

import (
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// MachOInfo contains metadata extracted from a Mach-O binary.
type MachOInfo struct {
	Format       string        `json:"format"`
	CPUType      string        `json:"cpu_type"`
	FileType     string        `json:"file_type"`
	LoadCommands int           `json:"load_commands"`
	MinOS        string        `json:"min_os,omitempty"`
	SDKVersion   string        `json:"sdk_version,omitempty"`
	Libraries    []string      `json:"libraries,omitempty"`
	RPaths       []string      `json:"rpaths,omitempty"`
	EntryPoint   uint64        `json:"entry_point,omitempty"`
	UUID         string        `json:"uuid,omitempty"`
	Encrypted    bool          `json:"encrypted"`
	HasBitcode   bool          `json:"has_bitcode"`
	Segments     []SegmentInfo `json:"segments,omitempty"`
}

// SegmentInfo describes a Mach-O segment.
type SegmentInfo struct {
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
	FileOff uint64 `json:"file_offset"`
}

// Mach-O load command constants not in debug/macho.
const (
	lcUUID            = 0x1b
	lcMain            = 0x80000028
	lcEncryptionInfo  = 0x21
	lcEncryption64    = 0x2C
	lcRpath           = 0x8000001C
	lcBuildVersion    = 0x32
	lcVersionMinIOS   = 0x25
	lcVersionMinMac   = 0x24
	lcVersionMinTV    = 0x2F
	lcVersionMinWatch = 0x30
)

// ParseMachO reads a Mach-O binary and extracts metadata.
func ParseMachO(path string) (*MachOInfo, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open macho: %w", err)
	}
	defer func() { _ = f.Close() }()

	info := &MachOInfo{
		Format:       machoCPUBits(f.Magic),
		CPUType:      machoCPUString(f.Cpu),
		FileType:     machoFileType(f.Type),
		LoadCommands: len(f.Loads),
	}

	// Extract segments.
	for _, load := range f.Loads {
		switch l := load.(type) {
		case *macho.Segment:
			info.Segments = append(info.Segments, SegmentInfo{
				Name:    l.Name,
				Size:    l.Filesz,
				FileOff: l.Offset,
			})
			if l.Name == "__LLVM" {
				info.HasBitcode = true
			}
		case *macho.Dylib:
			info.Libraries = append(info.Libraries, l.Name)
		}
	}

	// Walk raw load commands for types not decoded by debug/macho.
	if err := parseMachORawLoads(f, info); err != nil {
		// Non-fatal; we got the basics already.
		_ = err
	}

	return info, nil
}

// ParseMachOFromReader reads a Mach-O binary from an io.ReaderAt.
func ParseMachOFromReader(r io.ReaderAt) (*MachOInfo, error) {
	f, err := macho.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("parse macho: %w", err)
	}
	defer func() { _ = f.Close() }()

	info := &MachOInfo{
		Format:       machoCPUBits(f.Magic),
		CPUType:      machoCPUString(f.Cpu),
		FileType:     machoFileType(f.Type),
		LoadCommands: len(f.Loads),
	}

	for _, load := range f.Loads {
		switch l := load.(type) {
		case *macho.Segment:
			info.Segments = append(info.Segments, SegmentInfo{
				Name:    l.Name,
				Size:    l.Filesz,
				FileOff: l.Offset,
			})
			if l.Name == "__LLVM" {
				info.HasBitcode = true
			}
		case *macho.Dylib:
			info.Libraries = append(info.Libraries, l.Name)
		}
	}

	if err := parseMachORawLoads(f, info); err != nil {
		_ = err
	}

	return info, nil
}

func parseMachORawLoads(f *macho.File, info *MachOInfo) error {
	bo := f.ByteOrder

	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			continue
		}
		cmd := bo.Uint32(raw[0:4])

		switch cmd {
		case lcUUID:
			if len(raw) >= 24 {
				u := raw[8:24]
				info.UUID = fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
					binary.BigEndian.Uint32(u[0:4]),
					binary.BigEndian.Uint16(u[4:6]),
					binary.BigEndian.Uint16(u[6:8]),
					binary.BigEndian.Uint16(u[8:10]),
					u[10:16])
			}

		case lcMain:
			if len(raw) >= 16 {
				info.EntryPoint = bo.Uint64(raw[8:16])
			}

		case lcEncryptionInfo:
			if len(raw) >= 20 {
				cryptID := bo.Uint32(raw[16:20])
				info.Encrypted = cryptID != 0
			}

		case lcEncryption64:
			if len(raw) >= 24 {
				cryptID := bo.Uint32(raw[20:24])
				info.Encrypted = cryptID != 0
			}

		case lcRpath:
			if len(raw) >= 12 {
				off := bo.Uint32(raw[8:12])
				if int(off) < len(raw) {
					rp := cstring(raw[off:])
					if rp != "" {
						info.RPaths = append(info.RPaths, rp)
					}
				}
			}

		case lcBuildVersion:
			if len(raw) >= 20 {
				minOSRaw := bo.Uint32(raw[12:16])
				sdkRaw := bo.Uint32(raw[16:20])
				info.MinOS = machoVersionString(minOSRaw)
				info.SDKVersion = machoVersionString(sdkRaw)
			}

		case lcVersionMinIOS, lcVersionMinMac, lcVersionMinTV, lcVersionMinWatch:
			if len(raw) >= 16 {
				ver := bo.Uint32(raw[8:12])
				sdk := bo.Uint32(raw[12:16])
				info.MinOS = machoVersionString(ver)
				info.SDKVersion = machoVersionString(sdk)
			}
		}
	}

	return nil
}

func machoCPUBits(magic uint32) string {
	if magic == macho.Magic64 || magic == macho.MagicFat {
		return "Mach-O 64-bit"
	}
	return "Mach-O 32-bit"
}

func machoCPUString(cpu macho.Cpu) string {
	names := map[macho.Cpu]string{
		macho.CpuArm:   "arm",
		macho.CpuAmd64: "x86_64",
		macho.Cpu386:   "x86",
		macho.CpuPpc:   "ppc",
		macho.CpuPpc64: "ppc64",
	}
	// Arm64 constant (12 | 0x01000000)
	const cpuArm64 macho.Cpu = 0x100000C
	if cpu == cpuArm64 {
		return "arm64"
	}
	if s, ok := names[cpu]; ok {
		return s
	}
	return fmt.Sprintf("unknown(%d)", cpu)
}

func machoFileType(t macho.Type) string {
	names := map[macho.Type]string{
		macho.TypeExec:   "execute",
		macho.TypeDylib:  "dylib",
		macho.TypeBundle: "bundle",
		macho.TypeObj:    "object",
	}
	if s, ok := names[t]; ok {
		return s
	}
	return fmt.Sprintf("type(%d)", t)
}

func machoVersionString(v uint32) string {
	major := v >> 16
	minor := (v >> 8) & 0xFF
	patch := v & 0xFF
	if patch == 0 {
		return fmt.Sprintf("%d.%d", major, minor)
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

// cstring reads a null-terminated string from a byte slice.
func cstring(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
