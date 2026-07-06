/*
Copyright © 2026 Security Research
*/
package garble

import (
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// BinaryInfo holds metadata extracted from a Go binary.
type BinaryInfo struct {
	FilePath       string            `json:"file_path"`
	FileName       string            `json:"file_name"`
	FileSize       int64             `json:"file_size"`
	Format         string            `json:"format"`
	GoVersion      string            `json:"go_version"`
	ModulePath     string            `json:"module_path,omitempty"`
	BuildSettings  map[string]string `json:"build_settings,omitempty"`
	BuildID        string            `json:"build_id,omitempty"`
	IsStaticLinked bool              `json:"is_static_linked"`
	HasSymbolTable bool              `json:"has_symbol_table"`
	SymbolCount    int               `json:"symbol_count"`
	HasDWARF       bool              `json:"has_dwarf"`
	HasBuildInfo   bool              `json:"has_build_info"`
	Arch           string            `json:"arch"`
	OS             string            `json:"os"`
	Sections       []string          `json:"sections,omitempty"`
}

// ExtractInfo extracts Go binary metadata from the given file.
func ExtractInfo(binPath string) (*BinaryInfo, error) {
	absPath, err := filepath.Abs(binPath)
	if err != nil {
		absPath = binPath
	}

	fi, err := os.Stat(binPath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	format, err := detectFileFormat(binPath)
	if err != nil {
		return nil, err
	}

	info := &BinaryInfo{
		FilePath: absPath,
		FileName: filepath.Base(binPath),
		FileSize: fi.Size(),
		Format:   string(format),
	}

	// Extract build info
	bi, err := buildinfo.ReadFile(binPath)
	if err == nil {
		info.HasBuildInfo = true

		info.GoVersion = bi.GoVersion
		if bi.Main.Path != "" {
			info.ModulePath = bi.Main.Path
		}

		info.BuildSettings = make(map[string]string)
		for _, s := range bi.Settings {
			info.BuildSettings[s.Key] = s.Value
		}
	}

	// Extract format-specific metadata
	switch format {
	case FormatELF:
		extractELFInfo(binPath, info)
	case FormatPE:
		extractPEInfo(binPath, info)
	case FormatMachO:
		extractMachOInfo(binPath, info)
	}

	// Infer OS/Arch from build settings or current runtime
	if v, ok := info.BuildSettings["GOOS"]; ok {
		info.OS = v
	} else if info.OS == "" {
		info.OS = runtime.GOOS
	}

	if v, ok := info.BuildSettings["GOARCH"]; ok {
		info.Arch = v
	} else if info.Arch == "" {
		info.Arch = runtime.GOARCH
	}

	return info, nil
}

func extractELFInfo(binPath string, info *BinaryInfo) {
	f, err := elf.Open(binPath)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	// Architecture
	info.Arch = elfMachineArch(f.Machine)

	// DWARF
	dw, err := f.DWARF()
	info.HasDWARF = err == nil && dw != nil

	// Symbols
	syms, err := f.Symbols()
	if err == nil && len(syms) > 0 {
		info.HasSymbolTable = true
		info.SymbolCount = len(syms)
	}

	// Static linking: no INTERP program header and no dynamic section
	info.IsStaticLinked = true

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP || prog.Type == elf.PT_DYNAMIC {
			info.IsStaticLinked = false
			break
		}
	}

	// Sections
	for _, sect := range f.Sections {
		if sect.Name != "" {
			info.Sections = append(info.Sections, sect.Name)
		}
	}

	// Build ID from .note.go.buildid section
	if sect := f.Section(".note.go.buildid"); sect != nil {
		data, err := sect.Data()
		if err == nil && len(data) > 16 {
			// The build ID is typically after the note header
			info.BuildID = extractNoteString(data)
		}
	}

	// OS from ELF OSABI
	switch f.OSABI {
	case elf.ELFOSABI_LINUX:
		info.OS = "linux"
	case elf.ELFOSABI_FREEBSD:
		info.OS = "freebsd"
	case elf.ELFOSABI_OPENBSD:
		info.OS = "openbsd"
	case elf.ELFOSABI_NETBSD:
		info.OS = "netbsd"
	}
}

func extractPEInfo(binPath string, info *BinaryInfo) {
	f, err := pe.Open(binPath)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	info.OS = "windows"

	// Architecture
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Arch = "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Arch = "386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		info.Arch = "arm64"
	}

	// DWARF
	dw, err := f.DWARF()
	info.HasDWARF = err == nil && dw != nil

	// Symbols
	if f.Symbols != nil && len(f.Symbols) > 0 {
		info.HasSymbolTable = true
		info.SymbolCount = len(f.Symbols)
	}

	// PE binaries are typically dynamically linked; check for imports
	info.IsStaticLinked = true
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		info.IsStaticLinked = false
	}

	// Sections
	for _, sect := range f.Sections {
		if sect.Name != "" {
			info.Sections = append(info.Sections, sect.Name)
		}
	}
}

func extractMachOInfo(binPath string, info *BinaryInfo) {
	f, err := macho.Open(binPath)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	info.OS = "darwin"

	// Architecture
	switch f.Cpu {
	case macho.CpuAmd64:
		info.Arch = "amd64"
	case macho.CpuArm64:
		info.Arch = "arm64"
	case macho.Cpu386:
		info.Arch = "386"
	}

	// DWARF
	dw, err := f.DWARF()
	info.HasDWARF = err == nil && dw != nil

	// Symbols
	if f.Symtab != nil && len(f.Symtab.Syms) > 0 {
		info.HasSymbolTable = true
		info.SymbolCount = len(f.Symtab.Syms)
	}

	// Mach-O Go binaries are typically statically linked
	info.IsStaticLinked = true

	for _, load := range f.Loads {
		if _, ok := load.(*macho.Dylib); ok {
			info.IsStaticLinked = false
			break
		}
	}

	// Sections
	for _, sect := range f.Sections {
		if sect.Name != "" {
			info.Sections = append(info.Sections, sect.Name)
		}
	}

	// Build info section
	if sect := f.Section("__go_buildinfo"); sect != nil {
		data, err := sect.Data()
		if err == nil && len(data) > 0 {
			info.BuildID = "(present)"
		}
	}
}

func elfMachineArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_386:
		return "386"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_MIPS:
		return "mips"
	case elf.EM_RISCV:
		return "riscv64"
	case elf.EM_PPC64:
		return "ppc64"
	case elf.EM_S390:
		return "s390x"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// extractNoteString tries to extract the Go build ID from a .note.go.buildid section.
func extractNoteString(data []byte) string {
	// ELF note format: namesz(4) + descsz(4) + type(4) + name + padding + desc
	if len(data) < 12 {
		return ""
	}

	// Try to find a readable string in the descriptor
	// The build ID is typically the descriptor portion
	for i := 12; i < len(data); i++ {
		if data[i] == 0 {
			continue
		}
		// Find the start of printable text
		start := i
		for i < len(data) && data[i] >= 0x20 && data[i] < 0x7f {
			i++
		}

		if i-start > 8 {
			return string(data[start:i])
		}
	}

	return ""
}
