/*
Copyright © 2026 Security Research
*/
package cert

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"go.mozilla.org/pkcs7"
)

const (
	// Linux kernel module signature magic trailer
	moduleSignatureMagic = "~Module signature appended~\n"
	moduleSignatureSize  = 12 // struct module_signature size (excluding magic)
)

// ELFDetail holds metadata extracted from an ELF binary header and sections.
type ELFDetail struct {
	Class       string `json:"class"`                 // ELF32 or ELF64
	Machine     string `json:"machine"`               // x86_64, aarch64, etc.
	Type        string `json:"type"`                  // Executable, Shared Object, Relocatable
	OSABI       string `json:"os_abi"`                // Linux, FreeBSD, etc.
	ByteOrder   string `json:"byte_order"`            // LittleEndian or BigEndian
	BuildID     string `json:"build_id,omitempty"`    // GNU build ID hex
	Interpreter string `json:"interpreter,omitempty"` // Dynamic linker path
	HasModSig   bool   `json:"has_module_sig"`        // Kernel module appended signature
}

// moduleSignature mirrors the Linux kernel's struct module_signature.
// The sig_len field is big-endian regardless of architecture.
type moduleSignature struct {
	Algo      uint8
	Hash      uint8
	IDType    uint8
	SignerLen uint8
	KeyIDLen  uint8
	Pad       [3]uint8
	SigLen    uint32 // big-endian
}

// extractELFCertificates parses an ELF binary and extracts certificate information.
// It checks for:
//  1. Kernel module appended PKCS#7 signatures
//  2. ELF sections containing embedded PKCS#7/X.509 certificates
func extractELFCertificates(filePath string, info *CertInfo) error {
	elfFile, err := elf.Open(filePath)
	if err != nil {
		return fmt.Errorf("open ELF file: %w", err)
	}

	defer func() { _ = elfFile.Close() }()

	info.FileType = "ELF"
	info.ELFInfo = parseELFDetail(elfFile)

	// 1. Check for kernel module appended signature
	if found, sigErr := extractModuleSignature(filePath, info); found {
		return sigErr
	}

	// 2. Check ELF sections for embedded certificates
	if found, secErr := extractELFSectionCerts(elfFile, info); found {
		return secErr
	}

	return nil
}

// parseELFDetail extracts ELF header metadata.
func parseELFDetail(ef *elf.File) *ELFDetail {
	d := &ELFDetail{
		Class:     elfClassName(ef.Class),
		Machine:   elfMachineName(ef.Machine),
		Type:      elfTypeName(ef.Type),
		OSABI:     elfOSABIName(ef.OSABI),
		ByteOrder: ef.ByteOrder.String(),
	}

	// Extract GNU build ID from .note.gnu.build-id section
	if buildID := extractBuildID(ef); buildID != "" {
		d.BuildID = buildID
	}

	// Extract interpreter from .interp section
	if interp := ef.Section(".interp"); interp != nil {
		data, err := interp.Data()
		if err == nil {
			// Trim null terminator
			d.Interpreter = string(bytes.TrimRight(data, "\x00"))
		}
	}

	return d
}

// extractBuildID reads the GNU build ID from .note.gnu.build-id section.
func extractBuildID(ef *elf.File) string {
	sec := ef.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}

	data, err := sec.Data()
	if err != nil || len(data) < 16 {
		return ""
	}

	// ELF note format: namesz(4) + descsz(4) + type(4) + name + desc
	namesz := ef.ByteOrder.Uint32(data[0:4])
	descsz := ef.ByteOrder.Uint32(data[4:8])

	// Align namesz to 4 bytes
	nameOff := uint32(12)
	descOff := nameOff + ((namesz + 3) &^ 3)

	if uint32(len(data)) < descOff+descsz {
		return ""
	}

	return hex.EncodeToString(data[descOff : descOff+descsz])
}

// extractModuleSignature checks for a Linux kernel module appended PKCS#7 signature.
// Format: [module data][PKCS#7 sig][module_signature struct (12 bytes)][magic string (28 bytes)]
func extractModuleSignature(filePath string, info *CertInfo) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}

	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return false, err
	}

	magicLen := int64(len(moduleSignatureMagic))
	trailerLen := magicLen + moduleSignatureSize

	if stat.Size() < trailerLen+1 {
		return false, nil
	}

	// Read the trailer (module_signature struct + magic)
	if _, err := f.Seek(stat.Size()-trailerLen, io.SeekStart); err != nil {
		return false, nil
	}

	trailer := make([]byte, trailerLen)
	if _, err := io.ReadFull(f, trailer); err != nil {
		return false, nil
	}

	// Check magic
	magic := trailer[moduleSignatureSize:]
	if string(magic) != moduleSignatureMagic {
		return false, nil
	}

	// Parse module_signature struct
	var modSig moduleSignature
	if err := binary.Read(bytes.NewReader(trailer[:moduleSignatureSize]), binary.BigEndian, &modSig); err != nil {
		return true, fmt.Errorf("parse module signature struct: %w", err)
	}

	if info.ELFInfo != nil {
		info.ELFInfo.HasModSig = true
	}

	// sig_len is big-endian
	sigLen := modSig.SigLen
	if int64(sigLen) > stat.Size()-trailerLen {
		return true, fmt.Errorf("signature length %d exceeds file size", sigLen)
	}

	// Read the PKCS#7 signature data
	sigOffset := stat.Size() - trailerLen - int64(sigLen)
	if _, err := f.Seek(sigOffset, io.SeekStart); err != nil {
		return true, fmt.Errorf("seek to signature: %w", err)
	}

	sigData := make([]byte, sigLen)
	if _, err := io.ReadFull(f, sigData); err != nil {
		return true, fmt.Errorf("read signature data: %w", err)
	}

	// id_type 2 = PKEY_ID_PKCS7
	if modSig.IDType != 2 {
		// Non-PKCS7 signature (e.g., PGP) — mark as signed but can't parse certs
		info.HasSignature = true
		info.VerifyError = fmt.Sprintf("unsupported signature type: %d (not PKCS#7)", modSig.IDType)

		return true, nil
	}

	p7, err := pkcs7.Parse(sigData)
	if err != nil {
		return true, fmt.Errorf("parse module PKCS7: %w", err)
	}

	info.HasSignature = true
	info.RawCerts = p7.Certificates

	if len(p7.Certificates) > 0 {
		info.Signer = parseCertDetail(p7.Certificates[0])
		for i := 1; i < len(p7.Certificates); i++ {
			info.Chain = append(info.Chain, parseCertDetail(p7.Certificates[i]))
		}
	}

	if err := p7.Verify(); err != nil {
		info.Verified = false
		info.VerifyError = err.Error()
	} else {
		info.Verified = true
	}

	return true, nil
}

// extractELFSectionCerts scans ELF sections for embedded PKCS#7 or X.509 certificates.
// Some tools embed signatures in sections like .note.signature or .sig.
func extractELFSectionCerts(ef *elf.File, info *CertInfo) (bool, error) {
	sigSections := []string{
		".note.signature",
		".sig",
		".pkcs7",
		".certificate",
	}

	for _, name := range sigSections {
		sec := ef.Section(name)
		if sec == nil {
			continue
		}

		data, err := sec.Data()
		if err != nil || len(data) == 0 {
			continue
		}

		p7, err := pkcs7.Parse(data)
		if err != nil {
			continue
		}

		info.HasSignature = true
		info.RawCerts = p7.Certificates

		if len(p7.Certificates) > 0 {
			info.Signer = parseCertDetail(p7.Certificates[0])
			for i := 1; i < len(p7.Certificates); i++ {
				info.Chain = append(info.Chain, parseCertDetail(p7.Certificates[i]))
			}
		}

		if err := p7.Verify(); err != nil {
			info.Verified = false
			info.VerifyError = err.Error()
		} else {
			info.Verified = true
		}

		return true, nil
	}

	return false, nil
}

func elfClassName(c elf.Class) string {
	switch c {
	case elf.ELFCLASS32:
		return "ELF32"
	case elf.ELFCLASS64:
		return "ELF64"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}

func elfMachineName(m elf.Machine) string {
	switch m {
	case elf.EM_386:
		return "x86"
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_ARM:
		return "ARM"
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_MIPS:
		return "MIPS"
	case elf.EM_PPC:
		return "PowerPC"
	case elf.EM_PPC64:
		return "PowerPC64"
	case elf.EM_RISCV:
		return "RISC-V"
	case elf.EM_S390:
		return "s390x"
	default:
		return m.String()
	}
}

func elfTypeName(t elf.Type) string {
	switch t {
	case elf.ET_REL:
		return "Relocatable"
	case elf.ET_EXEC:
		return "Executable"
	case elf.ET_DYN:
		return "Shared Object"
	case elf.ET_CORE:
		return "Core Dump"
	default:
		return t.String()
	}
}

func elfOSABIName(o elf.OSABI) string {
	switch o {
	case elf.ELFOSABI_NONE, elf.ELFOSABI_LINUX:
		return "Linux"
	case elf.ELFOSABI_FREEBSD:
		return "FreeBSD"
	case elf.ELFOSABI_NETBSD:
		return "NetBSD"
	case elf.ELFOSABI_OPENBSD:
		return "OpenBSD"
	case elf.ELFOSABI_SOLARIS:
		return "Solaris"
	default:
		return o.String()
	}
}
