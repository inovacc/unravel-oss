/*
Copyright (c) 2026 Security Research
*/
package binary

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/cert"
)

// urlRe matches HTTP/HTTPS URLs in extracted strings.
var urlRe = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

// Info captures lightweight binary analysis for decompilation triage.
type Info struct {
	Path            string          `json:"path"`
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	Arch            string          `json:"arch,omitempty"`
	SizeBytes       int64           `json:"size_bytes"`
	SizeMB          float64         `json:"size_mb"`
	Imports         []string        `json:"imports,omitempty"`
	Libraries       []string        `json:"libraries,omitempty"`
	StringsTotal    int             `json:"strings_total"`
	URLCount        int             `json:"url_count"`
	SampleURLs      []string        `json:"sample_urls,omitempty"`
	SampleStrings   []string        `json:"sample_strings,omitempty"`
	ToolResults     []ToolResult    `json:"tool_results,omitempty"`
	CertSubject     string          `json:"cert_subject,omitempty"`
	CertIssuer      string          `json:"cert_issuer,omitempty"`
	ProductName     string          `json:"product_name,omitempty"`
	ProductVersion  string          `json:"product_version,omitempty"`
	FileDescription string          `json:"file_description,omitempty"`
	CompanyName     string          `json:"company_name,omitempty"`
	IsDotNet        bool            `json:"is_dotnet,omitempty"`
	DotNetMeta      *DotNetMetadata `json:"dotnet_meta,omitempty"`
}

// ToolResult captures best-effort external tool output for a binary.
type ToolResult struct {
	Name    string `json:"name"`
	Command string `json:"command"`
	Status  string `json:"status"` // ok, missing, skipped, error
	Output  string `json:"output,omitempty"`
}

// AnalyzeSingleFile extracts metadata, imports, strings, and certs from a single binary file.
// Returns nil, nil if the file is not a recognized binary format.
func AnalyzeSingleFile(path string, verbose bool) (*Info, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	btype := detectBinaryType(path)
	if btype == "" {
		return nil, nil
	}

	bi := &Info{
		Path:      path,
		Name:      filepath.Base(path),
		Type:      btype,
		SizeBytes: info.Size(),
		SizeMB:    float64(info.Size()) / (1024.0 * 1024.0),
	}

	switch btype {
	case "PE":
		arch, imports := peImports(path)
		bi.Arch = arch
		bi.Imports = imports
		extractPEVersionInfo(path, bi)
	case "ELF":
		arch, libs := elfImports(path)
		bi.Arch = arch
		bi.Libraries = libs
	case "Mach-O":
		arch, libs := machoImports(path)
		bi.Arch = arch
		bi.Libraries = libs
	}

	// Check if .NET binary
	dotnet := btype == "PE" && isDotNetBinary(path)
	bi.IsDotNet = dotnet

	if dotnet {
		// For .NET binaries: extract all strings, filter noise, pick best samples
		allStrs := extractAllStrings(path, 64*1024*1024, 6)
		bi.StringsTotal = len(allStrs)

		// Count URLs before filtering
		for _, s := range allStrs {
			if urlRe.MatchString(s) {
				bi.URLCount++
				if len(bi.SampleURLs) < 25 {
					for _, u := range urlRe.FindAllString(s, -1) {
						if len(bi.SampleURLs) >= 25 {
							break
						}
						bi.SampleURLs = append(bi.SampleURLs, u)
					}
				}
			}
		}

		// Apply .NET filtering to get meaningful sample strings
		bi.SampleStrings, bi.StringsTotal = filterDotNetStrings(path, allStrs, len(allStrs), 25)

		// Extract .NET CLR metadata
		bi.DotNetMeta = ExtractDotNetMetadata(path)
	} else {
		// Standard extraction for non-.NET binaries
		stringsTotal, urlCount, sampleURLs, sampleStrings := extractStrings(path, 64*1024*1024, 6, 25, 25)
		bi.StringsTotal = stringsTotal
		bi.URLCount = urlCount
		bi.SampleURLs = sampleURLs
		bi.SampleStrings = sampleStrings
	}

	// External tool outputs (best-effort)
	bi.ToolResults = runToolSuite(*bi)

	// Certificate info (PE/ELF only)
	if btype == "PE" || btype == "ELF" {
		if ci, err := cert.ExtractCertificates(path); err == nil && ci != nil && ci.Signer != nil {
			bi.CertSubject = ci.Signer.Subject
			bi.CertIssuer = ci.Signer.Issuer
		}
	}

	if verbose {
		if dotnet {
			fmt.Printf("  [BINARY] %s (%s .NET, %.1f MB)\n", bi.Name, bi.Type, bi.SizeMB)
		} else {
			fmt.Printf("  [BINARY] %s (%s, %.1f MB)\n", bi.Name, bi.Type, bi.SizeMB)
		}
	}

	return bi, nil
}

// Analyze scans for binaries and extracts basic metadata, imports, strings, and certs.
func Analyze(appPath string, verbose bool) []Info {
	var infos []Info

	binExts := map[string]bool{
		".exe":   true,
		".dll":   true,
		".sys":   true,
		".ocx":   true,
		".drv":   true,
		".so":    true,
		".dylib": true,
		".bin":   true,
		"":       true,
	}

	_ = filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if info.Size() < 64*1024 { // skip tiny files
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !binExts[ext] {
			return nil
		}

		btype := detectBinaryType(path)
		if btype == "" {
			return nil
		}

		bi := Info{
			Path:      path,
			Name:      filepath.Base(path),
			Type:      btype,
			SizeBytes: info.Size(),
			SizeMB:    float64(info.Size()) / (1024.0 * 1024.0),
		}

		switch btype {
		case "PE":
			arch, imports := peImports(path)
			bi.Arch = arch
			bi.Imports = imports
			extractPEVersionInfo(path, &bi)
		case "ELF":
			arch, libs := elfImports(path)
			bi.Arch = arch
			bi.Libraries = libs
		case "Mach-O":
			arch, libs := machoImports(path)
			bi.Arch = arch
			bi.Libraries = libs
		}

		// Check if .NET binary
		dotnet := btype == "PE" && isDotNetBinary(path)
		bi.IsDotNet = dotnet

		if dotnet {
			allStrs := extractAllStrings(path, 64*1024*1024, 6)
			bi.StringsTotal = len(allStrs)
			for _, s := range allStrs {
				if urlRe.MatchString(s) {
					bi.URLCount++
					if len(bi.SampleURLs) < 25 {
						for _, u := range urlRe.FindAllString(s, -1) {
							if len(bi.SampleURLs) >= 25 {
								break
							}
							bi.SampleURLs = append(bi.SampleURLs, u)
						}
					}
				}
			}
			bi.SampleStrings, bi.StringsTotal = filterDotNetStrings(path, allStrs, len(allStrs), 25)
			bi.DotNetMeta = ExtractDotNetMetadata(path)
		} else {
			stringsTotal, urlCount, sampleURLs, sampleStrings := extractStrings(path, 64*1024*1024, 6, 25, 25)
			bi.StringsTotal = stringsTotal
			bi.URLCount = urlCount
			bi.SampleURLs = sampleURLs
			bi.SampleStrings = sampleStrings
		}

		// External tool outputs (best-effort)
		bi.ToolResults = runToolSuite(bi)

		// Certificate info (PE/ELF only)
		if btype == "PE" || btype == "ELF" {
			if ci, err := cert.ExtractCertificates(path); err == nil && ci != nil && ci.Signer != nil {
				bi.CertSubject = ci.Signer.Subject
				bi.CertIssuer = ci.Signer.Issuer
			}
		}

		infos = append(infos, bi)
		if verbose {
			if dotnet {
				fmt.Printf("  [BINARY] %s (%s .NET, %.1f MB)\n", bi.Name, bi.Type, bi.SizeMB)
			} else {
				fmt.Printf("  [BINARY] %s (%s, %.1f MB)\n", bi.Name, bi.Type, bi.SizeMB)
			}
		}

		return nil
	})

	// Sort by size desc, then name
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].SizeBytes == infos[j].SizeBytes {
			return infos[i].Name < infos[j].Name
		}
		return infos[i].SizeBytes > infos[j].SizeBytes
	})

	return infos
}

func detectBinaryType(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, 4)
	if _, err := io.ReadFull(f, header); err != nil {
		return ""
	}

	if header[0] == 'M' && header[1] == 'Z' {
		return "PE"
	}
	if header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return "ELF"
	}
	if (header[0] == 0xfe && header[1] == 0xed) || (header[0] == 0xcf && header[1] == 0xfa) || (header[0] == 0xca && header[1] == 0xfe) {
		return "Mach-O"
	}

	return ""
}

func peImports(path string) (string, []string) {
	f, err := pe.Open(path)
	if err != nil {
		return "", nil
	}
	defer func() { _ = f.Close() }()

	arch := fmt.Sprintf("0x%x", f.FileHeader.Machine)
	imports, _ := f.ImportedSymbols()
	return arch, uniqueStrings(imports, 200)
}

// extractPEVersionInfo reads the VS_VERSION_INFO resource from a PE file
// and populates ProductName, ProductVersion, FileDescription, and CompanyName.
// Locates the .rsrc section via debug/pe and reads ONLY that section. Falls
// back to scanning the last 256KB when the section can't be parsed (covers
// non-standard PEs and avoids OOM on multi-hundred-MB Electron binaries
// where the resource section is far from the file tail).
func extractPEVersionInfo(path string, bi *Info) {
	keys := map[string]*string{
		"ProductName":     &bi.ProductName,
		"ProductVersion":  &bi.ProductVersion,
		"FileDescription": &bi.FileDescription,
		"CompanyName":     &bi.CompanyName,
	}

	if data := readPERsrcSection(path); data != nil {
		for key, dst := range keys {
			if val := findVersionString(data, key); val != "" {
				*dst = val
			}
		}
		// If we got at least one field from the .rsrc section, trust it.
		if bi.ProductName != "" || bi.FileDescription != "" || bi.CompanyName != "" {
			return
		}
	}

	// Fallback: tail-scan up to 256KB (preserves prior behavior for small
	// PEs where version info happens to sit at the end of the file).
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return
	}

	const maxRead = 256 * 1024
	size := fi.Size()
	offset := int64(0)
	readSize := size
	if size > maxRead {
		offset = size - maxRead
		readSize = maxRead
	}

	data := make([]byte, readSize)
	n, err := f.ReadAt(data, offset)
	if err != nil && n == 0 {
		return
	}
	data = data[:n]

	for key, dst := range keys {
		if *dst != "" {
			continue
		}
		if val := findVersionString(data, key); val != "" {
			*dst = val
		}
	}
}

// readPERsrcSection returns the raw bytes of the PE .rsrc section, or nil
// when the file isn't a parseable PE / has no .rsrc / read fails. Capped at
// 16 MB to bound memory use on pathological binaries.
func readPERsrcSection(path string) []byte {
	f, err := pe.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	for _, s := range f.Sections {
		if s.Name != ".rsrc" {
			continue
		}
		const maxRsrc = 16 * 1024 * 1024
		if s.Size > maxRsrc {
			return nil
		}
		data, err := s.Data()
		if err != nil {
			return nil
		}
		return data
	}
	return nil
}

// findVersionString searches PE binary data for a UTF-16LE encoded
// VS_VERSION_INFO string table entry.
func findVersionString(data []byte, key string) string {
	// Convert key to UTF-16LE for searching
	keyUTF16 := utf16Encode(key)
	idx := bytes.Index(data, keyUTF16)
	if idx < 0 {
		return ""
	}

	// Skip past the key, null terminator, and alignment padding
	pos := idx + len(keyUTF16)
	// Skip null terminator (2 bytes)
	if pos+2 > len(data) {
		return ""
	}
	pos += 2
	// Align to 4-byte boundary
	if pos%4 != 0 {
		pos += 4 - (pos % 4)
	}

	if pos >= len(data) {
		return ""
	}

	// Read UTF-16LE value until null terminator
	var result []byte
	for i := pos; i+1 < len(data) && i < pos+512; i += 2 {
		lo, hi := data[i], data[i+1]
		if lo == 0 && hi == 0 {
			break
		}
		if hi == 0 && lo >= 0x20 && lo < 0x7f {
			result = append(result, lo)
		} else {
			// Non-ASCII character — include as-is for basic support
			result = append(result, '?')
		}
	}
	return string(result)
}

// utf16Encode converts an ASCII string to UTF-16LE bytes.
func utf16Encode(s string) []byte {
	b := make([]byte, len(s)*2)
	for i := 0; i < len(s); i++ {
		b[i*2] = s[i]
		b[i*2+1] = 0
	}
	return b
}

func elfImports(path string) (string, []string) {
	f, err := elf.Open(path)
	if err != nil {
		return "", nil
	}
	defer func() { _ = f.Close() }()

	arch := f.Machine.String()
	libs, _ := f.ImportedLibraries()
	return arch, uniqueStrings(libs, 200)
}

func machoImports(path string) (string, []string) {
	f, err := macho.Open(path)
	if err != nil {
		return "", nil
	}
	defer func() { _ = f.Close() }()

	arch := f.Cpu.String()
	libs, _ := f.ImportedLibraries()
	return arch, uniqueStrings(libs, 200)
}

func extractStrings(path string, maxBytes int64, minLen int, maxURLs int, maxSamples int) (int, int, []string, []string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, nil, nil
	}
	defer func() { _ = f.Close() }()

	var (
		buf           = make([]byte, 64*1024)
		current       bytes.Buffer
		stringsTotal  int
		urlCount      int
		sampleURLs    []string
		sampleStrings []string
		readBytes     int64
	)

	flush := func() {
		if current.Len() >= minLen {
			stringsTotal++
			s := current.String()
			if len(sampleStrings) < maxSamples {
				sampleStrings = append(sampleStrings, s)
			}
			if urlRe.MatchString(s) {
				urlCount++
				if len(sampleURLs) < maxURLs {
					for _, u := range urlRe.FindAllString(s, -1) {
						if len(sampleURLs) >= maxURLs {
							break
						}
						sampleURLs = append(sampleURLs, u)
					}
				}
			}
		}
		current.Reset()
	}

	reader := bufio.NewReader(f)
	for {
		if maxBytes > 0 && readBytes >= maxBytes {
			break
		}
		n, err := reader.Read(buf)
		if n > 0 {
			if maxBytes > 0 && readBytes+int64(n) > maxBytes {
				n = int(maxBytes - readBytes)
			}
			readBytes += int64(n)
			for i := 0; i < n; i++ {
				b := buf[i]
				if b >= 0x20 && b <= 0x7e {
					_ = current.WriteByte(b)
				} else {
					flush()
				}
			}
		}
		if err != nil {
			break
		}
	}
	flush()

	return stringsTotal, urlCount, uniqueStrings(sampleURLs, maxURLs), uniqueStrings(sampleStrings, maxSamples)
}

func uniqueStrings(in []string, limit int) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func runToolSuite(bi Info) []ToolResult {
	results := make([]ToolResult, 0, 16)
	path := bi.Path
	// Absolutize the (untrusted) binary path so it can never be parsed as a
	// flag by the tools below (argument injection, CWE-88).
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}

	results = append(results, runTool("file", []string{"-b", path}, 4096))
	results = append(results, runTool("strings", []string{"-n", "6", path}, 16384))
	results = append(results, runTool("xxd", []string{"-l", "256", path}, 4096))
	results = append(results, runTool("hexdump", []string{"-C", "-n", "256", path}, 4096))

	switch bi.Type {
	case "ELF":
		results = append(results, runTool("readelf", []string{"-a", path}, 16384))
		results = append(results, runTool("nm", []string{"-n", path}, 16384))
		results = append(results, runTool("ldd", []string{path}, 8192))
	case "PE":
		results = append(results, runTool("objdump", []string{"-x", path}, 16384))
		results = append(results, runTool("nm", []string{"-n", path}, 16384))
	default:
		results = append(results, runTool("objdump", []string{"-x", path}, 16384))
		results = append(results, runTool("nm", []string{"-n", path}, 16384))
	}

	results = append(results, runTool("upx", []string{"-l", path}, 4096))
	results = append(results, runTool("binwalk", []string{"-B", path}, 8192))
	results = append(results, runTool("ndisasm", []string{"-b", "64", path}, 8192))

	results = append(results, runToolCommandOnly("radare2", "r2 -A <binary>"))
	results = append(results, runToolCommandOnly("rizin", "rizin -A <binary>"))
	results = append(results, runToolCommandOnly("ghidra", "analyzeHeadless <project> <analysis> -import <binary>"))
	results = append(results, runToolCommandOnly("cstool", "cstool x64 <hex bytes>"))
	results = append(results, runToolCommandOnly("retdec", "retdec-decompiler <binary>"))
	results = append(results, runToolCommandOnly("strace", "strace -o trace.txt <binary>"))
	results = append(results, runToolCommandOnly("ltrace", "ltrace -o ltrace.txt <binary>"))

	return results
}

func runTool(name string, args []string, limit int) ToolResult {
	cmdStr := name + " " + strings.Join(args, " ")
	// Resolve the tool only from PATH (exec.LookPath) to avoid running a
	// planted binary from a CWD-relative bin/ directory (CWE-426/427).
	toolPath, err := exec.LookPath(name)
	if err != nil {
		return ToolResult{Name: name, Command: cmdStr, Status: "missing"}
	}
	out, err := exec.Command(toolPath, args...).CombinedOutput()
	if err != nil {
		return ToolResult{Name: name, Command: cmdStr, Status: "error", Output: trimOutput(string(out), limit)}
	}
	return ToolResult{Name: name, Command: cmdStr, Status: "ok", Output: trimOutput(string(out), limit)}
}

func runToolCommandOnly(name, cmd string) ToolResult {
	// Resolve only from PATH; no CWD-relative bin/ fallback (CWE-426/427).
	if _, err := exec.LookPath(name); err != nil {
		return ToolResult{Name: name, Command: cmd, Status: "missing"}
	}
	return ToolResult{Name: name, Command: cmd, Status: "skipped", Output: "interactive tool; not executed"}
}

func trimOutput(s string, limit int) string {
	if limit <= 0 || len(s) <= limit {
		return s
	}
	return s[:limit] + "\n...[truncated]"
}
