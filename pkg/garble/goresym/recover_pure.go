package goresym

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// recover_pure.go is the default, dependency-free symbol-recovery backend. It
// parses the Go runtime pclntab (function-name/line table) directly out of a
// stripped or garble-obfuscated binary — no external tool, no cgo, no build
// tags. It works where the classic symbol table is gone because the pclntab is
// an intrinsic runtime structure Go always emits so the runtime can produce
// stack traces; stripping (-s -w) and garble leave it in place (garble only
// scrambles the pcHeader magic, not the table layout).
//
// The parser is deliberately bounded and panic-safe: every field read is
// bounds-checked, absurd function counts are rejected, and a top-level
// recover() converts any residual panic on malformed input into a normal error.

// errNoPclntab is the sentinel returned when no valid Go pclntab/pcHeader can be
// located in the binary. It is a normal (non-panic) error, distinct from
// ErrNotImplemented, so callers can tell "this isn't a recoverable Go binary"
// apart from "the backend is unavailable".
var errNoPclntab = errors.New("goresym: no Go pclntab found in binary")

// pcHeader magic values, one per pclntab format era this parser can actually
// walk. The low byte increments as the on-disk layout evolves; garble replaces
// the magic with a random value but keeps the surrounding structure intact (see
// the section-based locator).
//
// The pre-go1.16 magic (0xfffffffb, the "go1.2" era) is deliberately NOT listed.
// That era used a fundamentally different pcHeader/functab layout with none of
// the nfunc + offset-table fields decoded below, so accepting its magic would
// decode garbage and only ever produce a silent no-op (validHeader rejects the
// mis-read fields anyway). We support go1.16/1.17 (names-only, magicGo116) and
// go1.18+ (full functab walk, magicGo118/magicGo120).
const (
	magicGo120 uint32 = 0xfffffff1 // Go 1.20+
	magicGo118 uint32 = 0xfffffff0 // Go 1.18 / 1.19
	magicGo116 uint32 = 0xfffffffa // Go 1.16 / 1.17
)

// maxFuncs caps nfunc to reject a corrupt/hostile header claiming an absurd
// function count before we allocate or iterate.
const maxFuncs = 5_000_000

// maxBinarySize caps the whole-file read in loadBinary. It matches the process
// GOMEMLIMIT (2 GiB) so a corrupt/hostile file claiming a multi-GB size cannot
// drive an unbounded read and OOM the host; real analysis targets sit far below
// this ceiling.
const maxBinarySize = 2 << 30

// pcHeader holds the decoded, validated pcHeader fields we need, normalised
// across the supported format eras.
type pcHeader struct {
	ptrSize     int
	nfunc       int
	textStart   uint64 // moduledata.text; often 0 on ELF (filled from the text section)
	funcnameOff int    // offset of funcnametab from the pcHeader base
	cuOff       int    // offset of cutab (== end of funcnametab)
	pclnOff     int    // offset of the functab array from the pcHeader base
	hasFunctab  bool   // true for the go1.18+ layout we can walk for addresses
}

// binMeta carries the format-independent facts the locator extracts.
type binMeta struct {
	raw    []byte // whole file, for the raw magic scan
	blobs  []blob // named pclntab-candidate sections, priority order
	textVA uint64 // .text virtual address, used when header textStart is 0
}

// blob is a candidate byte region that may begin with a pcHeader.
type blob struct {
	name string
	data []byte
}

// recoverPure parses the pclntab of the binary at path and returns the
// recovered function symbols. It never panics: malformed input yields a wrapped
// error. A genuine "no pclntab" outcome returns errNoPclntab (not
// ErrNotImplemented).
func recoverPure(_ context.Context, path string, opts Options) (res *Result, err error) {
	if path == "" {
		return nil, fmt.Errorf("goresym: path is required")
	}
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("goresym: pure recovery panicked on %s: %v", path, r)
		}
	}()

	meta, err := loadBinary(path)
	if err != nil {
		return nil, err
	}

	// 1. Named-section locator (tolerates a scrambled/garbled magic because it
	//    trusts the section boundary and validates by structure, not by magic).
	//    Gather every section that parses and keep the most plausible table
	//    (largest validated nfunc) rather than the first hit — a binary can carry
	//    a smaller embedded/secondary pclntab that would otherwise truncate
	//    recovery.
	var named []pclntabCandidate
	for _, b := range meta.blobs {
		if hdr, ok := parseHeader(b.data, false); ok {
			named = append(named, pclntabCandidate{data: b.data, hdr: hdr})
		}
	}
	if best, ok := selectBestCandidate(named, meta.textVA); ok {
		return buildResult(best.data, best.hdr, meta.textVA, opts), nil
	}

	// 2. Whole-file raw scan for a known magic (the PE path, where the pclntab
	//    lives in an unnamed .rdata region). Strict validation rejects the many
	//    false magic hits across a large file; among the survivors we again keep
	//    the largest table.
	if best, ok := rawScan(meta.raw, meta.textVA); ok {
		return buildResult(best.data, best.hdr, meta.textVA, opts), nil
	}

	return nil, errNoPclntab
}

// loadBinary reads the file and, by sniffing the magic, extracts the
// pclntab-candidate sections and the text virtual address for the matching
// object format.
func loadBinary(path string) (*binMeta, error) {
	// os.ReadFile pulls the whole binary into memory on purpose: the raw scan
	// (PE path) needs a single contiguous view, and reusing each format's
	// ReaderAt would mean re-reading sections piecemeal. Guard it with a stat so
	// a corrupt/hostile size can't drive an unbounded read — see maxBinarySize.
	if fi, statErr := os.Stat(path); statErr == nil && fi.Size() > maxBinarySize {
		return nil, fmt.Errorf("goresym: %s is %d bytes, exceeds the %d-byte cap: %w", path, fi.Size(), maxBinarySize, errNoPclntab)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("goresym: reading %s: %w", path, err)
	}
	if len(raw) < 16 {
		return nil, fmt.Errorf("goresym: %s too small to be a binary: %w", path, errNoPclntab)
	}

	switch {
	case bytes.HasPrefix(raw, []byte("\x7fELF")):
		return loadELF(path, raw)
	case bytes.HasPrefix(raw, []byte("MZ")):
		return loadPE(path, raw)
	default:
		if m, err := loadMachO(path, raw); err == nil {
			return m, nil
		}
		return nil, fmt.Errorf("goresym: %s is not a recognised ELF/PE/Mach-O binary: %w", path, errNoPclntab)
	}
}

func loadELF(path string, raw []byte) (*binMeta, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("goresym: parsing ELF %s: %w", path, err)
	}
	defer f.Close()

	meta := &binMeta{raw: raw}
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS {
			continue
		}
		if s.Name == ".text" {
			meta.textVA = s.Addr
		}
		if isPclntabSection(s.Name) {
			if d, derr := s.Data(); derr == nil {
				meta.blobs = append(meta.blobs, blob{name: s.Name, data: d})
			}
		}
	}
	return meta, nil
}

func loadPE(path string, raw []byte) (*binMeta, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("goresym: parsing PE %s: %w", path, err)
	}
	defer f.Close()

	var imageBase uint64
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	}

	meta := &binMeta{raw: raw}
	for _, s := range f.Sections {
		if s.Name == ".text" {
			meta.textVA = imageBase + uint64(s.VirtualAddress)
		}
		if isPclntabSection(s.Name) {
			if d, derr := s.Data(); derr == nil {
				meta.blobs = append(meta.blobs, blob{name: s.Name, data: d})
			}
		}
	}
	return meta, nil
}

func loadMachO(path string, raw []byte) (*binMeta, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("goresym: parsing Mach-O %s: %w", path, err)
	}
	defer f.Close()

	meta := &binMeta{raw: raw}
	for _, s := range f.Sections {
		if s.Name == "__text" {
			meta.textVA = s.Addr
		}
		if isPclntabSection(s.Name) {
			if d, derr := s.Data(); derr == nil {
				meta.blobs = append(meta.blobs, blob{name: s.Name, data: d})
			}
		}
	}
	return meta, nil
}

// isPclntabSection reports whether a section name denotes the Go pclntab across
// the three object formats (ELF ".gopclntab", Mach-O "__gopclntab", and any
// vendor variant that still carries the "gopclntab" token).
func isPclntabSection(name string) bool {
	return strings.Contains(name, "gopclntab")
}

// parseHeader decodes and validates a pcHeader at the start of blob. When
// requireKnownMagic is false the magic is ignored (garble scrambles it) and the
// header is accepted purely on structural grounds, which is why the field
// ordering and bounds checks below must be strict.
func parseHeader(blob []byte, requireKnownMagic bool) (pcHeader, bool) {
	if len(blob) < 8 {
		return pcHeader{}, false
	}
	magic := binary.LittleEndian.Uint32(blob[:4])
	known := magic == magicGo120 || magic == magicGo118 || magic == magicGo116
	if requireKnownMagic && !known {
		return pcHeader{}, false
	}
	// pad1, pad2 must be zero; minLC (pc quantum) and ptrSize must be plausible.
	if blob[4] != 0 || blob[5] != 0 {
		return pcHeader{}, false
	}
	minLC := blob[6]
	ptrSize := int(blob[7])
	if minLC != 1 && minLC != 2 && minLC != 4 {
		return pcHeader{}, false
	}
	if ptrSize != 4 && ptrSize != 8 {
		return pcHeader{}, false
	}

	readField := func(i int) (uint64, bool) {
		at := 8 + i*ptrSize
		if at+ptrSize > len(blob) {
			return 0, false
		}
		if ptrSize == 8 {
			return binary.LittleEndian.Uint64(blob[at:]), true
		}
		return uint64(binary.LittleEndian.Uint32(blob[at:])), true
	}

	// Field ordering differs only by the textStart field, which go1.18 added.
	// Unknown magics (garble) are assumed to use the modern (go1.18+) layout —
	// the layout garble targets — and are rejected by validation otherwise.
	old1617 := magic == magicGo116
	textIdx, funcnameIdx, cuIdx, pclnIdx := 2, 3, 4, 7
	if old1617 {
		textIdx, funcnameIdx, cuIdx, pclnIdx = -1, 2, 3, 6
	}

	nfunc64, ok := readField(0)
	if !ok {
		return pcHeader{}, false
	}
	if nfunc64 == 0 || nfunc64 > maxFuncs {
		return pcHeader{}, false
	}
	funcnameOff, ok1 := readField(funcnameIdx)
	cuOff, ok2 := readField(cuIdx)
	pclnOff, ok3 := readField(pclnIdx)
	if !ok1 || !ok2 || !ok3 {
		return pcHeader{}, false
	}
	var textStart uint64
	if textIdx >= 0 {
		textStart, _ = readField(textIdx)
	}

	hdr := pcHeader{
		ptrSize:     ptrSize,
		nfunc:       int(nfunc64),
		textStart:   textStart,
		funcnameOff: int(funcnameOff),
		cuOff:       int(cuOff),
		pclnOff:     int(pclnOff),
		// go1.16/1.17 (magicGo116) uses a functab/_func encoding we don't walk, so
		// it falls back to names-only; go1.18+ (and unknown/garbled magics, which
		// we assume use the modern layout) get the full functab walk.
		hasFunctab: !old1617,
	}
	if !validHeader(hdr, blob) {
		return pcHeader{}, false
	}
	return hdr, true
}

// validHeader enforces that the table offsets are in-bounds, ascending, and
// point at a funcnametab whose first byte looks like a real symbol name. These
// checks reject the many spurious magic matches a raw file scan produces.
func validHeader(h pcHeader, blob []byte) bool {
	if h.funcnameOff <= 0 || h.cuOff <= h.funcnameOff || h.cuOff > len(blob) {
		return false
	}
	if h.pclnOff <= 0 || h.pclnOff >= len(blob) {
		return false
	}
	if h.hasFunctab {
		// Need room for nfunc+1 functab entries of 8 bytes each.
		if h.pclnOff+(h.nfunc+1)*8 > len(blob) {
			return false
		}
	}
	// First funcnametab byte should start a printable, plausible symbol name.
	first := blob[h.funcnameOff]
	return isNameByte(first)
}

func isNameByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b == '_' || b == '.' || b == '*' || b == '(' || b == '/':
		return true
	default:
		return false
	}
}

// pclntabCandidate is one validated pcHeader together with the byte region that
// begins with it. recoverPure gathers every candidate a locator produces and
// picks the most plausible one via selectBestCandidate.
type pclntabCandidate struct {
	data []byte
	hdr  pcHeader
}

// selectBestCandidate chooses the most plausible pclntab among the validated
// candidates. Primary key: the largest validated nfunc — a truncated or
// secondary embedded table carries fewer functions than the runtime's real
// pclntab. Tie-break: prefer the header whose textStart matches the binary's
// .text virtual address, the strongest signal that this is the genuine runtime
// table. Returns ok=false for an empty candidate set.
func selectBestCandidate(cands []pclntabCandidate, textVA uint64) (pclntabCandidate, bool) {
	if len(cands) == 0 {
		return pclntabCandidate{}, false
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if betterCandidate(c, best, textVA) {
			best = c
		}
	}
	return best, true
}

// betterCandidate reports whether c should displace best: more functions wins,
// and on an exact nfunc tie the one whose textStart matches .text wins.
func betterCandidate(c, best pclntabCandidate, textVA uint64) bool {
	if c.hdr.nfunc != best.hdr.nfunc {
		return c.hdr.nfunc > best.hdr.nfunc
	}
	cMatch := textVA != 0 && c.hdr.textStart == textVA
	bMatch := textVA != 0 && best.hdr.textStart == textVA
	return cMatch && !bMatch
}

// rawScan sweeps the whole file for each known pcHeader magic, strictly
// validates every hit, and returns the most plausible candidate (largest
// validated nfunc, tie-broken toward a textStart matching .text). Used for PE
// binaries where the pclntab is embedded in an unnamed .rdata region and a large
// file yields many spurious magic matches.
func rawScan(raw []byte, textVA uint64) (pclntabCandidate, bool) {
	var cands []pclntabCandidate
	for _, magic := range []uint32{magicGo120, magicGo118, magicGo116} {
		var mb [4]byte
		binary.LittleEndian.PutUint32(mb[:], magic)
		idx := 0
		for {
			p := bytes.Index(raw[idx:], mb[:])
			if p < 0 {
				break
			}
			off := idx + p
			idx = off + 1
			if hdr, ok := parseHeader(raw[off:], true); ok {
				cands = append(cands, pclntabCandidate{data: raw[off:], hdr: hdr})
			}
		}
	}
	return selectBestCandidate(cands, textVA)
}

// buildResult walks the functab (go1.18+) or, for older layouts, splits the
// funcnametab, projecting each recovered function onto a Symbol. blob begins at
// the pcHeader; all header offsets are relative to it.
func buildResult(blob []byte, h pcHeader, textVA uint64, opts Options) *Result {
	textStart := h.textStart
	if textStart == 0 {
		textStart = textVA
	}
	if h.cuOff > len(blob) || h.funcnameOff >= h.cuOff {
		return &Result{}
	}
	funcnametab := blob[h.funcnameOff:h.cuOff]

	res := &Result{}
	if h.hasFunctab {
		appendFromFunctab(res, blob, funcnametab, h, textStart, opts)
	} else {
		appendFromNametab(res, funcnametab, opts)
	}
	return res
}

// appendFromFunctab walks the go1.18+ functab: each 8-byte entry is
// {entryoff uint32, funcoff uint32}; the _func at blob[pclnOff+funcoff] begins
// with {entryOff uint32, nameOff int32}; the name is funcnametab[nameOff].
func appendFromFunctab(res *Result, blob, funcnametab []byte, h pcHeader, textStart uint64, opts Options) {
	for i := 0; i < h.nfunc; i++ {
		ep := h.pclnOff + i*8
		if ep+8 > len(blob) {
			break
		}
		funcoff := binary.LittleEndian.Uint32(blob[ep+4:])
		fb := h.pclnOff + int(funcoff)
		if fb < 0 || fb+8 > len(blob) {
			continue
		}
		entryOff := binary.LittleEndian.Uint32(blob[fb:])
		nameOff := int32(binary.LittleEndian.Uint32(blob[fb+4:]))
		name := nameAt(funcnametab, nameOff)
		if name == "" {
			continue
		}
		if !opts.IncludeStdLib && isStdlibName(name) {
			continue
		}
		var addr uint64
		if textStart != 0 {
			addr = textStart + uint64(entryOff)
		}
		res.Symbols = append(res.Symbols, Symbol{Name: name, Address: addr})
	}
}

// appendFromNametab is the names-only fallback for the go1.16/1.17 layout, whose
// functab/_func encoding differs; it emits every distinct null-terminated name
// in funcnametab with a zero address.
func appendFromNametab(res *Result, funcnametab []byte, opts Options) {
	for _, part := range bytes.Split(funcnametab, []byte{0}) {
		if len(part) == 0 {
			continue
		}
		name := string(part)
		if !opts.IncludeStdLib && isStdlibName(name) {
			continue
		}
		res.Symbols = append(res.Symbols, Symbol{Name: name})
	}
}

// nameAt returns the null-terminated name at index off in funcnametab, or "".
func nameAt(funcnametab []byte, off int32) string {
	if off < 0 || int(off) >= len(funcnametab) {
		return ""
	}
	b := funcnametab[off:]
	if z := bytes.IndexByte(b, 0); z >= 0 {
		b = b[:z]
	}
	if len(b) == 0 {
		return ""
	}
	return string(b)
}

// stdlibRoots is the set of top-level import-path segments that belong to the
// Go standard library (the directories under GOROOT/src). Classification keys
// off this set rather than the old "first segment has no dot" heuristic, which
// silently misclassified monorepo layouts: a Bazel/blaze-style build vendors
// all first- and third-party code under a non-dotted root such as "google3/…",
// so "google3/third_party/foo/bar.Baz" has first segment "google3" (no dot) and
// was wrongly treated as stdlib — dropping essentially the entire application.
//
// MAINTENANCE: this whitelist must be updated whenever a Go release adds a new
// top-level stdlib package directory (e.g. the recent "iter", "unique", "weak").
// A missing entry only means a real stdlib package leaks through as user code
// (over-inclusion), never a crash. KNOWN EDGE CASE: a bare single-word module
// path with no dot and no slash (module "myapp", symbol "myapp.Run") is
// indistinguishable from a bare runtime/asm symbol and is classified as stdlib
// (dropped when IncludeStdLib=false); such modules are rare in practice.
var stdlibRoots = map[string]bool{
	"archive": true, "arena": true, "bufio": true, "builtin": true, "bytes": true,
	"cmd": true, "cmp": true, "compress": true, "container": true, "context": true,
	"crypto": true, "database": true, "debug": true, "embed": true, "encoding": true,
	"errors": true, "expvar": true, "flag": true, "fmt": true, "go": true, "hash": true,
	"html": true, "image": true, "index": true, "internal": true, "io": true, "iter": true,
	"log": true, "maps": true, "math": true, "mime": true, "net": true, "os": true,
	"path": true, "plugin": true, "reflect": true, "regexp": true, "runtime": true,
	"slices": true, "sort": true, "strconv": true, "strings": true, "structs": true,
	"sync": true, "syscall": true, "testing": true, "text": true, "time": true,
	"unicode": true, "unique": true, "unsafe": true, "vendor": true, "weak": true,
}

// isStdlibName reports whether a Go symbol name belongs to the standard library
// or runtime (as opposed to the user's main package or a third-party module).
//
// The rules, in order:
//   - "main"/"main." is always user code.
//   - A compiler/linker-generated symbol (package segment carries a ':', e.g.
//     "go:textfipsend", "type:.eq.…") is runtime noise → stdlib.
//   - A dotted first path segment is a third-party module domain
//     (github.com/…, golang.org/…) → user code.
//   - A slash-qualified path is stdlib only if its first segment is a known
//     stdlib root (net/http, crypto/x509, internal/abi); any other multi-segment
//     root (google3/…) is user/third-party code.
//   - A bare, single-segment name is either a stdlib package func (slices.Sort)
//     or an unqualified runtime/asm/linker symbol (gcWriteBarrier, sigtramp,
//     _cgoexp_…) — both are noise → stdlib.
func isStdlibName(name string) bool {
	pkg := packagePrefix(name)
	if pkg == "main" || strings.HasPrefix(pkg, "main.") {
		return false
	}
	firstSeg := pkg
	if i := strings.IndexByte(pkg, '/'); i >= 0 {
		firstSeg = pkg[:i]
	}
	if strings.IndexByte(firstSeg, ':') >= 0 {
		return true
	}
	if strings.Contains(firstSeg, ".") {
		return false
	}
	if strings.IndexByte(pkg, '/') >= 0 {
		return stdlibRoots[firstSeg]
	}
	return true
}

// packagePrefix extracts the import-path portion of a Go symbol name, stripping
// a leading method-receiver group and cutting at the function-name boundary.
func packagePrefix(name string) string {
	n := name
	// Generic instantiations carry their type arguments in a trailing "[…]"
	// whose contents include fully-qualified type paths (with their own '/' and
	// '.' separators). The package/func portion is always before the first '[';
	// cut there so those bracketed paths cannot leak into the prefix and defeat
	// classification (e.g. "slices.pdqsortCmpFunc[go.shape.struct{ github.com/… }]"
	// must resolve to package "slices", not to a bracketed third-party path).
	if i := strings.IndexByte(n, '['); i >= 0 {
		n = n[:i]
	}
	// Method on a (possibly pointer) receiver: "pkg.(*T).Method" — the package
	// is what precedes the first ".(".
	if i := strings.Index(n, ".("); i >= 0 {
		return n[:i]
	}
	// Otherwise cut after the last path separator, then at the first dot.
	slash := strings.LastIndexByte(n, '/')
	base := n
	prefix := ""
	if slash >= 0 {
		prefix = n[:slash+1]
		base = n[slash+1:]
	}
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		return prefix + base[:dot]
	}
	return prefix + base
}
