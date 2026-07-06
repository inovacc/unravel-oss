package goresym

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// containsName reports whether any recovered symbol has exactly the given name.
func containsName(syms []Symbol, want string) bool {
	for _, s := range syms {
		if s.Name == want {
			return true
		}
	}
	return false
}

// TestRecoverPure_StrippedELF verifies the pure-Go pclntab parser recovers a
// real function set (names + addresses) from a `-s -w` stripped Go ELF that has
// no symtab, no DWARF, and no runtime.pclntab locator symbol.
func TestRecoverPure_StrippedELF(t *testing.T) {
	path := filepath.Join("testdata", "app_linux_stripped")
	res, err := recoverPure(context.Background(), path, Options{IncludeStdLib: true})
	if err != nil {
		t.Fatalf("recoverPure(stripped) error: %v", err)
	}
	if res == nil {
		t.Fatal("recoverPure(stripped) returned nil result")
	}
	if len(res.Symbols) < 100 {
		t.Fatalf("recovered too few symbols: got %d, want >= 100", len(res.Symbols))
	}

	// At least one name must be a real, dotted Go symbol.
	dotted := false
	addrSeen := false
	for _, s := range res.Symbols {
		if s.Name == "" {
			t.Fatalf("recovered an empty symbol name: %+v", s)
		}
		if strings.Contains(s.Name, ".") {
			dotted = true
		}
		if s.Address != 0 {
			addrSeen = true
		}
	}
	if !dotted {
		t.Error("no recovered name contains a '.' — names look implausible")
	}
	if !addrSeen {
		t.Error("no recovered symbol carries a non-zero address")
	}

	// The set must include recognizable, well-known Go functions.
	if !containsName(res.Symbols, "main.main") {
		t.Error("expected recovered set to include main.main")
	}
	if !containsName(res.Symbols, "runtime.main") {
		t.Error("expected recovered set to include the stdlib func runtime.main")
	}
	t.Logf("stripped ELF: recovered %d functions", len(res.Symbols))
}

// TestRecoverPure_StrippedELF_SkipsStdlib verifies IncludeStdLib=false drops
// runtime/stdlib names but keeps user (main.*) names.
func TestRecoverPure_StrippedELF_SkipsStdlib(t *testing.T) {
	path := filepath.Join("testdata", "app_linux_stripped")
	res, err := recoverPure(context.Background(), path, Options{IncludeStdLib: false})
	if err != nil {
		t.Fatalf("recoverPure error: %v", err)
	}
	if !containsName(res.Symbols, "main.main") {
		t.Error("expected main.main to survive stdlib filtering")
	}
	if containsName(res.Symbols, "runtime.main") {
		t.Error("runtime.main should be filtered out when IncludeStdLib=false")
	}
}

// TestRecoverPure_GarbledELF verifies recovery still works on a
// garble-obfuscated binary whose pcHeader magic is scrambled. GoReSym's
// signature scan fails here; the section-based structural locator does not.
// Names may be hashed, but the function set is still recovered.
func TestRecoverPure_GarbledELF(t *testing.T) {
	path := filepath.Join("testdata", "app_linux_garbled")
	res, err := recoverPure(context.Background(), path, Options{IncludeStdLib: true})
	if err != nil {
		t.Fatalf("recoverPure(garbled) error: %v", err)
	}
	if res == nil || len(res.Symbols) == 0 {
		t.Fatal("recoverPure(garbled) recovered no functions")
	}
	if !containsName(res.Symbols, "main.main") {
		t.Error("expected recovered set to include main.main even when garbled")
	}
	t.Logf("garbled ELF: recovered %d functions", len(res.Symbols))
}

// TestRecoverPure_NonGoInput verifies a non-Go file yields a clean error and
// never panics.
func TestRecoverPure_NonGoInput(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "not-a-binary.bin")
	if err := os.WriteFile(p, []byte("this is not a Go binary at all\x00\x01\x02"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	res, err := recoverPure(context.Background(), p, Options{})
	if err == nil {
		t.Fatal("expected an error for non-Go input, got nil")
	}
	if res != nil {
		t.Errorf("expected nil result for non-Go input, got %+v", res)
	}
}

// TestIsStdlibName_MonorepoAndGenerics guards the stdlib classifier against the
// two failure modes that collapsed a 151k-function PE down to ~300 recovered
// symbols: (1) a non-dotted monorepo root (google3/…) being misread as stdlib,
// and (2) a generic instantiation's bracketed type paths leaking into the
// package prefix. It also pins the invariants the ELF fixture relies on.
func TestIsStdlibName_MonorepoAndGenerics(t *testing.T) {
	cases := []struct {
		name    string
		stdlib  bool
		comment string
	}{
		// User / third-party code — must be KEPT (not stdlib).
		{"main.main", false, "user main"},
		{"main.init.0", false, "user main init"},
		{"github.com/pkg/errors.Wrap", false, "dotted third-party domain"},
		{"golang.org/x/sys/windows.NewLazyDLL", false, "dotted third-party domain"},
		{"google3/third_party/jetski/cli/store/store.NewStore", false, "non-dotted monorepo root"},
		{"google3/third_party/golang/github_com/openai/openai_go/v/v2/client.New", false, "vendored monorepo third-party"},
		// Bracketed generic instantiation whose type args carry monorepo paths:
		// the receiver package is stdlib "slices" and must still be dropped.
		{"slices.pdqsortCmpFunc[go.shape.struct { google3/third_party/x.a int }]", true, "generic over monorepo type, stdlib receiver"},
		// Standard library / runtime / compiler noise — must be DROPPED (stdlib).
		{"runtime.main", true, "runtime"},
		{"internal/abi.(*RegArgs).Dump", true, "internal stdlib"},
		{"net/http.(*Server).Serve", true, "stdlib slash-qualified"},
		{"crypto/x509.ParseCertificate", true, "stdlib slash-qualified"},
		{"go:textfipsend", true, "linker-generated go: symbol"},
		{"type:.eq.[]interface {}", true, "compiler-generated type: symbol"},
		{"gcWriteBarrier", true, "bare runtime asm symbol"},
		{"sigtramp", true, "bare runtime asm symbol"},
	}
	for _, tc := range cases {
		if got := isStdlibName(tc.name); got != tc.stdlib {
			t.Errorf("isStdlibName(%q) = %v, want %v (%s)", tc.name, got, tc.stdlib, tc.comment)
		}
	}
}

// TestRecoverPure_MissingPath verifies a missing file yields an error, not a panic.
func TestRecoverPure_MissingPath(t *testing.T) {
	res, err := recoverPure(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"), Options{})
	if err == nil {
		t.Fatal("expected an error for missing path, got nil")
	}
	if res != nil {
		t.Errorf("expected nil result, got %+v", res)
	}
}

// TestRecoverPure_StrippedPE exercises the PE code path (imageBase +
// VirtualAddress textStart math + the whole-file rawScan the ELF fixture never
// touches) against a committed `-s -w -trimpath` windows/amd64 fixture. It must
// recover real, dotted user function names. See testdata/README.md for the
// reproducible build command.
func TestRecoverPure_StrippedPE(t *testing.T) {
	path := filepath.Join("testdata", "app_windows_stripped.exe")
	res, err := recoverPure(context.Background(), path, Options{IncludeStdLib: true})
	if err != nil {
		t.Fatalf("recoverPure(PE) error: %v", err)
	}
	if res == nil || len(res.Symbols) == 0 {
		t.Fatal("recoverPure(PE) recovered no functions")
	}
	if !containsName(res.Symbols, "main.main") {
		t.Error("expected recovered PE set to include main.main")
	}
	// The tiny source declares main.greet and main.add — proof the funcnametab
	// walk yields real names, not just the runtime entrypoint.
	if !containsName(res.Symbols, "main.greet") || !containsName(res.Symbols, "main.add") {
		t.Error("expected recovered PE set to include the user funcs main.greet and main.add")
	}
	t.Logf("stripped PE: recovered %d functions", len(res.Symbols))
}

// TestSelectBestCandidate pins the I1 selection rule: among validated pclntab
// candidates the largest nfunc wins (so a smaller embedded/secondary table can't
// truncate recovery), and an exact nfunc tie breaks toward the header whose
// textStart matches the .text virtual address.
func TestSelectBestCandidate(t *testing.T) {
	if _, ok := selectBestCandidate(nil, 0); ok {
		t.Error("empty candidate set must return ok=false")
	}

	small := pclntabCandidate{hdr: pcHeader{nfunc: 10}}
	big := pclntabCandidate{hdr: pcHeader{nfunc: 2000}}

	// Largest nfunc wins regardless of ordering.
	for _, order := range [][]pclntabCandidate{{small, big}, {big, small}} {
		got, ok := selectBestCandidate(order, 0)
		if !ok || got.hdr.nfunc != 2000 {
			t.Fatalf("largest nfunc must win: ok=%v nfunc=%d", ok, got.hdr.nfunc)
		}
	}

	// Tie on nfunc → the textStart matching .text wins even when it is second.
	matches := pclntabCandidate{hdr: pcHeader{nfunc: 100, textStart: 0x401000}}
	other := pclntabCandidate{hdr: pcHeader{nfunc: 100, textStart: 0x900000}}
	got, _ := selectBestCandidate([]pclntabCandidate{other, matches}, 0x401000)
	if got.hdr.textStart != 0x401000 {
		t.Fatalf("tie must break toward textStart matching .text, got %#x", got.hdr.textStart)
	}
}

// makeHeaderBlob assembles a go1.18+-shaped pcHeader for tests. total sizes the
// backing slice so callers can drive both in-bounds and out-of-bounds cases.
func makeHeaderBlob(magic uint32, ptrSize int, nfunc uint64, fields map[int]uint64, total int) []byte {
	b := make([]byte, total)
	if total >= 8 {
		binary.LittleEndian.PutUint32(b[:4], magic)
		b[6] = 1 // minLC
		b[7] = byte(ptrSize)
	}
	put := func(i int, v uint64) {
		at := 8 + i*ptrSize
		if at+ptrSize > len(b) {
			return
		}
		if ptrSize == 8 {
			binary.LittleEndian.PutUint64(b[at:], v)
		} else {
			binary.LittleEndian.PutUint32(b[at:], uint32(v))
		}
	}
	put(0, nfunc)
	for i, v := range fields {
		put(i, v)
	}
	return b
}

// TestParseHeader_Malformed feeds crafted, hostile pcHeaders to the parser. Each
// must be rejected (ok=false) with no panic and no unbounded work — this is the
// #1 security surface for the recovery path.
func TestParseHeader_Malformed(t *testing.T) {
	// go1.18+ field indices used by makeHeaderBlob callers below.
	const (
		fnTextStart = 2
		fnFuncname  = 3
		fnCu        = 4
		fnPcln      = 7
	)

	cases := []struct {
		name string
		blob []byte
	}{
		{
			name: "too short for even the fixed prefix",
			blob: []byte{0xf1, 0xff, 0xff},
		},
		{
			name: "valid magic but truncated before any offset field",
			blob: makeHeaderBlob(magicGo120, 8, 3, nil, 8),
		},
		{
			name: "nonzero pad byte",
			blob: func() []byte {
				b := makeHeaderBlob(magicGo120, 8, 3, map[int]uint64{fnFuncname: 80, fnCu: 96, fnPcln: 120}, 256)
				b[4] = 0x7f
				return b
			}(),
		},
		{
			name: "implausible ptrSize",
			blob: makeHeaderBlob(magicGo120, 3, 3, nil, 256),
		},
		{
			name: "nfunc above the cap",
			blob: makeHeaderBlob(magicGo120, 8, maxFuncs+1, map[int]uint64{fnFuncname: 80, fnCu: 96, fnPcln: 120}, 256),
		},
		{
			name: "nfunc at the cap but functab runs off the end",
			// nfunc==maxFuncs passes the count check, but validHeader needs room
			// for (nfunc+1)*8 functab bytes — far beyond this small blob.
			blob: makeHeaderBlob(magicGo120, 8, maxFuncs, map[int]uint64{fnTextStart: 0x401000, fnFuncname: 80, fnCu: 96, fnPcln: 120}, 256),
		},
		{
			name: "funcname/cu offsets point out of bounds",
			blob: makeHeaderBlob(magicGo120, 8, 3, map[int]uint64{fnFuncname: 1 << 30, fnCu: 1 << 31, fnPcln: 1 << 20}, 256),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseHeader(tc.blob, true); ok {
				t.Errorf("parseHeader accepted a malformed header %q", tc.name)
			}
			// Whatever parseHeader decided, the raw-scan + build path over the
			// same bytes must not panic.
			if best, ok := rawScan(tc.blob, 0x401000); ok {
				_ = buildResult(best.data, best.hdr, 0x401000, Options{IncludeStdLib: true})
			}
		})
	}
}

// TestRawScan_GarbageAfterMagic verifies a real magic followed by garbage yields
// no candidate and never panics.
func TestRawScan_GarbageAfterMagic(t *testing.T) {
	raw := make([]byte, 128)
	binary.LittleEndian.PutUint32(raw[:4], magicGo120)
	for i := 4; i < len(raw); i++ {
		raw[i] = 0xAA
	}
	if _, ok := rawScan(raw, 0x401000); ok {
		t.Error("rawScan validated a magic followed by pure garbage")
	}

	// Truncated .gopclntab-style blob (magic but nothing after) must also fail.
	if _, ok := rawScan([]byte{0xf1, 0xff, 0xff, 0xff}, 0); ok {
		t.Error("rawScan validated a bare truncated magic")
	}
}

// FuzzRecoverPure fuzzes the header/parse path directly (parseHeader → rawScan →
// buildResult), which is where a hostile pclntab does its damage. It asserts the
// path never panics or OOMs on arbitrary bytes; buildResult is invoked in the
// same body when a header validates, so malformed-but-accepted headers are
// exercised end-to-end. Fuzzing the exported recoverPure via a temp file would
// only add per-iteration file IO without reaching deeper code.
func FuzzRecoverPure(f *testing.F) {
	f.Add(append([]byte{0xf1, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0}, 64)...))
	f.Add(makeHeaderBlob(magicGo120, 8, 3, map[int]uint64{3: 80, 4: 96, 7: 120}, 256))
	f.Add([]byte("\x7fELF not really an elf at all"))
	f.Add(bytes.Repeat([]byte{0xff}, 256))
	f.Fuzz(func(t *testing.T, data []byte) {
		if hdr, ok := parseHeader(data, false); ok {
			_ = buildResult(data, hdr, 0x401000, Options{IncludeStdLib: true})
		}
		if best, ok := rawScan(data, 0x401000); ok {
			_ = buildResult(best.data, best.hdr, 0x401000, Options{IncludeStdLib: true})
		}
	})
}
