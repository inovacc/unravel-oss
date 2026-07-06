/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestCanonicalizeObfuscatedPair(t *testing.T) {
	a, err := os.ReadFile("testdata/kb-obfuscated-pair/a.js")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/kb-obfuscated-pair/b.js")
	if err != nil {
		t.Fatal(err)
	}
	ha, bypA := Canonicalize(a)
	hb, bypB := Canonicalize(b)
	if bypA || bypB {
		t.Fatalf("did not expect bypass on small fixture (a=%v b=%v)", bypA, bypB)
	}
	if ha != hb {
		t.Fatalf("expected identical canonical hashes\n  a=%s\n  b=%s", ha, hb)
	}
}

func TestCanonicalizeBypassLargeInput(t *testing.T) {
	big := make([]byte, maxCanonicalizeSize+1)
	for i := range big {
		big[i] = 'a'
	}
	h, bypassed := Canonicalize(big)
	if !bypassed {
		t.Fatal("expected bypassed=true for >4 MiB input")
	}
	want := sha256.Sum256(big)
	if h != hex.EncodeToString(want[:]) {
		t.Fatal("expected raw-bytes SHA-256 in bypass mode")
	}
}

func TestCanonicalizeWhitelistPreserved(t *testing.T) {
	src := []byte(`document.getElementById("x");`)
	out := tokenizeAndRename(stripComments(string(src)))
	if !strings.Contains(out, "document.getElementById") {
		t.Fatalf("whitelist names must survive: %s", out)
	}
}

func TestCanonicalizeCommentsStripped(t *testing.T) {
	a := []byte(`var x = 1; // line comment`)
	b := []byte(`/* block */ var x = 1;`)
	ha, _ := Canonicalize(a)
	hb, _ := Canonicalize(b)
	if ha != hb {
		t.Fatalf("comments should not affect canonical hash:\n  a=%s\n  b=%s", ha, hb)
	}
}

func TestCanonicalizeIdentifiersRenamedStably(t *testing.T) {
	a := []byte(`var apple = 1; var banana = apple;`)
	b := []byte(`var x = 1; var y = x;`)
	ha, _ := Canonicalize(a)
	hb, _ := Canonicalize(b)
	if ha != hb {
		t.Fatalf("identifier-rename invariance broken:\n  a=%s\n  b=%s", ha, hb)
	}
}

func TestCanonicalizeStringLiteralsPreserved(t *testing.T) {
	// Different string contents must produce different hashes.
	a := []byte(`var x = "secret-A";`)
	b := []byte(`var x = "secret-B";`)
	ha, _ := Canonicalize(a)
	hb, _ := Canonicalize(b)
	if ha == hb {
		t.Fatal("string literals must be preserved (and distinguish hashes)")
	}
}
