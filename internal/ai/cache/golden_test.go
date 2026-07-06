/*
Copyright (c) 2026 Security Research

Golden vectors freezing sha256(prompt || 0x00 || modelID) byte-for-byte.
RESEARCH Pitfall 1: any future drift in Key() must invalidate every cached
file under store.CacheDir(); these tests catch byte-level drift instantly.

Vectors captured via:

	printf 'hello\x00claude-3-5-sonnet-20241022' | sha256sum
	printf 'script-body\x00model-id'              | sha256sum
	printf '\x00'                                  | sha256sum
	printf 'a\x00bc'                               | sha256sum
	printf 'ab\x00c'                               | sha256sum
*/
package cache

import "testing"

// Frozen sha256 hex vectors. NEVER recompute at test time.
const (
	wantHelloModel  = "575364b81e6587545241ccb1ea694449d1a3ff47fcaccb8956d086761ebc982b"
	wantFridaPair   = "70c9b58ab6ec40d7573b9171edb6a6d386055ba69d355017f8137758b2f03d34"
	wantEmptyEmpty  = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
	wantSepCollideA = "40bb547d936bbd31318ee37ac8799e7ecbb22eda2651f65e3214bffb8ce97bb4" // Key("a","bc")
	wantSepCollideB = "6c032e631d39a14d85aff7e319546af701e26c97b57ca95fbfe9c6ba855f67bf" // Key("ab","c")
)

func TestKey_GoldenForensic(t *testing.T) {
	got := Key("hello", "claude-3-5-sonnet-20241022")
	if got != wantHelloModel {
		t.Fatalf("forensic golden drift:\n got=  %s\n want= %s", got, wantHelloModel)
	}
}

func TestKey_GoldenFrida(t *testing.T) {
	got := Key("script-body", "model-id")
	if got != wantFridaPair {
		t.Fatalf("frida golden drift:\n got=  %s\n want= %s", got, wantFridaPair)
	}
}

func TestKey_GoldenEmpty(t *testing.T) {
	got := Key("", "")
	if got != wantEmptyEmpty {
		t.Fatalf("empty golden drift:\n got=  %s\n want= %s", got, wantEmptyEmpty)
	}
}

func TestKey_SeparatorCollision(t *testing.T) {
	// Without the 0x00 separator, Key("a","bc") and Key("ab","c") would
	// hash the same byte stream "abc" and collide.
	a := Key("a", "bc")
	b := Key("ab", "c")
	if a == b {
		t.Fatalf("separator collision: Key(\"a\",\"bc\") == Key(\"ab\",\"c\") = %s", a)
	}
	if a != wantSepCollideA {
		t.Fatalf("Key(\"a\",\"bc\") drift:\n got=  %s\n want= %s", a, wantSepCollideA)
	}
	if b != wantSepCollideB {
		t.Fatalf("Key(\"ab\",\"c\") drift:\n got=  %s\n want= %s", b, wantSepCollideB)
	}
}
