package hashutil

import "testing"

func TestHashHex(t *testing.T) {
	got := HashHex([]byte("abc"))
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("HashHex(\"abc\") = %q; want %q", got, want)
	}
	if len(got) != 64 {
		t.Errorf("HashHex length = %d; want 64", len(got))
	}
}

func TestHashHex8(t *testing.T) {
	got := HashHex8([]byte("abc"))
	if len(got) != 8 {
		t.Errorf("HashHex8 length = %d; want 8", len(got))
	}
	if got != "ba7816bf" {
		t.Errorf("HashHex8(\"abc\") = %q; want \"ba7816bf\"", got)
	}
}

func TestHashHex16(t *testing.T) {
	got := HashHex16([]byte("abc"))
	if len(got) != 16 {
		t.Errorf("HashHex16 length = %d; want 16", len(got))
	}
	if got != "ba7816bf8f01cfea" {
		t.Errorf("HashHex16(\"abc\") = %q; want \"ba7816bf8f01cfea\"", got)
	}
}

func TestHashHexString(t *testing.T) {
	if HashHexString("abc") != HashHex([]byte("abc")) {
		t.Error("HashHexString != HashHex byte form")
	}
	if HashHex16String("abc") != HashHex16([]byte("abc")) {
		t.Error("HashHex16String != HashHex16 byte form")
	}
}

func TestHashHex_Deterministic(t *testing.T) {
	a := HashHex16([]byte("whatsapp|windows-msix"))
	b := HashHex16([]byte("whatsapp|windows-msix"))
	if a != b {
		t.Errorf("HashHex16 not deterministic: %q vs %q", a, b)
	}
	c := HashHex16([]byte("whatsapp|windows-pe"))
	if a == c {
		t.Errorf("HashHex16 collision on different input: %q", a)
	}
}
