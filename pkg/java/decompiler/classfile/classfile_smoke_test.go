/*
Copyright (c) 2026 Security Research
*/
package classfile

import "testing"

func TestParse_TooShort(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Error("expected error on nil")
	}
	if _, err := Parse([]byte{0xCA, 0xFE, 0xBA, 0xBE}); err == nil {
		t.Error("expected error on header-only buffer")
	}
}

func TestParse_BadMagic(t *testing.T) {
	// Wrong magic — must be 0xCAFEBABE.
	data := make([]byte, 32)
	data[0] = 0xDE
	data[1] = 0xAD
	data[2] = 0xBE
	data[3] = 0xEF
	if _, err := Parse(data); err == nil {
		t.Error("expected error on bad magic")
	}
}
