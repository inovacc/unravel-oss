/*
Copyright (c) 2026 Security Research
*/
package reader

import "testing"

func TestNewReader_Empty(t *testing.T) {
	r := NewReader(nil)
	if r == nil {
		t.Fatal("NewReader returned nil")
	}
	r2 := NewReader([]byte{})
	if r2 == nil {
		t.Fatal("NewReader([]) returned nil")
	}
}

func TestReader_BasicReads(t *testing.T) {
	r := NewReader([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	u8, err := r.ReadU1()
	if err != nil {
		t.Fatalf("ReadU1: %v", err)
	}
	if u8 != 0x01 {
		t.Errorf("u8: got %#x want 0x01", u8)
	}
	u16, err := r.ReadU2()
	if err != nil {
		t.Fatalf("ReadU2: %v", err)
	}
	if u16 != 0x0203 {
		t.Errorf("u16: got %#x want 0x0203", u16)
	}
	u32, err := r.ReadU4()
	if err != nil {
		t.Fatalf("ReadU4: %v", err)
	}
	if u32 != 0x04050607 {
		t.Errorf("u32: got %#x want 0x04050607", u32)
	}
}

func TestReader_EOF(t *testing.T) {
	r := NewReader([]byte{0x01})
	_, _ = r.ReadU1()
	if _, err := r.ReadU1(); err == nil {
		t.Error("expected EOF on second read of 1-byte buffer")
	}
}
