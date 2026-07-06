/*
Copyright (c) 2026 Security Research
*/
package clrtok

import "testing"

func TestToken_BitMath(t *testing.T) {
	tests := []struct {
		name      string
		tok       Token
		wantTable byte
		wantRow   uint32
	}{
		{"methoddef row 1", 0x06000001, 0x06, 1},
		{"typedef row 0x123", 0x02000123, 0x02, 0x123},
		{"userstring high rid", 0x70000005, 0x70, 5},
		{"max rid", 0x0AFFFFFF, 0x0A, 0xFFFFFF},
		{"nil token", 0x00000000, 0x00, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.TableID(); got != tt.wantTable {
				t.Errorf("TableID() = %#x, want %#x", got, tt.wantTable)
			}
			if got := tt.tok.RowID(); got != tt.wantRow {
				t.Errorf("RowID() = %#x, want %#x", got, tt.wantRow)
			}
		})
	}
}

func TestTbl_Constants(t *testing.T) {
	if TblMethodDef != 0x06 {
		t.Errorf("TblMethodDef = %#x, want 0x06", TblMethodDef)
	}
	// Spot-check the rest of the canonical table ids.
	pairs := []struct {
		name string
		got  byte
		want byte
	}{
		{"TblModule", TblModule, 0x00},
		{"TblTypeRef", TblTypeRef, 0x01},
		{"TblTypeDef", TblTypeDef, 0x02},
		{"TblField", TblField, 0x04},
		{"TblParam", TblParam, 0x08},
		{"TblMemberRef", TblMemberRef, 0x0A},
		{"TblTypeSpec", TblTypeSpec, 0x1B},
		{"TblMethodSpec", TblMethodSpec, 0x2B},
		{"TblUserString", TblUserString, 0x70},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Errorf("%s = %#x, want %#x", p.name, p.got, p.want)
		}
	}
}
