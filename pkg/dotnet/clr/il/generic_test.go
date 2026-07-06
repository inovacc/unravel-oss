/*
Copyright (c) 2026 Security Research
*/
package il

import "testing"

func TestDisassemble_GenericTokensDegrade(t *testing.T) {
	// call MethodSpec(0x2B000001) ; ldftn TypeSpec(0x1B000002) ; ret.
	res := stubResolver{} // resolver returns "" → forces degradation path
	code := []byte{
		0x28, 0x01, 0x00, 0x00, 0x2B, // call 0x2B000001 (MethodSpec)
		0xFE, 0x06, 0x02, 0x00, 0x00, 0x1B, // ldftn 0x1B000002 (TypeSpec) — prefixed
		0x2A, // ret
	}
	mb := &MethodBody{Code: code, MaxStack: 8}
	text, callees, _ := Disassemble(mb, res)

	if !contains(text, "/* token 0x2b000001 */") {
		t.Errorf("MethodSpec not degraded in text:\n%s", text)
	}
	if !contains(text, "/* token 0x1b000002 */") {
		t.Errorf("TypeSpec not degraded in text:\n%s", text)
	}
	// Both are call-graph edges (call, ldftn) but render as raw tokens; tokens still recorded.
	if len(callees) != 2 {
		t.Fatalf("callees = %d, want 2 (raw MethodSpec + TypeSpec edges still tracked)", len(callees))
	}
	if uint32(callees[0]) != 0x2B000001 || uint32(callees[1]) != 0x1B000002 {
		t.Errorf("callees = %#x, want [0x2b000001 0x1b000002]", callees)
	}
}
