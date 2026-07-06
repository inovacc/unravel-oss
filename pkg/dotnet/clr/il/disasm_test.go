/*
Copyright (c) 2026 Security Research
*/
package il

import "testing"

func TestInstructions_OperandWidths(t *testing.T) {
	// ldc.i4 (0x20, InlineI=4 bytes) 0x0000002A ; ldstr (0x72, InlineString=token) ;
	// br.s (0x2B, ShortInlineBrTarget=1 byte) +0 ; ret (0x2A).
	code := []byte{
		0x20, 0x2A, 0x00, 0x00, 0x00, // ldc.i4 42
		0x72, 0x01, 0x00, 0x00, 0x70, // ldstr token 0x70000001
		0x2B, 0x00, // br.s 0
		0x2A, // ret
	}
	mb := &MethodBody{Code: code, MaxStack: 8}
	ins, err := mb.Instructions()
	if err != nil {
		t.Fatalf("Instructions: %v", err)
	}
	if len(ins) != 4 {
		t.Fatalf("got %d instructions, want 4", len(ins))
	}
	if ins[0].Op.Name != "ldc.i4" || ins[0].Operand.(int32) != 42 {
		t.Errorf("ins0 = %q %v, want ldc.i4 42", ins[0].Op.Name, ins[0].Operand)
	}
	if ins[1].Op.Name != "ldstr" || uint32(ins[1].Operand.(Token)) != 0x70000001 {
		t.Errorf("ins1 = %q %v, want ldstr token", ins[1].Op.Name, ins[1].Operand)
	}
	if ins[2].Op.Name != "br.s" || ins[2].Operand.(int8) != 0 {
		t.Errorf("ins2 = %q %v, want br.s 0", ins[2].Op.Name, ins[2].Operand)
	}
	if ins[3].Offset != 12 || ins[3].Op.Name != "ret" {
		t.Errorf("ins3 = off %d %q, want off 12 ret", ins[3].Offset, ins[3].Op.Name)
	}
}

func TestInstructions_Switch(t *testing.T) {
	// switch (0x45, InlineSwitch): count=2 then 2 int32 targets, then ret.
	code := []byte{
		0x45, 0x02, 0x00, 0x00, 0x00, // switch n=2
		0x01, 0x00, 0x00, 0x00, // target[0]=1
		0x02, 0x00, 0x00, 0x00, // target[1]=2
		0x2A, // ret
	}
	mb := &MethodBody{Code: code}
	ins, err := mb.Instructions()
	if err != nil {
		t.Fatalf("Instructions switch: %v", err)
	}
	if ins[0].Op.Name != "switch" {
		t.Fatalf("ins0 = %q, want switch", ins[0].Op.Name)
	}
	targets := ins[0].Operand.([]int32)
	if len(targets) != 2 || targets[0] != 1 || targets[1] != 2 {
		t.Errorf("switch targets = %v, want [1 2]", targets)
	}
	if ins[1].Op.Name != "ret" {
		t.Errorf("ins1 = %q, want ret", ins[1].Op.Name)
	}
}

func TestInstructions_TruncatedOperand(t *testing.T) {
	mb := &MethodBody{Code: []byte{0x20, 0x01}} // ldc.i4 needs 4 bytes, only 1 present
	if _, err := mb.Instructions(); err == nil {
		t.Fatal("expected truncation error, got nil")
	}
}

func TestDisassemble_CallGraphAndStrings(t *testing.T) {
	res := stubResolver{
		m:  map[uint32]string{0x06000001: "Greeter::Hello()", 0x0A000002: "Console::WriteLine(string)"},
		f:  map[uint32]string{0x04000003: "Greeter::name"},
		us: map[uint32]string{0x70000004: `"hi"`},
	}
	// ldstr "hi" ; call WriteLine ; ldfld name ; call Hello ; newobj 0x06000001 ; ret
	code := []byte{
		0x72, 0x04, 0x00, 0x00, 0x70, // ldstr 0x70000004
		0x28, 0x02, 0x00, 0x00, 0x0A, // call 0x0A000002
		0x7B, 0x03, 0x00, 0x00, 0x04, // ldfld 0x04000003
		0x28, 0x01, 0x00, 0x00, 0x06, // call 0x06000001
		0x73, 0x01, 0x00, 0x00, 0x06, // newobj 0x06000001
		0x2A, // ret
	}
	mb := &MethodBody{Code: code, MaxStack: 8}
	text, callees, strs := Disassemble(mb, res)

	if want := `"hi"`; len(strs) != 1 || strs[0] != want {
		t.Errorf("strings = %v, want [%q]", strs, want)
	}
	// callees: WriteLine, Hello, Hello(newobj) → dedup keeps order, unique tokens.
	wantCallees := []uint32{0x0A000002, 0x06000001}
	if len(callees) != len(wantCallees) {
		t.Fatalf("callees = %v, want %v", callees, wantCallees)
	}
	for i, c := range callees {
		if uint32(c) != wantCallees[i] {
			t.Errorf("callee[%d] = %#x, want %#x", i, uint32(c), wantCallees[i])
		}
	}
	for _, frag := range []string{"ldstr", "Console::WriteLine", "ldfld", "Greeter::name", "newobj", "ret", "IL_0000"} {
		if !contains(text, frag) {
			t.Errorf("IL text missing %q:\n%s", frag, text)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestDisassemble_NativeBody(t *testing.T) {
	text, callees, strs := Disassemble(&MethodBody{IsNative: true}, stubResolver{})
	if !contains(text, "native") {
		t.Errorf("native body text = %q, want native marker", text)
	}
	if callees != nil || strs != nil {
		t.Errorf("native body callees/strings should be nil")
	}
}
