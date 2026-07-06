/*
Copyright (c) 2026 Security Research
*/
package il

import "testing"

// stubResolver records lookups and returns canned text.
type stubResolver struct{ m, f, ty, us map[uint32]string }

func (s stubResolver) Method(t Token) string     { return s.m[uint32(t)] }
func (s stubResolver) Field(t Token) string      { return s.f[uint32(t)] }
func (s stubResolver) Type(t Token) string       { return s.ty[uint32(t)] }
func (s stubResolver) UserString(t Token) string { return s.us[uint32(t)] }

func TestResolveOperand(t *testing.T) {
	res := stubResolver{
		m:  map[uint32]string{0x06000001: "Foo::Bar()"},
		f:  map[uint32]string{0x04000002: "Foo::field"},
		ty: map[uint32]string{0x01000003: "System.String"},
		us: map[uint32]string{0x70000004: `"hello"`},
	}
	cases := []struct {
		class OperandClass
		tok   uint32
		want  string
	}{
		{InlineMethod, 0x06000001, "Foo::Bar()"},
		{InlineField, 0x04000002, "Foo::field"},
		{InlineType, 0x01000003, "System.String"},
		{InlineString, 0x70000004, `"hello"`},
		{InlineTok, 0x06000001, "Foo::Bar()"}, // ldtoken on a methoddef
	}
	for _, c := range cases {
		got := resolveOperand(c.class, Token(c.tok), res)
		if got != c.want {
			t.Errorf("resolveOperand(%d,%#x) = %q, want %q", c.class, c.tok, got, c.want)
		}
	}
}

func TestResolveOperand_MethodSpecDegrades(t *testing.T) {
	// MethodSpec (0x2B) / TypeSpec (0x1B) degrade to raw token text (spec §4).
	got := resolveOperand(InlineMethod, Token(0x2B000005), stubResolver{})
	if got != "/* token 0x2b000005 */" {
		t.Errorf("MethodSpec degraded = %q, want raw token text", got)
	}
}
