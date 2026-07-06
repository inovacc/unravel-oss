/*
Copyright (c) 2026 Security Research
*/
package clr

import "testing"

func TestModuleName_AssemblyQualifiedArity(t *testing.T) {
	cases := []struct {
		ns, name, asm string
		arity         int
		want          string
	}{
		{"LinkedIn.Foo", "Bar", "LinkedIn", 0, "LinkedIn.Foo.Bar"},
		{"System.Collections.Generic", "List`1", "System.Private.CoreLib", 1, "System.Collections.Generic.List`1"},
		{"", "Global", "App", 0, "Global"},
	}
	for _, c := range cases {
		got := moduleName(c.ns, c.name)
		if got != c.want {
			t.Errorf("moduleName(%q,%q) = %q, want %q", c.ns, c.name, got, c.want)
		}
	}
}

func TestExtractModules_FromFixture(t *testing.T) {
	// clrgenGreeterImage builds a synth assembly with one type
	// Demo.Greeter::Hello() that does ldstr "hi"; call WriteLine; ret.
	img := clrgenGreeterImage(t)
	mods, asm, refs, pinvokes, err := ExtractModules(img)
	if err != nil {
		t.Fatalf("ExtractModules: %v", err)
	}
	if asm.Name != "Greeter" {
		t.Errorf("asm.Name = %q, want Greeter", asm.Name)
	}
	if len(refs) == 0 {
		t.Errorf("expected at least one AssemblyRef")
	}
	_ = pinvokes
	var greeter *TypeModule
	for i := range mods {
		if mods[i].Name == "Demo.Greeter" {
			greeter = &mods[i]
		}
	}
	if greeter == nil {
		t.Fatalf("Demo.Greeter module not found in %d modules", len(mods))
	}
	if !containsStr(greeter.IL, "ldstr") || !containsStr(greeter.IL, "ret") {
		t.Errorf("Greeter IL missing expected opcodes:\n%s", greeter.IL)
	}
	if len(greeter.Strings) == 0 || greeter.Strings[0] != `"hi"` {
		t.Errorf("Greeter strings = %v, want [\"hi\"]", greeter.Strings)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
