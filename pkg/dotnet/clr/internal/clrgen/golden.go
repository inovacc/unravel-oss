/*
Copyright (c) 2026 Security Research
*/
package clrgen

// Canonical returns the single fixed fixture imported by every test group.
// Contents are frozen so cross-group assertions and the SHA-256 golden are
// stable: assembly CanonAsm 9.9.9.9, one AssemblyRef (System.Runtime),
// one type Canon.Core.Widget with two methods, one #US literal, one P/Invoke.
func Canonical() []byte {
	return New().
		WithAssembly("CanonAsm", [4]uint16{9, 9, 9, 9}).
		WithAssemblyRef("System.Runtime", [4]uint16{8, 0, 0, 0}).
		WithType("Canon.Core", "Widget",
			Method("Spin", 0x2050),
			Method("Stop", 0x2060)).
		WithUserString("canon literal").
		WithPInvoke("Beep", "kernel32.dll").
		Emit()
}
