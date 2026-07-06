/*
Copyright (c) 2026 Security Research
*/
package clrgen

// WithPtrIndirection makes Emit include a MethodPtr (0x05) indirection table.
// Used to prove the reader refuses to parse through *Ptr tables.
func (b *Builder) WithPtrIndirection() *Builder {
	b.emitPtrTables = true
	return b
}

// PtrIndirected is the canonical *Ptr edge fixture.
func PtrIndirected() []byte {
	return New().
		WithAssembly("PtrAsm", [4]uint16{1, 0, 0, 0}).
		WithType("Edge", "Indirect", Method("M", 0x2050)).
		WithPtrIndirection().
		Emit()
}
