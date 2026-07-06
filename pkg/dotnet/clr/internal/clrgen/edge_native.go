/*
Copyright (c) 2026 Security Research
*/
package clrgen

// NativeImplFlags marks a method whose body is native (CorMethodImpl.Native,
// II.23.1.10). The IL reader must skip it.
const NativeImplFlags uint16 = 0x0004

// NativeMethodRVA is the RVA the native method "body" lives at; its bytes are
// intentionally not a valid IL header.
const NativeMethodRVA uint32 = 0x2050

// WithNativeMethod adds a type with one method flagged native, placing garbage
// (non-IL) bytes at NativeMethodRVA inside the section.
func (b *Builder) WithNativeMethod() *Builder {
	b.nativeBodyRVA = NativeMethodRVA
	b.types = append(b.types, typeSpec{
		ns: "Edge", name: "Native",
		methods: []methodSpec{{name: "Extern", rva: NativeMethodRVA}},
	})
	return b
}

// NativeBody is the canonical native-method edge fixture.
func NativeBody() []byte {
	return New().WithAssembly("NativeAsm", [4]uint16{1, 0, 0, 0}).WithNativeMethod().Emit()
}
