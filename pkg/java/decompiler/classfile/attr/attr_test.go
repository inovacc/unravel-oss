package attr

import (
	"encoding/binary"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// helpers ---------------------------------------------------------------

// u2 encodes a uint16 big-endian into 2 bytes.
func u2(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// u4 encodes a uint32 big-endian into 4 bytes.
func u4(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// concat joins byte slices.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// emptyCP returns a minimal constant pool with a single UTF-8 entry at index 1
// (empty string "").
// NOTE: constantpool.Read takes count as a parameter; it does NOT read it from
// the reader.  The reader must contain exactly the entry bytes (no count prefix).
func emptyCP() *constantpool.Pool {
	// One UTF-8 entry: tag=0x01, length=0
	data := concat([]byte{0x01}, u2(0))
	r := reader.NewReader(data)
	cp, err := constantpool.Read(r, 2) // count=2 → 1 real entry (indices 1..1)
	if err != nil {
		panic("emptyCP: " + err.Error())
	}
	return cp
}

// cpWithStrings builds a CP containing N consecutive UTF-8 entries starting at
// index 1.  The reader passed to constantpool.Read must NOT include the count.
func cpWithStrings(strs ...string) *constantpool.Pool {
	count := uint16(len(strs) + 1) // +1 because CP indices are 1-based
	var data []byte
	for _, s := range strs {
		bs := []byte(s)
		data = concat(data, []byte{0x01}, u2(uint16(len(bs))), bs)
	}
	r := reader.NewReader(data)
	cp, err := constantpool.Read(r, count)
	if err != nil {
		panic("cpWithStrings: " + err.Error())
	}
	return cp
}

// Map tests ---------------------------------------------------------------

func TestMap_NewMap(t *testing.T) {
	m := NewMap()
	if m == nil {
		t.Fatal("NewMap returned nil")
	}
}

func TestMap_AddGetHasAll(t *testing.T) {
	m := NewMap()

	a1 := &Raw{AttrName: "Foo", Data: []byte{1}}
	a2 := &Raw{AttrName: "Foo", Data: []byte{2}}
	a3 := &Raw{AttrName: "Bar", Data: []byte{3}}

	m.Add(a1)
	m.Add(a2)
	m.Add(a3)

	// Has
	if !m.Has("Foo") {
		t.Error("Has(Foo) expected true")
	}
	if !m.Has("Bar") {
		t.Error("Has(Bar) expected true")
	}
	if m.Has("Baz") {
		t.Error("Has(Baz) expected false")
	}

	// Get returns first
	got := m.Get("Foo")
	if got != a1 {
		t.Errorf("Get(Foo) = %v, want a1", got)
	}

	// GetAll returns all
	all := m.GetAll("Foo")
	if len(all) != 2 {
		t.Errorf("GetAll(Foo) len = %d, want 2", len(all))
	}

	// Get missing returns nil
	if m.Get("Missing") != nil {
		t.Error("Get(Missing) expected nil")
	}

	// All returns everything
	everything := m.All()
	if len(everything) != 3 {
		t.Errorf("All() len = %d, want 3", len(everything))
	}
}

func TestMap_GetAll_Missing(t *testing.T) {
	m := NewMap()
	if got := m.GetAll("nope"); got != nil {
		t.Errorf("GetAll on empty = %v, want nil", got)
	}
}

// Raw attribute -----------------------------------------------------------

func TestRaw_Name(t *testing.T) {
	r := &Raw{AttrName: "MyAttr", Data: []byte{0xDE, 0xAD}}
	if r.Name() != "MyAttr" {
		t.Errorf("Name() = %q, want MyAttr", r.Name())
	}
}

// ReadAttributes – happy paths -------------------------------------------

func buildAttrBytes(nameIdx uint16, body []byte) []byte {
	return concat(u2(nameIdx), u4(uint32(len(body))), body)
}

func TestReadAttributes_ZeroCount(t *testing.T) {
	cp := emptyCP()
	r := reader.NewReader([]byte{})
	m, err := ReadAttributes(r, cp, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.All()) != 0 {
		t.Errorf("expected 0 attrs, got %d", len(m.All()))
	}
}

func TestReadAttributes_UnknownAttr(t *testing.T) {
	// CP: index 1 = "UnknownXYZ"
	cp := cpWithStrings("UnknownXYZ")
	body := []byte{0xCA, 0xFE}
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)

	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, ok := m.Get("UnknownXYZ").(*Raw)
	if !ok {
		t.Fatalf("expected *Raw, got %T", m.Get("UnknownXYZ"))
	}
	if string(raw.Data) != string(body) {
		t.Errorf("raw data mismatch")
	}
}

func TestReadAttributes_StackMapTable(t *testing.T) {
	cp := cpWithStrings("StackMapTable")
	body := []byte{0x01, 0x02, 0x03}
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)

	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := m.Get("StackMapTable")
	if got == nil {
		t.Fatal("StackMapTable not found")
	}
	raw, ok := got.(*Raw)
	if !ok {
		t.Fatalf("expected *Raw, got %T", got)
	}
	if string(raw.Data) != string(body) {
		t.Errorf("raw data mismatch")
	}
}

func TestReadAttributes_SyntheticDeprecated(t *testing.T) {
	tests := []struct {
		name    string
		wantTyp string
	}{
		{"Synthetic", "*attr.Synthetic"},
		{"Deprecated", "*attr.Deprecated"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := cpWithStrings(tc.name)
			data := buildAttrBytes(1, []byte{}) // empty body
			r := reader.NewReader(data)
			m, err := ReadAttributes(r, cp, 1)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := m.Get(tc.name)
			if got == nil {
				t.Fatalf("%s not found in map", tc.name)
			}
			if got.Name() != tc.name {
				t.Errorf("Name() = %q, want %q", got.Name(), tc.name)
			}
		})
	}
}

// Synthetic / Deprecated Name() ------------------------------------------

func TestSynthetic_Name(t *testing.T) {
	s := &Synthetic{}
	if s.Name() != "Synthetic" {
		t.Errorf("got %q", s.Name())
	}
}

func TestDeprecated_Name(t *testing.T) {
	d := &Deprecated{}
	if d.Name() != "Deprecated" {
		t.Errorf("got %q", d.Name())
	}
}

// simple.go attribute parsers -------------------------------------------

func TestConstantValue(t *testing.T) {
	cp := cpWithStrings("ConstantValue")
	body := u2(42)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	cv, ok := m.Get("ConstantValue").(*ConstantValue)
	if !ok {
		t.Fatalf("expected *ConstantValue, got %T", m.Get("ConstantValue"))
	}
	if cv.ValueIndex != 42 {
		t.Errorf("ValueIndex = %d, want 42", cv.ValueIndex)
	}
	if cv.Name() != "ConstantValue" {
		t.Errorf("Name() = %q", cv.Name())
	}
}

func TestExceptions(t *testing.T) {
	cp := cpWithStrings("Exceptions")
	// 2 exception indices: 10, 20
	body := concat(u2(2), u2(10), u2(20))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ex, ok := m.Get("Exceptions").(*Exceptions)
	if !ok {
		t.Fatalf("expected *Exceptions, got %T", m.Get("Exceptions"))
	}
	if len(ex.ExceptionIndexTable) != 2 {
		t.Fatalf("len = %d, want 2", len(ex.ExceptionIndexTable))
	}
	if ex.ExceptionIndexTable[0] != 10 || ex.ExceptionIndexTable[1] != 20 {
		t.Errorf("table = %v", ex.ExceptionIndexTable)
	}
	if ex.Name() != "Exceptions" {
		t.Errorf("Name() = %q", ex.Name())
	}
}

func TestExceptions_Empty(t *testing.T) {
	cp := cpWithStrings("Exceptions")
	body := u2(0)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ex := m.Get("Exceptions").(*Exceptions)
	if len(ex.ExceptionIndexTable) != 0 {
		t.Errorf("expected empty table")
	}
}

func TestSourceFile(t *testing.T) {
	// CP: 1="SourceFile", 2="MyClass.java"
	cp := cpWithStrings("SourceFile", "MyClass.java")
	// body: index 2 points to "MyClass.java"
	body := u2(2)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	sf, ok := m.Get("SourceFile").(*SourceFile)
	if !ok {
		t.Fatalf("expected *SourceFile, got %T", m.Get("SourceFile"))
	}
	if sf.SourceFileName != "MyClass.java" {
		t.Errorf("SourceFileName = %q, want MyClass.java", sf.SourceFileName)
	}
	if sf.Name() != "SourceFile" {
		t.Errorf("Name() = %q", sf.Name())
	}
}

func TestSignature(t *testing.T) {
	cp := cpWithStrings("Signature", "<T:Ljava/lang/Object;>Ljava/lang/Object;")
	body := u2(2)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	sig, ok := m.Get("Signature").(*Signature)
	if !ok {
		t.Fatalf("expected *Signature, got %T", m.Get("Signature"))
	}
	if sig.SignatureValue != "<T:Ljava/lang/Object;>Ljava/lang/Object;" {
		t.Errorf("SignatureValue = %q", sig.SignatureValue)
	}
	if sig.Name() != "Signature" {
		t.Errorf("Name() = %q", sig.Name())
	}
}

func TestEnclosingMethod(t *testing.T) {
	cp := cpWithStrings("EnclosingMethod")
	body := concat(u2(5), u2(7))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	em, ok := m.Get("EnclosingMethod").(*EnclosingMethod)
	if !ok {
		t.Fatalf("expected *EnclosingMethod, got %T", m.Get("EnclosingMethod"))
	}
	if em.ClassIndex != 5 || em.MethodIndex != 7 {
		t.Errorf("ClassIndex=%d MethodIndex=%d", em.ClassIndex, em.MethodIndex)
	}
	if em.Name() != "EnclosingMethod" {
		t.Errorf("Name() = %q", em.Name())
	}
}

func TestNestHost(t *testing.T) {
	cp := cpWithStrings("NestHost")
	body := u2(9)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	nh, ok := m.Get("NestHost").(*NestHost)
	if !ok {
		t.Fatalf("expected *NestHost, got %T", m.Get("NestHost"))
	}
	if nh.HostClassIndex != 9 {
		t.Errorf("HostClassIndex = %d, want 9", nh.HostClassIndex)
	}
	if nh.Name() != "NestHost" {
		t.Errorf("Name() = %q", nh.Name())
	}
}

func TestNestMembers(t *testing.T) {
	cp := cpWithStrings("NestMembers")
	body := concat(u2(3), u2(11), u2(12), u2(13))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	nm, ok := m.Get("NestMembers").(*NestMembers)
	if !ok {
		t.Fatalf("expected *NestMembers, got %T", m.Get("NestMembers"))
	}
	if len(nm.Classes) != 3 {
		t.Fatalf("len = %d, want 3", len(nm.Classes))
	}
	if nm.Name() != "NestMembers" {
		t.Errorf("Name() = %q", nm.Name())
	}
}

func TestPermittedSubclasses(t *testing.T) {
	cp := cpWithStrings("PermittedSubclasses")
	body := concat(u2(2), u2(100), u2(200))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ps, ok := m.Get("PermittedSubclasses").(*PermittedSubclasses)
	if !ok {
		t.Fatalf("expected *PermittedSubclasses, got %T", m.Get("PermittedSubclasses"))
	}
	if len(ps.Classes) != 2 || ps.Classes[0] != 100 || ps.Classes[1] != 200 {
		t.Errorf("Classes = %v", ps.Classes)
	}
	if ps.Name() != "PermittedSubclasses" {
		t.Errorf("Name() = %q", ps.Name())
	}
}

func TestMethodParameters(t *testing.T) {
	cp := cpWithStrings("MethodParameters")
	// 2 params: (nameIdx=1, flags=0x10), (nameIdx=2, flags=0x00)
	body := concat(
		[]byte{0x02}, // count (u1)
		u2(1), u2(0x10),
		u2(2), u2(0x00),
	)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	mp, ok := m.Get("MethodParameters").(*MethodParameters)
	if !ok {
		t.Fatalf("expected *MethodParameters, got %T", m.Get("MethodParameters"))
	}
	if len(mp.Parameters) != 2 {
		t.Fatalf("len = %d, want 2", len(mp.Parameters))
	}
	if mp.Parameters[0].NameIndex != 1 || mp.Parameters[0].AccessFlags != 0x10 {
		t.Errorf("param[0] = %+v", mp.Parameters[0])
	}
	if mp.Name() != "MethodParameters" {
		t.Errorf("Name() = %q", mp.Name())
	}
}

func TestLineNumberTable(t *testing.T) {
	cp := cpWithStrings("LineNumberTable")
	// 2 entries: (pc=0, line=1), (pc=5, line=3)
	body := concat(u2(2), u2(0), u2(1), u2(5), u2(3))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	lnt, ok := m.Get("LineNumberTable").(*LineNumberTable)
	if !ok {
		t.Fatalf("expected *LineNumberTable, got %T", m.Get("LineNumberTable"))
	}
	if len(lnt.Entries) != 2 {
		t.Fatalf("len = %d, want 2", len(lnt.Entries))
	}
	if lnt.Entries[0].StartPC != 0 || lnt.Entries[0].LineNumber != 1 {
		t.Errorf("entry[0] = %+v", lnt.Entries[0])
	}
	if lnt.Entries[1].StartPC != 5 || lnt.Entries[1].LineNumber != 3 {
		t.Errorf("entry[1] = %+v", lnt.Entries[1])
	}
	if lnt.Name() != "LineNumberTable" {
		t.Errorf("Name() = %q", lnt.Name())
	}
}

func TestLocalVariableTable(t *testing.T) {
	cp := cpWithStrings("LocalVariableTable")
	// 1 entry: startPC=0, length=10, nameIdx=1, descIdx=1, idx=0
	body := concat(u2(1), u2(0), u2(10), u2(1), u2(1), u2(0))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	lvt, ok := m.Get("LocalVariableTable").(*LocalVariableTable)
	if !ok {
		t.Fatalf("expected *LocalVariableTable, got %T", m.Get("LocalVariableTable"))
	}
	if len(lvt.Entries) != 1 {
		t.Fatalf("len = %d, want 1", len(lvt.Entries))
	}
	e := lvt.Entries[0]
	if e.StartPC != 0 || e.Length != 10 || e.NameIndex != 1 || e.DescriptorIndex != 1 || e.Index != 0 {
		t.Errorf("entry = %+v", e)
	}
	if lvt.Name() != "LocalVariableTable" {
		t.Errorf("Name() = %q", lvt.Name())
	}
}

func TestLocalVariableTypeTable(t *testing.T) {
	cp := cpWithStrings("LocalVariableTypeTable")
	// 1 entry: startPC=2, length=8, nameIdx=1, sigIdx=1, idx=3
	body := concat(u2(1), u2(2), u2(8), u2(1), u2(1), u2(3))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	lvtt, ok := m.Get("LocalVariableTypeTable").(*LocalVariableTypeTable)
	if !ok {
		t.Fatalf("expected *LocalVariableTypeTable, got %T", m.Get("LocalVariableTypeTable"))
	}
	if len(lvtt.Entries) != 1 {
		t.Fatalf("len = %d, want 1", len(lvtt.Entries))
	}
	e := lvtt.Entries[0]
	if e.StartPC != 2 || e.Length != 8 || e.SignatureIndex != 1 || e.Index != 3 {
		t.Errorf("entry = %+v", e)
	}
	if lvtt.Name() != "LocalVariableTypeTable" {
		t.Errorf("Name() = %q", lvtt.Name())
	}
}

func TestInnerClasses(t *testing.T) {
	cp := cpWithStrings("InnerClasses")
	// 1 entry: innerInfo=1, outerInfo=2, innerName=3, flags=0x0001
	body := concat(u2(1), u2(1), u2(2), u2(3), u2(0x0001))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ic, ok := m.Get("InnerClasses").(*InnerClasses)
	if !ok {
		t.Fatalf("expected *InnerClasses, got %T", m.Get("InnerClasses"))
	}
	if len(ic.Classes) != 1 {
		t.Fatalf("len = %d, want 1", len(ic.Classes))
	}
	c := ic.Classes[0]
	if c.InnerClassInfoIndex != 1 || c.OuterClassInfoIndex != 2 || c.InnerNameIndex != 3 || c.InnerClassAccessFlags != 1 {
		t.Errorf("entry = %+v", c)
	}
	if ic.Name() != "InnerClasses" {
		t.Errorf("Name() = %q", ic.Name())
	}
}

func TestBootstrapMethods(t *testing.T) {
	cp := cpWithStrings("BootstrapMethods")
	// 1 method: methodRef=5, 2 args: 6, 7
	body := concat(u2(1), u2(5), u2(2), u2(6), u2(7))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	bm, ok := m.Get("BootstrapMethods").(*BootstrapMethods)
	if !ok {
		t.Fatalf("expected *BootstrapMethods, got %T", m.Get("BootstrapMethods"))
	}
	if len(bm.Methods) != 1 {
		t.Fatalf("len = %d, want 1", len(bm.Methods))
	}
	if bm.Methods[0].MethodRef != 5 {
		t.Errorf("MethodRef = %d", bm.Methods[0].MethodRef)
	}
	if len(bm.Methods[0].BootstrapArgs) != 2 {
		t.Errorf("args len = %d", len(bm.Methods[0].BootstrapArgs))
	}
	if bm.Methods[0].BootstrapArgs[0] != 6 || bm.Methods[0].BootstrapArgs[1] != 7 {
		t.Errorf("args = %v", bm.Methods[0].BootstrapArgs)
	}
	if bm.Name() != "BootstrapMethods" {
		t.Errorf("Name() = %q", bm.Name())
	}
}

func TestBootstrapMethods_NoArgs(t *testing.T) {
	cp := cpWithStrings("BootstrapMethods")
	body := concat(u2(1), u2(3), u2(0)) // 1 method, 0 args
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	bm := m.Get("BootstrapMethods").(*BootstrapMethods)
	if len(bm.Methods[0].BootstrapArgs) != 0 {
		t.Errorf("expected 0 args")
	}
}

// Code attribute ---------------------------------------------------------

func buildCodeBody(maxStack, maxLocals uint16, bytecode []byte, exceptions []ExceptionEntry, subAttrs []byte) []byte {
	body := concat(u2(maxStack), u2(maxLocals), u4(uint32(len(bytecode))), bytecode)
	body = concat(body, u2(uint16(len(exceptions))))
	for _, ex := range exceptions {
		body = concat(body, u2(ex.StartPC), u2(ex.EndPC), u2(ex.HandlerPC), u2(ex.CatchType))
	}
	// sub-attribute count + data
	body = concat(body, subAttrs)
	return body
}

func TestCode_SimpleNoExceptions(t *testing.T) {
	cp := cpWithStrings("Code")
	bytecode := []byte{0x00, 0xb1} // nop, return
	// 0 exceptions, 0 sub-attrs
	codeBody := buildCodeBody(2, 1, bytecode, nil, u2(0))
	data := buildAttrBytes(1, codeBody)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	code, ok := m.Get("Code").(*Code)
	if !ok {
		t.Fatalf("expected *Code, got %T", m.Get("Code"))
	}
	if code.MaxStack != 2 || code.MaxLocals != 1 {
		t.Errorf("MaxStack=%d MaxLocals=%d", code.MaxStack, code.MaxLocals)
	}
	if string(code.Bytecode) != string(bytecode) {
		t.Errorf("bytecode mismatch")
	}
	if len(code.ExceptionTable) != 0 {
		t.Errorf("expected 0 exceptions")
	}
	if code.Name() != "Code" {
		t.Errorf("Name() = %q", code.Name())
	}
}

func TestCode_WithException(t *testing.T) {
	cp := cpWithStrings("Code")
	bytecode := []byte{0xb1}
	ex := ExceptionEntry{StartPC: 0, EndPC: 5, HandlerPC: 10, CatchType: 3}
	codeBody := buildCodeBody(1, 1, bytecode, []ExceptionEntry{ex}, u2(0))
	data := buildAttrBytes(1, codeBody)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	code := m.Get("Code").(*Code)
	if len(code.ExceptionTable) != 1 {
		t.Fatalf("exceptions len = %d", len(code.ExceptionTable))
	}
	got := code.ExceptionTable[0]
	if got.StartPC != 0 || got.EndPC != 5 || got.HandlerPC != 10 || got.CatchType != 3 {
		t.Errorf("exception = %+v", got)
	}
}

func TestCode_WithLineNumberTableSubAttr(t *testing.T) {
	// CP: 1="Code", 2="LineNumberTable"
	cp := cpWithStrings("Code", "LineNumberTable")
	bytecode := []byte{0xb1}

	// sub-attr: LineNumberTable with 1 entry
	lntBody := concat(u2(1), u2(0), u2(1))
	// 1 sub-attr at CP index 2
	subAttrs := concat(u2(1), buildAttrBytes(2, lntBody))

	codeBody := buildCodeBody(1, 1, bytecode, nil, subAttrs)
	data := buildAttrBytes(1, codeBody)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	code := m.Get("Code").(*Code)
	lnt := code.Attributes.Get("LineNumberTable")
	if lnt == nil {
		t.Fatal("LineNumberTable sub-attr not found")
	}
}

// Record attribute -------------------------------------------------------

func TestRecord(t *testing.T) {
	// CP: 1="Record", 2="x", 3="I" (two more for component name/descriptor)
	cp := cpWithStrings("Record", "x", "I")
	// 1 component: nameIdx=2, descIdx=3, 0 sub-attrs
	compBody := concat(u2(2), u2(3), u2(0))
	body := concat(u2(1), compBody)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	rec, ok := m.Get("Record").(*Record)
	if !ok {
		t.Fatalf("expected *Record, got %T", m.Get("Record"))
	}
	if len(rec.Components) != 1 {
		t.Fatalf("len = %d, want 1", len(rec.Components))
	}
	if rec.Components[0].NameIndex != 2 || rec.Components[0].DescriptorIndex != 3 {
		t.Errorf("component = %+v", rec.Components[0])
	}
	if rec.Name() != "Record" {
		t.Errorf("Name() = %q", rec.Name())
	}
}

// Annotations ------------------------------------------------------------

func buildAnnotationEntry(typeIdx uint16, pairs []struct {
	nameIdx  uint16
	tag      byte
	constIdx uint16
}) []byte {
	body := u2(typeIdx)
	body = concat(body, u2(uint16(len(pairs))))
	for _, p := range pairs {
		body = concat(body, u2(p.nameIdx), []byte{p.tag}, u2(p.constIdx))
	}
	return body
}

func TestAnnotations_Empty(t *testing.T) {
	cp := cpWithStrings("RuntimeVisibleAnnotations")
	body := u2(0) // 0 annotations
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ann, ok := m.Get("RuntimeVisibleAnnotations").(*Annotations)
	if !ok {
		t.Fatalf("expected *Annotations, got %T", m.Get("RuntimeVisibleAnnotations"))
	}
	if len(ann.Annots) != 0 {
		t.Errorf("expected 0 annotations")
	}
	if ann.Name() != "RuntimeVisibleAnnotations" {
		t.Errorf("Name() = %q", ann.Name())
	}
}

func TestAnnotations_OneWithConstValue(t *testing.T) {
	cp := cpWithStrings("RuntimeInvisibleAnnotations")
	// 1 annotation: typeIdx=1, 1 pair: nameIdx=1, tag='I', constIdx=1
	annEntry := buildAnnotationEntry(1, []struct {
		nameIdx  uint16
		tag      byte
		constIdx uint16
	}{{1, 'I', 1}})
	body := concat(u2(1), annEntry)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ann := m.Get("RuntimeInvisibleAnnotations").(*Annotations)
	if len(ann.Annots) != 1 {
		t.Fatalf("len = %d, want 1", len(ann.Annots))
	}
	if ann.Annots[0].TypeIndex != 1 {
		t.Errorf("TypeIndex = %d", ann.Annots[0].TypeIndex)
	}
	if len(ann.Annots[0].Pairs) != 1 {
		t.Fatalf("pairs len = %d", len(ann.Annots[0].Pairs))
	}
	pair := ann.Annots[0].Pairs[0]
	if pair.Value.Tag != 'I' || pair.Value.ConstValueIdx != 1 {
		t.Errorf("pair value = %+v", pair.Value)
	}
}

// ElementValue tag coverage -----------------------------------------------

func TestElementValue_Tags(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"tagB", concat([]byte{'B'}, u2(5))},
		{"tagC", concat([]byte{'C'}, u2(6))},
		{"tagD", concat([]byte{'D'}, u2(7))},
		{"tagF", concat([]byte{'F'}, u2(8))},
		{"tagI", concat([]byte{'I'}, u2(9))},
		{"tagJ", concat([]byte{'J'}, u2(10))},
		{"tagS", concat([]byte{'S'}, u2(11))},
		{"tagZ", concat([]byte{'Z'}, u2(12))},
		{"tags", concat([]byte{'s'}, u2(13))},
		{"tagc", concat([]byte{'c'}, u2(14))},
		{"tage", concat([]byte{'e'}, u2(1), u2(2))},
		{"tagArray_empty", concat([]byte{'['}, u2(0))},
		{"tagArray_one_int", concat([]byte{'['}, u2(1), []byte{'I'}, u2(99))},
		// nested annotation: '@' then a minimal annotation entry (typeIdx=1, 0 pairs)
		{"tagAnnotation", concat([]byte{'@'}, u2(1), u2(0))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := reader.NewReader(tc.data)
			ev, err := readElementValue(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			_ = ev
		})
	}
}

func TestElementValue_UnknownTag(t *testing.T) {
	r := reader.NewReader([]byte{0xFF, 0x00, 0x01})
	_, err := readElementValue(r)
	if err == nil {
		t.Fatal("expected error for unknown tag")
	}
}

// AnnotationDefault -------------------------------------------------------

func TestAnnotationDefault(t *testing.T) {
	cp := cpWithStrings("AnnotationDefault")
	// body: elementValue with tag='I', constIdx=7
	body := concat([]byte{'I'}, u2(7))
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ad, ok := m.Get("AnnotationDefault").(*AnnotationDefault)
	if !ok {
		t.Fatalf("expected *AnnotationDefault, got %T", m.Get("AnnotationDefault"))
	}
	if ad.DefaultValue.Tag != 'I' || ad.DefaultValue.ConstValueIdx != 7 {
		t.Errorf("DefaultValue = %+v", ad.DefaultValue)
	}
	if ad.Name() != "AnnotationDefault" {
		t.Errorf("Name() = %q", ad.Name())
	}
}

// ParameterAnnotations ----------------------------------------------------

func TestParameterAnnotations_TwoParams(t *testing.T) {
	cp := cpWithStrings("RuntimeVisibleParameterAnnotations")
	// 2 params: param0 has 1 annotation (typeIdx=1, 0 pairs), param1 has 0 annotations
	param0Ann := buildAnnotationEntry(1, nil)
	body := concat(
		[]byte{0x02},     // numParams
		u2(1), param0Ann, // param 0: 1 annotation
		u2(0), // param 1: 0 annotations
	)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	pa, ok := m.Get("RuntimeVisibleParameterAnnotations").(*ParameterAnnotations)
	if !ok {
		t.Fatalf("expected *ParameterAnnotations, got %T", m.Get("RuntimeVisibleParameterAnnotations"))
	}
	if len(pa.Parameters) != 2 {
		t.Fatalf("len = %d, want 2", len(pa.Parameters))
	}
	if len(pa.Parameters[0]) != 1 {
		t.Errorf("param0 annotations = %d", len(pa.Parameters[0]))
	}
	if len(pa.Parameters[1]) != 0 {
		t.Errorf("param1 annotations = %d", len(pa.Parameters[1]))
	}
	if pa.Name() != "RuntimeVisibleParameterAnnotations" {
		t.Errorf("Name() = %q", pa.Name())
	}
}

func TestParameterAnnotations_Invisible(t *testing.T) {
	cp := cpWithStrings("RuntimeInvisibleParameterAnnotations")
	body := concat([]byte{0x01}, u2(0)) // 1 param, 0 annotations
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	pa := m.Get("RuntimeInvisibleParameterAnnotations").(*ParameterAnnotations)
	if len(pa.Parameters) != 1 {
		t.Errorf("len = %d, want 1", len(pa.Parameters))
	}
}

// TypeAnnotations ---------------------------------------------------------

// buildTypeAnnotationEntry builds a minimal type annotation for a given targetType.
func buildTypeAnnotationEntry(targetType byte, targetInfo []byte) []byte {
	// targetType + targetInfo + type_path (0 entries) + typeIndex + 0 pairs
	return concat(
		[]byte{targetType},
		targetInfo,
		[]byte{0x00}, // path_length=0
		u2(1),        // type_index
		u2(0),        // num_pairs=0
	)
}

func TestTypeAnnotations_TargetTypes(t *testing.T) {
	tests := []struct {
		name       string
		targetType byte
		targetInfo []byte
	}{
		{"type_param_0x00", 0x00, []byte{0x01}},
		{"type_param_0x01", 0x01, []byte{0x02}},
		{"supertype_0x10", 0x10, u2(3)},
		{"type_param_bound_0x11", 0x11, []byte{0x01, 0x02}},
		{"type_param_bound_0x12", 0x12, []byte{0x00, 0x01}},
		{"empty_0x13", 0x13, nil},
		{"empty_0x14", 0x14, nil},
		{"empty_0x15", 0x15, nil},
		{"formal_param_0x16", 0x16, []byte{0x01}},
		{"throws_0x17", 0x17, u2(5)},
		{"catch_0x42", 0x42, u2(7)},
		{"offset_0x43", 0x43, u2(8)},
		{"offset_0x44", 0x44, u2(9)},
		{"offset_0x45", 0x45, u2(10)},
		{"offset_0x46", 0x46, u2(11)},
		{"type_arg_0x47", 0x47, []byte{0x00, 0x01, 0x02}},
		{"type_arg_0x48", 0x48, []byte{0x00, 0x01, 0x03}},
		{"type_arg_0x49", 0x49, []byte{0x00, 0x01, 0x04}},
		{"type_arg_0x4A", 0x4A, []byte{0x00, 0x01, 0x05}},
		{"type_arg_0x4B", 0x4B, []byte{0x00, 0x01, 0x06}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := cpWithStrings("RuntimeVisibleTypeAnnotations")
			entry := buildTypeAnnotationEntry(tc.targetType, tc.targetInfo)
			body := concat(u2(1), entry)
			data := buildAttrBytes(1, body)
			r := reader.NewReader(data)
			m, err := ReadAttributes(r, cp, 1)
			if err != nil {
				t.Fatalf("targetType %#x error: %v", tc.targetType, err)
			}
			ta, ok := m.Get("RuntimeVisibleTypeAnnotations").(*TypeAnnotations)
			if !ok {
				t.Fatalf("expected *TypeAnnotations, got %T", m.Get("RuntimeVisibleTypeAnnotations"))
			}
			if len(ta.Annots) != 1 {
				t.Errorf("len = %d, want 1", len(ta.Annots))
			}
		})
	}
}

func TestTypeAnnotations_LocalVar_0x40(t *testing.T) {
	cp := cpWithStrings("RuntimeVisibleTypeAnnotations")
	// localvar_target: table_length=1, then 6 bytes per entry
	localVarTarget := concat(u2(1), []byte{0, 0, 0, 5, 0, 2}) // 1 entry of 6 bytes
	entry := buildTypeAnnotationEntry(0x40, localVarTarget)
	body := concat(u2(1), entry)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ta := m.Get("RuntimeVisibleTypeAnnotations").(*TypeAnnotations)
	if len(ta.Annots) != 1 {
		t.Errorf("expected 1 annotation")
	}
}

func TestTypeAnnotations_LocalVar_0x41(t *testing.T) {
	cp := cpWithStrings("RuntimeVisibleTypeAnnotations")
	localVarTarget := concat(u2(2), []byte{0, 0, 0, 5, 0, 2}, []byte{0, 6, 0, 2, 0, 1})
	entry := buildTypeAnnotationEntry(0x41, localVarTarget)
	body := concat(u2(1), entry)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ta := m.Get("RuntimeVisibleTypeAnnotations").(*TypeAnnotations)
	if len(ta.Annots) != 1 {
		t.Errorf("expected 1 annotation")
	}
}

func TestTypeAnnotations_Invisible(t *testing.T) {
	cp := cpWithStrings("RuntimeInvisibleTypeAnnotations")
	entry := buildTypeAnnotationEntry(0x13, nil)
	body := concat(u2(1), entry)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ta, ok := m.Get("RuntimeInvisibleTypeAnnotations").(*TypeAnnotations)
	if !ok {
		t.Fatalf("expected *TypeAnnotations, got %T", m.Get("RuntimeInvisibleTypeAnnotations"))
	}
	if ta.Name() != "RuntimeInvisibleTypeAnnotations" {
		t.Errorf("Name() = %q", ta.Name())
	}
}

func TestTypeAnnotations_UnknownTargetType(t *testing.T) {
	cp := cpWithStrings("RuntimeVisibleTypeAnnotations")
	entry := buildTypeAnnotationEntry(0xFF, nil)
	body := concat(u2(1), entry)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	// Parse failure falls back to Raw
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be stored as Raw due to parse failure
	raw, ok := m.Get("RuntimeVisibleTypeAnnotations").(*Raw)
	if !ok {
		t.Fatalf("expected *Raw fallback, got %T", m.Get("RuntimeVisibleTypeAnnotations"))
	}
	if raw.Name() != "RuntimeVisibleTypeAnnotations" {
		t.Errorf("Name() = %q", raw.Name())
	}
}

func TestTypeAnnotations_WithTypePath(t *testing.T) {
	cp := cpWithStrings("RuntimeVisibleTypeAnnotations")
	// targetType=0x13 (empty), type_path with 2 entries, then typeIndex=1, 0 pairs
	entry := concat(
		[]byte{0x13}, // empty_target
		// type_path: 2 entries
		[]byte{0x02},       // path_length
		[]byte{0x00, 0x01}, // entry 1: kind=0, argIndex=1
		[]byte{0x01, 0x00}, // entry 2: kind=1, argIndex=0
		u2(1),              // typeIndex
		u2(0),              // numPairs
	)
	body := concat(u2(1), entry)
	data := buildAttrBytes(1, body)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	ta := m.Get("RuntimeVisibleTypeAnnotations").(*TypeAnnotations)
	if len(ta.Annots[0].TypePath) != 2 {
		t.Errorf("type_path len = %d, want 2", len(ta.Annots[0].TypePath))
	}
}

// ReadAttributes – truncation error paths --------------------------------

func TestReadAttributes_TruncatedNameIdx(t *testing.T) {
	cp := emptyCP()
	// Only 1 byte instead of 2 for name index
	r := reader.NewReader([]byte{0x00})
	_, err := ReadAttributes(r, cp, 1)
	if err == nil {
		t.Fatal("expected error on truncated name index")
	}
}

func TestReadAttributes_TruncatedLength(t *testing.T) {
	cp := emptyCP()
	// name index OK (2 bytes), but length only partially present (2 bytes, need 4)
	r := reader.NewReader(concat(u2(1), []byte{0x00, 0x00}))
	_, err := ReadAttributes(r, cp, 1)
	if err == nil {
		t.Fatal("expected error on truncated length")
	}
}

func TestReadAttributes_TruncatedBody(t *testing.T) {
	cp := emptyCP()
	// name index + length=10, but no body bytes
	r := reader.NewReader(concat(u2(1), u4(10)))
	_, err := ReadAttributes(r, cp, 1)
	if err == nil {
		t.Fatal("expected error on truncated body")
	}
}

// Multiple attributes in one ReadAttributes call -------------------------

func TestReadAttributes_Multiple(t *testing.T) {
	// CP: 1="Synthetic", 2="Deprecated", 3="UnknownXXX"
	cp := cpWithStrings("Synthetic", "Deprecated", "UnknownXXX")

	data := concat(
		buildAttrBytes(1, []byte{}),
		buildAttrBytes(2, []byte{}),
		buildAttrBytes(3, []byte{0xAB}),
	)
	r := reader.NewReader(data)
	m, err := ReadAttributes(r, cp, 3)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !m.Has("Synthetic") {
		t.Error("missing Synthetic")
	}
	if !m.Has("Deprecated") {
		t.Error("missing Deprecated")
	}
	if !m.Has("UnknownXXX") {
		t.Error("missing UnknownXXX")
	}
}
