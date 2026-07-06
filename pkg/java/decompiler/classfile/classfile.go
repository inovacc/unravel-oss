package classfile

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/attr"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// Magic is the Java class file magic number: 0xCAFEBABE.
const Magic uint32 = 0xCAFEBABE

// ClassFile represents a parsed Java .class file.
type ClassFile struct {
	MinorVersion uint16
	MajorVersion uint16
	ConstantPool *constantpool.Pool
	AccessFlags  AccessFlags
	ThisClass    uint16 // index into constant pool
	SuperClass   uint16 // index into constant pool (0 for java.lang.Object)
	Interfaces   []uint16
	Fields       []*Field
	Methods      []*Method
	Attributes   *attr.Map
}

// Parse reads a Java .class file from raw bytes.
func Parse(data []byte) (*ClassFile, error) {
	r := reader.NewReader(data)

	// Magic number
	magic, err := r.ReadU4()
	if err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}

	if magic != Magic {
		return nil, fmt.Errorf("invalid class file magic: %#x (expected %#x)", magic, Magic)
	}

	// Version
	minor, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read minor_version: %w", err)
	}

	major, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read major_version: %w", err)
	}

	// Constant pool
	cpCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read constant_pool_count: %w", err)
	}

	cp, err := constantpool.Read(r, cpCount)
	if err != nil {
		return nil, fmt.Errorf("read constant_pool: %w", err)
	}

	// Access flags
	flags, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read access_flags: %w", err)
	}

	// This class
	thisClass, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read this_class: %w", err)
	}

	// Super class
	superClass, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read super_class: %w", err)
	}

	// Interfaces
	ifaceCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read interfaces_count: %w", err)
	}

	interfaces := make([]uint16, ifaceCount)
	for i := range interfaces {
		if interfaces[i], err = r.ReadU2(); err != nil {
			return nil, fmt.Errorf("read interface %d: %w", i, err)
		}
	}

	// Fields
	fieldCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read fields_count: %w", err)
	}

	fields := make([]*Field, fieldCount)
	for i := range fields {
		if fields[i], err = ReadField(r, cp); err != nil {
			return nil, fmt.Errorf("read field %d: %w", i, err)
		}
	}

	// Methods
	methodCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read methods_count: %w", err)
	}

	methods := make([]*Method, methodCount)
	for i := range methods {
		if methods[i], err = ReadMethod(r, cp); err != nil {
			return nil, fmt.Errorf("read method %d: %w", i, err)
		}
	}

	// Attributes
	attrCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read attributes_count: %w", err)
	}

	attrs, err := attr.ReadAttributes(r, cp, attrCount)
	if err != nil {
		return nil, fmt.Errorf("read class attributes: %w", err)
	}

	return &ClassFile{
		MinorVersion: minor,
		MajorVersion: major,
		ConstantPool: cp,
		AccessFlags:  AccessFlags(flags),
		ThisClass:    thisClass,
		SuperClass:   superClass,
		Interfaces:   interfaces,
		Fields:       fields,
		Methods:      methods,
		Attributes:   attrs,
	}, nil
}

// ClassName returns the fully qualified class name in internal form (e.g. "java/lang/Object").
func (cf *ClassFile) ClassName() string {
	return cf.ConstantPool.ClassName(cf.ThisClass)
}

// ClassNameDotted returns the class name in dotted form (e.g. "java.lang.Object").
func (cf *ClassFile) ClassNameDotted() string {
	return cf.ConstantPool.ClassNameDotted(cf.ThisClass)
}

// SuperClassName returns the superclass name in internal form, or "" for java.lang.Object.
func (cf *ClassFile) SuperClassName() string {
	if cf.SuperClass == 0 {
		return ""
	}

	return cf.ConstantPool.ClassName(cf.SuperClass)
}

// InterfaceNames returns the interface names in internal form.
func (cf *ClassFile) InterfaceNames() []string {
	names := make([]string, len(cf.Interfaces))
	for i, idx := range cf.Interfaces {
		names[i] = cf.ConstantPool.ClassName(idx)
	}

	return names
}

// SourceFile returns the source file name if present.
func (cf *ClassFile) SourceFile() string {
	if sf := cf.Attributes.Get("SourceFile"); sf != nil {
		if s, ok := sf.(*attr.SourceFile); ok {
			return s.SourceFileName
		}
	}

	return ""
}

// JavaVersion returns the human-readable Java version string.
func (cf *ClassFile) JavaVersion() string {
	switch cf.MajorVersion {
	case 45:
		return "Java 1.1"
	case 46:
		return "Java 1.2"
	case 47:
		return "Java 1.3"
	case 48:
		return "Java 1.4"
	case 49:
		return "Java 5"
	case 50:
		return "Java 6"
	case 51:
		return "Java 7"
	case 52:
		return "Java 8"
	case 53:
		return "Java 9"
	case 54:
		return "Java 10"
	case 55:
		return "Java 11"
	case 56:
		return "Java 12"
	case 57:
		return "Java 13"
	case 58:
		return "Java 14"
	case 59:
		return "Java 15"
	case 60:
		return "Java 16"
	case 61:
		return "Java 17"
	case 62:
		return "Java 18"
	case 63:
		return "Java 19"
	case 64:
		return "Java 20"
	case 65:
		return "Java 21"
	case 66:
		return "Java 22"
	case 67:
		return "Java 23"
	default:
		if cf.MajorVersion > 67 {
			return fmt.Sprintf("Java %d", cf.MajorVersion-44)
		}

		return fmt.Sprintf("version %d.%d", cf.MajorVersion, cf.MinorVersion)
	}
}

// IsInterface returns true if this is an interface.
func (cf *ClassFile) IsInterface() bool { return cf.AccessFlags.IsInterface() }

// IsEnum returns true if this is an enum.
func (cf *ClassFile) IsEnum() bool { return cf.AccessFlags.IsEnum() }

// IsAnnotation returns true if this is an annotation type.
func (cf *ClassFile) IsAnnotation() bool { return cf.AccessFlags.IsAnnotation() }

// IsModule returns true if this is a module descriptor.
func (cf *ClassFile) IsModule() bool { return cf.AccessFlags.IsModule() }

// Stub returns a human-readable summary of the parsed class file.
// This is a temporary output for Phase 1 before full decompilation is implemented.
func (cf *ClassFile) Stub() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("// Decompiled from %s (%s)\n", cf.ClassName(), cf.JavaVersion()))

	if sf := cf.SourceFile(); sf != "" {
		b.WriteString(fmt.Sprintf("// Source: %s\n", sf))
	}

	b.WriteString("\n")

	// Package
	className := cf.ClassNameDotted()
	if lastDot := strings.LastIndex(className, "."); lastDot >= 0 {
		b.WriteString(fmt.Sprintf("package %s;\n\n", className[:lastDot]))
	}

	// Class declaration
	access := cf.AccessFlags.ClassAccessString()
	if access != "" {
		b.WriteString(access + " ")
	}

	if cf.IsInterface() {
		b.WriteString("interface ")
	} else if cf.IsEnum() {
		b.WriteString("enum ")
	} else if cf.IsAnnotation() {
		b.WriteString("@interface ")
	} else {
		b.WriteString("class ")
	}

	// Simple name
	simpleName := className
	if lastDot := strings.LastIndex(className, "."); lastDot >= 0 {
		simpleName = className[lastDot+1:]
	}

	b.WriteString(simpleName)

	// Super class
	if sc := cf.SuperClassName(); sc != "" && sc != "java/lang/Object" {
		b.WriteString(" extends ")
		b.WriteString(strings.ReplaceAll(sc, "/", "."))
	}

	// Interfaces
	if ifaces := cf.InterfaceNames(); len(ifaces) > 0 {
		if cf.IsInterface() {
			b.WriteString(" extends ")
		} else {
			b.WriteString(" implements ")
		}

		for i, iface := range ifaces {
			if i > 0 {
				b.WriteString(", ")
			}

			b.WriteString(strings.ReplaceAll(iface, "/", "."))
		}
	}

	b.WriteString(" {\n")

	// Fields
	for _, f := range cf.Fields {
		b.WriteString(fmt.Sprintf("    %s %s %s;\n", f.AccessFlags.FieldAccessString(), descriptorToJava(f.Descriptor), f.Name))
	}

	if len(cf.Fields) > 0 && len(cf.Methods) > 0 {
		b.WriteString("\n")
	}

	// Methods
	for _, m := range cf.Methods {
		if m.IsStaticInitializer() {
			b.WriteString("    static { /* ... */ }\n")
			continue
		}

		access := m.AccessFlags.MethodAccessString()
		if access != "" {
			access += " "
		}

		if m.IsConstructor() {
			b.WriteString(fmt.Sprintf("    %s%s%s { /* ... */ }\n", access, simpleName, descriptorParamsToJava(m.Descriptor)))
		} else {
			ret, params := parseMethodDescriptor(m.Descriptor)
			b.WriteString(fmt.Sprintf("    %s%s %s(%s)", access, ret, m.Name, params))

			if m.IsAbstract() || m.IsNative() {
				b.WriteString(";\n")
			} else {
				b.WriteString(" { /* ... */ }\n")
			}
		}
	}

	b.WriteString("}\n")

	return b.String()
}

// descriptorToJava converts a single field descriptor to Java source form.
func descriptorToJava(desc string) string {
	result, _ := parseType(desc, 0)
	return result
}

func parseType(desc string, pos int) (string, int) {
	if pos >= len(desc) {
		return "void", pos
	}

	switch desc[pos] {
	case 'B':
		return "byte", pos + 1
	case 'C':
		return "char", pos + 1
	case 'D':
		return "double", pos + 1
	case 'F':
		return "float", pos + 1
	case 'I':
		return "int", pos + 1
	case 'J':
		return "long", pos + 1
	case 'S':
		return "short", pos + 1
	case 'Z':
		return "boolean", pos + 1
	case 'V':
		return "void", pos + 1
	case 'L':
		end := strings.IndexByte(desc[pos:], ';')
		if end < 0 {
			return desc[pos:], len(desc)
		}

		className := desc[pos+1 : pos+end]

		return strings.ReplaceAll(className, "/", "."), pos + end + 1
	case '[':
		elemType, newPos := parseType(desc, pos+1)
		return elemType + "[]", newPos
	default:
		return string(desc[pos]), pos + 1
	}
}

func descriptorParamsToJava(desc string) string {
	if len(desc) == 0 || desc[0] != '(' {
		return "()"
	}

	_, params := parseMethodDescriptor(desc)

	return "(" + params + ")"
}

func parseMethodDescriptor(desc string) (returnType, params string) {
	if len(desc) == 0 || desc[0] != '(' {
		return "void", ""
	}

	pos := 1

	var paramTypes []string

	for pos < len(desc) && desc[pos] != ')' {
		t, newPos := parseType(desc, pos)
		paramTypes = append(paramTypes, t)
		pos = newPos
	}

	if pos < len(desc) {
		pos++ // skip ')'
	}

	ret, _ := parseType(desc, pos)

	return ret, strings.Join(paramTypes, ", ")
}
