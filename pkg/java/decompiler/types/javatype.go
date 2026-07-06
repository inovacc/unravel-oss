package types

import (
	"fmt"
	"strings"
)

// JavaType represents a Java type in the decompiler's type system.
// This is the core interface — all type representations implement it.
type JavaType interface {
	// Name returns the Java source-level name (e.g. "int", "java.lang.String", "int[]").
	Name() string

	// RawName returns the internal/binary name (e.g. "int", "java/lang/String").
	RawName() string

	// Descriptor returns the JVM type descriptor (e.g. "I", "Ljava/lang/String;", "[I").
	Descriptor() string

	// IsObject returns true for reference types (classes, arrays, null), false for primitives.
	IsObject() bool

	// IsPrimitive returns true for JVM primitives (boolean, byte, char, short, int, long, float, double).
	IsPrimitive() bool

	// IsArray returns true for array types.
	IsArray() bool

	// ArrayDimensions returns the number of array dimensions (0 for non-arrays).
	ArrayDimensions() int

	// ElementType returns the innermost element type (strips all array layers). Returns self for non-arrays.
	ElementType() JavaType

	// ComponentType returns the type with one array dimension removed. Returns nil for non-arrays.
	ComponentType() JavaType

	// StackCategory returns the JVM stack computation category (1 or 2).
	// Long and double are category 2; all others are category 1.
	StackCategory() int

	// String returns a human-readable representation.
	String() string
}

// RawType represents a JVM primitive type, void, or the special null/ref types.
type RawType int

const (
	TypeBoolean       RawType = iota // boolean — JVM uses int for storage
	TypeByte                         // byte
	TypeChar                         // char
	TypeShort                        // short
	TypeInt                          // int
	TypeLong                         // long
	TypeFloat                        // float
	TypeDouble                       // double
	TypeVoid                         // void — not a real value type
	TypeRef                          // generic reference (used internally during analysis)
	TypeNull                         // the null literal type
	TypeReturnAddress                // JSR return address (deprecated)
)

var rawTypeNames = [...]string{
	TypeBoolean:       "boolean",
	TypeByte:          "byte",
	TypeChar:          "char",
	TypeShort:         "short",
	TypeInt:           "int",
	TypeLong:          "long",
	TypeFloat:         "float",
	TypeDouble:        "double",
	TypeVoid:          "void",
	TypeRef:           "reference",
	TypeNull:          "null",
	TypeReturnAddress: "returnAddress",
}

var rawTypeDescriptors = [...]string{
	TypeBoolean: "Z",
	TypeByte:    "B",
	TypeChar:    "C",
	TypeShort:   "S",
	TypeInt:     "I",
	TypeLong:    "J",
	TypeFloat:   "F",
	TypeDouble:  "D",
	TypeVoid:    "V",
}

var rawTypeBoxedNames = map[RawType]string{
	TypeBoolean: "java.lang.Boolean",
	TypeByte:    "java.lang.Byte",
	TypeChar:    "java.lang.Character",
	TypeShort:   "java.lang.Short",
	TypeInt:     "java.lang.Integer",
	TypeLong:    "java.lang.Long",
	TypeFloat:   "java.lang.Float",
	TypeDouble:  "java.lang.Double",
}

// boxedToRaw maps boxed class names to their primitive types.
var boxedToRaw = map[string]RawType{}

// nameToRaw maps primitive type names to RawType values.
var nameToRaw = map[string]RawType{}

func init() {
	for rt, boxed := range rawTypeBoxedNames {
		boxedToRaw[boxed] = rt
	}

	for rt := TypeBoolean; rt <= TypeVoid; rt++ {
		nameToRaw[rawTypeNames[rt]] = rt
	}
}

// PrimitiveFromName returns the RawType for a primitive type name (e.g. "int").
func PrimitiveFromName(name string) (RawType, bool) {
	rt, ok := nameToRaw[name]
	return rt, ok
}

// UnboxedTypeFor returns the primitive type for a boxed class name, if any.
func UnboxedTypeFor(className string) (RawType, bool) {
	rt, ok := boxedToRaw[className]
	return rt, ok
}

func (rt RawType) Name() string {
	if int(rt) < len(rawTypeNames) {
		return rawTypeNames[rt]
	}

	return fmt.Sprintf("RawType(%d)", rt)
}

func (rt RawType) RawName() string         { return rt.Name() }
func (rt RawType) String() string          { return rt.Name() }
func (rt RawType) IsArray() bool           { return false }
func (rt RawType) ArrayDimensions() int    { return 0 }
func (rt RawType) ElementType() JavaType   { return rt }
func (rt RawType) ComponentType() JavaType { return nil }

func (rt RawType) Descriptor() string {
	if int(rt) < len(rawTypeDescriptors) && rawTypeDescriptors[rt] != "" {
		return rawTypeDescriptors[rt]
	}

	return ""
}

func (rt RawType) IsObject() bool {
	return rt == TypeRef || rt == TypeNull || rt == TypeReturnAddress
}

func (rt RawType) IsPrimitive() bool {
	return rt >= TypeBoolean && rt <= TypeDouble
}

func (rt RawType) StackCategory() int {
	if rt == TypeLong || rt == TypeDouble {
		return 2
	}

	if rt == TypeVoid {
		return 0
	}

	return 1
}

// BoxedName returns the fully qualified name of the boxed wrapper class, if any.
func (rt RawType) BoxedName() string {
	return rawTypeBoxedNames[rt]
}

// IsNumeric returns true for numeric primitives (byte through double).
func (rt RawType) IsNumeric() bool {
	return rt >= TypeByte && rt <= TypeDouble
}

// IsIntegral returns true for integer-category primitives (boolean, byte, char, short, int).
func (rt RawType) IsIntegral() bool {
	return rt >= TypeBoolean && rt <= TypeInt
}

// SimplifyJavaLang converts fully qualified class names to simple names.
// Since the decompiler now generates import statements, all class references
// can use their simple name (last dot-separated component).
// For example: "java.lang.String" → "String", "org.benf.cfr.reader.Foo" → "Foo".
func SimplifyJavaLang(name string) string {
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		return name[idx+1:]
	}

	return name
}

// sourceClassName converts a binary JVM class name into Java source form.
// Nested classes keep their package, but inner separators become dots:
// "java.lang.invoke.MethodHandles$Lookup" -> "java.lang.invoke.MethodHandles.Lookup".
func sourceClassName(className string) string {
	if className == "" {
		return ""
	}

	lastDot := strings.LastIndex(className, ".")
	if lastDot < 0 {
		return strings.ReplaceAll(className, "$", ".")
	}

	pkg := className[:lastDot]
	name := strings.ReplaceAll(className[lastDot+1:], "$", ".")

	if pkg == "" {
		return name
	}

	return pkg + "." + name
}

// RefType represents a class or interface type (non-array, non-primitive).
type RefType struct {
	className string // Fully qualified dotted name (e.g. "java.lang.String")
}

// NewRefType creates a reference type from a fully qualified dotted class name.
func NewRefType(className string) *RefType {
	return &RefType{className: className}
}

// NewRefTypeFromInternal creates a reference type from a JVM internal name (e.g. "java/lang/String").
func NewRefTypeFromInternal(internalName string) *RefType {
	return &RefType{className: strings.ReplaceAll(internalName, "/", ".")}
}

func (rt *RefType) Name() string            { return SimplifyJavaLang(sourceClassName(rt.className)) }
func (rt *RefType) RawName() string         { return rt.className }
func (rt *RefType) String() string          { return rt.className }
func (rt *RefType) IsObject() bool          { return true }
func (rt *RefType) IsPrimitive() bool       { return false }
func (rt *RefType) IsArray() bool           { return false }
func (rt *RefType) ArrayDimensions() int    { return 0 }
func (rt *RefType) ElementType() JavaType   { return rt }
func (rt *RefType) ComponentType() JavaType { return nil }
func (rt *RefType) StackCategory() int      { return 1 }

func (rt *RefType) Descriptor() string {
	return "L" + strings.ReplaceAll(rt.className, ".", "/") + ";"
}

// InternalName returns the JVM internal form (e.g. "java/lang/String").
func (rt *RefType) InternalName() string {
	return strings.ReplaceAll(rt.className, ".", "/")
}

// SimpleName returns the unqualified class name (e.g. "String" from "java.lang.String").
func (rt *RefType) SimpleName() string {
	return SimplifyJavaLang(sourceClassName(rt.className))
}

// PackageName returns the package name (e.g. "java.lang" from "java.lang.String").
func (rt *RefType) PackageName() string {
	idx := strings.LastIndex(rt.className, ".")
	if idx >= 0 {
		return rt.className[:idx]
	}

	return ""
}

// ArrayType represents an array type with a specific number of dimensions.
type ArrayType struct {
	Dimensions     int
	UnderlyingType JavaType
}

// NewArrayType creates an array type wrapping the given element type.
func NewArrayType(dimensions int, elementType JavaType) *ArrayType {
	return &ArrayType{Dimensions: dimensions, UnderlyingType: elementType}
}

func (at *ArrayType) Name() string {
	var b strings.Builder
	b.WriteString(at.UnderlyingType.Name())

	for range at.Dimensions {
		b.WriteString("[]")
	}

	return b.String()
}

func (at *ArrayType) RawName() string      { return at.Name() }
func (at *ArrayType) String() string       { return at.Name() }
func (at *ArrayType) IsObject() bool       { return true }
func (at *ArrayType) IsPrimitive() bool    { return false }
func (at *ArrayType) IsArray() bool        { return true }
func (at *ArrayType) ArrayDimensions() int { return at.Dimensions }
func (at *ArrayType) StackCategory() int   { return 1 }

func (at *ArrayType) ElementType() JavaType {
	return at.UnderlyingType
}

func (at *ArrayType) ComponentType() JavaType {
	if at.Dimensions == 1 {
		return at.UnderlyingType
	}

	return NewArrayType(at.Dimensions-1, at.UnderlyingType)
}

func (at *ArrayType) Descriptor() string {
	var b strings.Builder
	for range at.Dimensions {
		b.WriteByte('[')
	}

	b.WriteString(at.UnderlyingType.Descriptor())

	return b.String()
}
