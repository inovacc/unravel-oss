package classfile

import "strings"

// AccessFlags represents a set of access flags for classes, fields, or methods.
type AccessFlags uint16

// Class access flags.
const (
	AccPublic     AccessFlags = 0x0001
	AccPrivate    AccessFlags = 0x0002
	AccProtected  AccessFlags = 0x0004
	AccStatic     AccessFlags = 0x0008
	AccFinal      AccessFlags = 0x0010
	AccSuper      AccessFlags = 0x0020 // Class: treat superclass methods specially
	AccVolatile   AccessFlags = 0x0040 // Field
	AccBridge     AccessFlags = 0x0040 // Method
	AccTransient  AccessFlags = 0x0080 // Field
	AccVarargs    AccessFlags = 0x0080 // Method
	AccNative     AccessFlags = 0x0100 // Method
	AccInterface  AccessFlags = 0x0200
	AccAbstract   AccessFlags = 0x0400
	AccStrict     AccessFlags = 0x0800 // strictfp
	AccSynthetic  AccessFlags = 0x1000
	AccAnnotation AccessFlags = 0x2000
	AccEnum       AccessFlags = 0x4000
	AccModule     AccessFlags = 0x8000
)

// Has returns true if the flag is set.
func (a AccessFlags) Has(flag AccessFlags) bool {
	return a&flag != 0
}

// ClassAccessString returns the access flags as a Java class modifier string.
func (a AccessFlags) ClassAccessString() string {
	var parts []string
	if a.Has(AccPublic) {
		parts = append(parts, "public")
	}

	if a.Has(AccFinal) {
		parts = append(parts, "final")
	}

	if a.Has(AccAbstract) {
		parts = append(parts, "abstract")
	}

	return strings.Join(parts, " ")
}

// FieldAccessString returns the access flags as a Java field modifier string.
func (a AccessFlags) FieldAccessString() string {
	var parts []string
	if a.Has(AccPublic) {
		parts = append(parts, "public")
	}

	if a.Has(AccPrivate) {
		parts = append(parts, "private")
	}

	if a.Has(AccProtected) {
		parts = append(parts, "protected")
	}

	if a.Has(AccStatic) {
		parts = append(parts, "static")
	}

	if a.Has(AccFinal) {
		parts = append(parts, "final")
	}

	if a.Has(AccVolatile) {
		parts = append(parts, "volatile")
	}

	if a.Has(AccTransient) {
		parts = append(parts, "transient")
	}

	return strings.Join(parts, " ")
}

// MethodAccessString returns the access flags as a Java method modifier string.
func (a AccessFlags) MethodAccessString() string {
	var parts []string
	if a.Has(AccPublic) {
		parts = append(parts, "public")
	}

	if a.Has(AccPrivate) {
		parts = append(parts, "private")
	}

	if a.Has(AccProtected) {
		parts = append(parts, "protected")
	}

	if a.Has(AccStatic) {
		parts = append(parts, "static")
	}

	if a.Has(AccFinal) {
		parts = append(parts, "final")
	}

	if a.Has(AccAbstract) {
		parts = append(parts, "abstract")
	}

	if a.Has(AccNative) {
		parts = append(parts, "native")
	}

	if a.Has(AccStrict) {
		parts = append(parts, "strictfp")
	}

	return strings.Join(parts, " ")
}

// IsInterface returns true if this is an interface.
func (a AccessFlags) IsInterface() bool { return a.Has(AccInterface) }

// IsEnum returns true if this is an enum.
func (a AccessFlags) IsEnum() bool { return a.Has(AccEnum) }

// IsAnnotation returns true if this is an annotation type.
func (a AccessFlags) IsAnnotation() bool { return a.Has(AccAnnotation) }

// IsModule returns true if this is a module.
func (a AccessFlags) IsModule() bool { return a.Has(AccModule) }

// IsSynthetic returns true if this is synthetic.
func (a AccessFlags) IsSynthetic() bool { return a.Has(AccSynthetic) }
