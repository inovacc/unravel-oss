package attr

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// ConstantValue holds a constant value index for a field.
type ConstantValue struct {
	ValueIndex uint16
}

func (*ConstantValue) Name() string { return "ConstantValue" }

func readConstantValue(r *reader.Reader) (Attribute, error) {
	idx, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	return &ConstantValue{ValueIndex: idx}, nil
}

// Exceptions lists the checked exceptions a method may throw.
type Exceptions struct {
	ExceptionIndexTable []uint16
}

func (*Exceptions) Name() string { return "Exceptions" }

func readExceptions(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	table := make([]uint16, count)
	for i := range table {
		if table[i], err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &Exceptions{ExceptionIndexTable: table}, nil
}

// SourceFile holds the source file name.
type SourceFile struct {
	SourceFileName string
}

func (*SourceFile) Name() string { return "SourceFile" }

func readSourceFile(r *reader.Reader, cp *constantpool.Pool) (Attribute, error) {
	idx, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	return &SourceFile{SourceFileName: cp.UTF8(idx)}, nil
}

// Signature holds a generic signature string.
type Signature struct {
	SignatureValue string
}

func (*Signature) Name() string { return "Signature" }

func readSignature(r *reader.Reader, cp *constantpool.Pool) (Attribute, error) {
	idx, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	return &Signature{SignatureValue: cp.UTF8(idx)}, nil
}

// Synthetic marks a class member as compiler-generated.
type Synthetic struct{}

func (*Synthetic) Name() string { return "Synthetic" }

// Deprecated marks a class, field, or method as deprecated.
type Deprecated struct{}

func (*Deprecated) Name() string { return "Deprecated" }

// EnclosingMethod identifies the enclosing class and method of a local/anonymous class.
type EnclosingMethod struct {
	ClassIndex  uint16
	MethodIndex uint16
}

func (*EnclosingMethod) Name() string { return "EnclosingMethod" }

func readEnclosingMethod(r *reader.Reader) (Attribute, error) {
	classIdx, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	methodIdx, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	return &EnclosingMethod{ClassIndex: classIdx, MethodIndex: methodIdx}, nil
}

// NestHost identifies the nest host of a class.
type NestHost struct {
	HostClassIndex uint16
}

func (*NestHost) Name() string { return "NestHost" }

func readNestHost(r *reader.Reader) (Attribute, error) {
	idx, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	return &NestHost{HostClassIndex: idx}, nil
}

// NestMembers lists the nest members of a class.
type NestMembers struct {
	Classes []uint16
}

func (*NestMembers) Name() string { return "NestMembers" }

func readNestMembers(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	classes := make([]uint16, count)
	for i := range classes {
		if classes[i], err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &NestMembers{Classes: classes}, nil
}

// PermittedSubclasses lists the permitted subclasses (sealed classes).
type PermittedSubclasses struct {
	Classes []uint16
}

func (*PermittedSubclasses) Name() string { return "PermittedSubclasses" }

func readPermittedSubclasses(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	classes := make([]uint16, count)
	for i := range classes {
		if classes[i], err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &PermittedSubclasses{Classes: classes}, nil
}

// MethodParameters holds parameter names and flags.
type MethodParameters struct {
	Parameters []MethodParameter
}

func (*MethodParameters) Name() string { return "MethodParameters" }

// MethodParameter is a single method parameter entry.
type MethodParameter struct {
	NameIndex   uint16
	AccessFlags uint16
}

func readMethodParameters(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU1()
	if err != nil {
		return nil, err
	}

	params := make([]MethodParameter, count)
	for i := range params {
		if params[i].NameIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if params[i].AccessFlags, err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &MethodParameters{Parameters: params}, nil
}

// LineNumberTable maps bytecode offsets to source line numbers.
type LineNumberTable struct {
	Entries []LineNumberEntry
}

func (*LineNumberTable) Name() string { return "LineNumberTable" }

// LineNumberEntry maps a bytecode PC to a source line number.
type LineNumberEntry struct {
	StartPC    uint16
	LineNumber uint16
}

func readLineNumberTable(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	entries := make([]LineNumberEntry, count)
	for i := range entries {
		if entries[i].StartPC, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].LineNumber, err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &LineNumberTable{Entries: entries}, nil
}

// LocalVariableTable holds local variable debug info.
type LocalVariableTable struct {
	Entries []LocalVariableEntry
}

func (*LocalVariableTable) Name() string { return "LocalVariableTable" }

// LocalVariableEntry describes a local variable's scope and type.
type LocalVariableEntry struct {
	StartPC         uint16
	Length          uint16
	NameIndex       uint16
	DescriptorIndex uint16
	Index           uint16
}

func readLocalVariableTable(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	entries := make([]LocalVariableEntry, count)
	for i := range entries {
		if entries[i].StartPC, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].Length, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].NameIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].DescriptorIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].Index, err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &LocalVariableTable{Entries: entries}, nil
}

// LocalVariableTypeTable holds local variable generic type info.
type LocalVariableTypeTable struct {
	Entries []LocalVariableTypeEntry
}

func (*LocalVariableTypeTable) Name() string { return "LocalVariableTypeTable" }

// LocalVariableTypeEntry extends LocalVariableEntry with signature info.
type LocalVariableTypeEntry struct {
	StartPC        uint16
	Length         uint16
	NameIndex      uint16
	SignatureIndex uint16
	Index          uint16
}

func readLocalVariableTypeTable(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	entries := make([]LocalVariableTypeEntry, count)
	for i := range entries {
		if entries[i].StartPC, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].Length, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].NameIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].SignatureIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if entries[i].Index, err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &LocalVariableTypeTable{Entries: entries}, nil
}

// InnerClasses lists the inner class relationships.
type InnerClasses struct {
	Classes []InnerClassEntry
}

func (*InnerClasses) Name() string { return "InnerClasses" }

// InnerClassEntry describes a single inner class relationship.
type InnerClassEntry struct {
	InnerClassInfoIndex   uint16
	OuterClassInfoIndex   uint16
	InnerNameIndex        uint16
	InnerClassAccessFlags uint16
}

func readInnerClasses(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	classes := make([]InnerClassEntry, count)
	for i := range classes {
		if classes[i].InnerClassInfoIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if classes[i].OuterClassInfoIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if classes[i].InnerNameIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if classes[i].InnerClassAccessFlags, err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	return &InnerClasses{Classes: classes}, nil
}

// BootstrapMethods holds bootstrap method specifiers for invokedynamic.
type BootstrapMethods struct {
	Methods []BootstrapMethod
}

func (*BootstrapMethods) Name() string { return "BootstrapMethods" }

// BootstrapMethod is a single bootstrap method specifier.
type BootstrapMethod struct {
	MethodRef     uint16
	BootstrapArgs []uint16
}

func readBootstrapMethods(r *reader.Reader) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	methods := make([]BootstrapMethod, count)
	for i := range methods {
		if methods[i].MethodRef, err = r.ReadU2(); err != nil {
			return nil, err
		}

		numArgs, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		methods[i].BootstrapArgs = make([]uint16, numArgs)
		for j := range methods[i].BootstrapArgs {
			if methods[i].BootstrapArgs[j], err = r.ReadU2(); err != nil {
				return nil, err
			}
		}
	}

	return &BootstrapMethods{Methods: methods}, nil
}

// Record holds the record components.
type Record struct {
	Components []RecordComponent
}

func (*Record) Name() string { return "Record" }

// RecordComponent represents a record component.
type RecordComponent struct {
	NameIndex       uint16
	DescriptorIndex uint16
	Attributes      *Map
}

func readRecord(r *reader.Reader, cp *constantpool.Pool) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	components := make([]RecordComponent, count)
	for i := range components {
		if components[i].NameIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if components[i].DescriptorIndex, err = r.ReadU2(); err != nil {
			return nil, err
		}

		attrCount, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		components[i].Attributes, err = ReadAttributes(r, cp, attrCount)
		if err != nil {
			return nil, fmt.Errorf("read record component attributes: %w", err)
		}
	}

	return &Record{Components: components}, nil
}
