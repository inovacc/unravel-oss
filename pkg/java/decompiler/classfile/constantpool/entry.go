package constantpool

// Tag identifies the type of a constant pool entry.
type Tag uint8

const (
	TagUTF8               Tag = 1
	TagInteger            Tag = 3
	TagFloat              Tag = 4
	TagLong               Tag = 5
	TagDouble             Tag = 6
	TagClass              Tag = 7
	TagString             Tag = 8
	TagFieldRef           Tag = 9
	TagMethodRef          Tag = 10
	TagInterfaceMethodRef Tag = 11
	TagNameAndType        Tag = 12
	TagMethodHandle       Tag = 15
	TagMethodType         Tag = 16
	TagDynamic            Tag = 17
	TagInvokeDynamic      Tag = 18
	TagModule             Tag = 19
	TagPackage            Tag = 20
)

// String returns a human-readable name for the tag.
func (t Tag) String() string {
	switch t {
	case TagUTF8:
		return "UTF8"
	case TagInteger:
		return "Integer"
	case TagFloat:
		return "Float"
	case TagLong:
		return "Long"
	case TagDouble:
		return "Double"
	case TagClass:
		return "Class"
	case TagString:
		return "String"
	case TagFieldRef:
		return "FieldRef"
	case TagMethodRef:
		return "MethodRef"
	case TagInterfaceMethodRef:
		return "InterfaceMethodRef"
	case TagNameAndType:
		return "NameAndType"
	case TagMethodHandle:
		return "MethodHandle"
	case TagMethodType:
		return "MethodType"
	case TagDynamic:
		return "Dynamic"
	case TagInvokeDynamic:
		return "InvokeDynamic"
	case TagModule:
		return "Module"
	case TagPackage:
		return "Package"
	default:
		return "Unknown"
	}
}

// Entry is a single constant pool entry.
type Entry struct {
	Tag Tag

	// UTF8
	UTF8Value string

	// Integer / Float / Long / Double
	IntValue    int32
	FloatValue  float32
	LongValue   int64
	DoubleValue float64

	// Class, String, MethodType, Module, Package (single index)
	NameIndex uint16

	// FieldRef, MethodRef, InterfaceMethodRef
	ClassIndex       uint16
	NameAndTypeIndex uint16

	// NameAndType
	// NameIndex (reused) = name_index
	DescriptorIndex uint16

	// MethodHandle
	ReferenceKind  uint8
	ReferenceIndex uint16

	// Dynamic, InvokeDynamic
	BootstrapMethodAttrIndex uint16
	// NameAndTypeIndex (reused)
}

// IsWide returns true if this entry takes two constant pool slots (Long, Double).
func (e *Entry) IsWide() bool {
	return e.Tag == TagLong || e.Tag == TagDouble
}

// MethodHandleBehavior represents the reference_kind of CONSTANT_MethodHandle.
type MethodHandleBehavior uint8

const (
	RefGetField         MethodHandleBehavior = 1
	RefGetStatic        MethodHandleBehavior = 2
	RefPutField         MethodHandleBehavior = 3
	RefPutStatic        MethodHandleBehavior = 4
	RefInvokeVirtual    MethodHandleBehavior = 5
	RefInvokeStatic     MethodHandleBehavior = 6
	RefInvokeSpecial    MethodHandleBehavior = 7
	RefNewInvokeSpecial MethodHandleBehavior = 8
	RefInvokeInterface  MethodHandleBehavior = 9
)
