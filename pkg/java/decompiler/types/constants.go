package types

// Well-known Java types used frequently during decompilation.
var (
	ObjectType        = NewRefType("java.lang.Object")
	StringType        = NewRefType("java.lang.String")
	ClassType         = NewRefType("java.lang.Class")
	ThrowableType     = NewRefType("java.lang.Throwable")
	EnumType          = NewRefType("java.lang.Enum")
	RecordType        = NewRefType("java.lang.Record")
	IterableType      = NewRefType("java.lang.Iterable")
	ComparableType    = NewRefType("java.lang.Comparable")
	SerializableType  = NewRefType("java.io.Serializable")
	CloseableType     = NewRefType("java.io.Closeable")
	AutoCloseableType = NewRefType("java.lang.AutoCloseable")
	NumberType        = NewRefType("java.lang.Number")
)
