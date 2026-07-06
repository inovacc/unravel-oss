package sig

import (
	"fmt"
	"strings"
)

// ilPrimitiveNames maps primitive element types to ILAsm keyword names (II.7.1).
var ilPrimitiveNames = map[ElementType]string{
	ETVoid: "void", ETBoolean: "bool", ETChar: "char",
	ETI1: "int8", ETU1: "uint8", ETI2: "int16", ETU2: "uint16",
	ETI4: "int32", ETU4: "uint32", ETI8: "int64", ETU8: "uint64",
	ETR4: "float32", ETR8: "float64", ETString: "string",
	ETI: "native int", ETU: "native uint", ETObject: "object",
	ETTypedByRef: "typedref",
}

// String renders the TypeSig as IL-style text (the single printer for SIG).
func (s TypeSig) String() string {
	if name, ok := ilPrimitiveNames[s.Kind]; ok {
		return name
	}
	switch s.Kind {
	case ETSZArray:
		return s.elemString() + "[]"
	case ETArray:
		dims := ","
		if s.Rank > 0 {
			dims = strings.Repeat(",", int(s.Rank)-1)
		}
		return s.elemString() + "[" + dims + "]"
	case ETPtr:
		return s.elemString() + "*"
	case ETByRef:
		return s.elemString() + "&"
	case ETVar:
		return fmt.Sprintf("!%d", s.GenIndex)
	case ETMVar:
		return fmt.Sprintf("!!%d", s.GenIndex)
	case ETClass:
		return "class " + tokenString(s.Token)
	case ETValueType:
		return "valuetype " + tokenString(s.Token)
	case ETGenericInst:
		var b strings.Builder
		b.WriteString(s.elemString())
		b.WriteByte('<')
		for i := range s.Args {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(s.Args[i].String())
		}
		b.WriteByte('>')
		return b.String()
	default:
		return fmt.Sprintf("type(0x%02x)", byte(s.Kind))
	}
}

func (s TypeSig) elemString() string {
	if s.Elem == nil {
		return "?"
	}
	return s.Elem.String()
}
