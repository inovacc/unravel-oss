package sig

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"
)

func TestTypeSigString(t *testing.T) {
	classTok := clrtok.Token(uint32(0x01)<<24 | 4) // TypeRef rid 4
	tests := []struct {
		name string
		in   TypeSig
		want string
	}{
		{"void", TypeSig{Kind: ETVoid}, "void"},
		{"i4", TypeSig{Kind: ETI4}, "int32"},
		{"string", TypeSig{Kind: ETString}, "string"},
		{"object", TypeSig{Kind: ETObject}, "object"},
		{"szarray i4", TypeSig{Kind: ETSZArray, Elem: &TypeSig{Kind: ETI4}}, "int32[]"},
		{
			"array rank2 i4",
			TypeSig{Kind: ETArray, Elem: &TypeSig{Kind: ETI4}, Rank: 2},
			"int32[,]",
		},
		{"ptr u1", TypeSig{Kind: ETPtr, Elem: &TypeSig{Kind: ETU1}}, "uint8*"},
		{"byref string", TypeSig{Kind: ETByRef, Elem: &TypeSig{Kind: ETString}}, "string&"},
		{"var0", TypeSig{Kind: ETVar, GenIndex: 0}, "!0"},
		{"mvar1", TypeSig{Kind: ETMVar, GenIndex: 1}, "!!1"},
		{"class", TypeSig{Kind: ETClass, Token: classTok}, "class 0x01000004"},
		{
			"genericinst",
			TypeSig{
				Kind: ETGenericInst,
				Elem: &TypeSig{Kind: ETClass, Token: classTok},
				Args: []TypeSig{{Kind: ETString}, {Kind: ETI4}},
			},
			"class 0x01000004<string,int32>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
