/*
Copyright (c) 2026 Security Research
*/
package il

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	strstd "strings"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"
)

// Instruction is one decoded IL instruction. Operand's concrete type depends on
// Op.Operand: int32/int64/float64/int8/Token/uint16/[]int32/nil.
type Instruction struct {
	Offset  uint32
	Op      Opcode
	Operand any
}

var errTruncOperand = errors.New("instruction operand truncated")

// Instructions decodes Code into a linear instruction stream.
func (b *MethodBody) Instructions() ([]Instruction, error) {
	code := b.Code
	var out []Instruction
	for pc := 0; pc < len(code); {
		start := pc
		var prefixed bool
		op := code[pc]
		pc++
		if op == 0xFE {
			if pc >= len(code) {
				return nil, fmt.Errorf("truncated 0xFE prefix at %d: %w", start, errTruncOperand)
			}
			prefixed = true
			op = code[pc]
			pc++
		}
		oc, ok := lookupOpcode(prefixed, op)
		if !ok {
			return nil, fmt.Errorf("unknown opcode prefixed=%v %#x at %d", prefixed, op, start)
		}
		operand, n, err := decodeOperand(oc.Operand, code[pc:])
		if err != nil {
			return nil, fmt.Errorf("opcode %q at %d: %w", oc.Name, start, err)
		}
		pc += n
		out = append(out, Instruction{Offset: uint32(start), Op: oc, Operand: operand})
	}
	return out, nil
}

func need(b []byte, n int) error {
	if len(b) < n {
		return errTruncOperand
	}
	return nil
}

// decodeOperand returns (operand, bytesConsumed, error).
func decodeOperand(class OperandClass, b []byte) (any, int, error) {
	switch class {
	case InlineNone:
		return nil, 0, nil
	case ShortInlineI:
		if err := need(b, 1); err != nil {
			return nil, 0, err
		}
		return int8(b[0]), 1, nil
	case ShortInlineVar:
		if err := need(b, 1); err != nil {
			return nil, 0, err
		}
		return uint8(b[0]), 1, nil
	case ShortInlineBrTarget:
		if err := need(b, 1); err != nil {
			return nil, 0, err
		}
		return int8(b[0]), 1, nil
	case ShortInlineR:
		if err := need(b, 4); err != nil {
			return nil, 0, err
		}
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(b))), 4, nil
	case InlineVar:
		if err := need(b, 2); err != nil {
			return nil, 0, err
		}
		return binary.LittleEndian.Uint16(b), 2, nil
	case InlineI, InlineBrTarget:
		if err := need(b, 4); err != nil {
			return nil, 0, err
		}
		return int32(binary.LittleEndian.Uint32(b)), 4, nil
	case InlineMethod, InlineField, InlineType, InlineTok, InlineString, InlineSig:
		if err := need(b, 4); err != nil {
			return nil, 0, err
		}
		return Token(binary.LittleEndian.Uint32(b)), 4, nil
	case InlineI8:
		if err := need(b, 8); err != nil {
			return nil, 0, err
		}
		return int64(binary.LittleEndian.Uint64(b)), 8, nil
	case InlineR:
		if err := need(b, 8); err != nil {
			return nil, 0, err
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b)), 8, nil
	case InlineSwitch:
		if err := need(b, 4); err != nil {
			return nil, 0, err
		}
		n := int(binary.LittleEndian.Uint32(b))
		total := 4 + n*4
		if err := need(b, total); err != nil {
			return nil, 0, err
		}
		targets := make([]int32, n)
		for i := 0; i < n; i++ {
			targets[i] = int32(binary.LittleEndian.Uint32(b[4+i*4:]))
		}
		return targets, total, nil
	default:
		return nil, 0, fmt.Errorf("unhandled operand class %d", class)
	}
}

// TokenResolver maps metadata tokens to display text.
type TokenResolver interface {
	Method(Token) string
	Field(Token) string
	Type(Token) string
	UserString(Token) string
}

// resolveOperand renders a token operand for IL text and call-graph use.
// MethodSpec/TypeSpec tokens degrade to raw token text (generic resolution is
// out of M0 scope, spec §4).
func resolveOperand(class OperandClass, tok Token, res TokenResolver) string {
	switch tok.TableID() {
	case clrtok.TblMethodSpec, clrtok.TblTypeSpec:
		return rawToken(tok)
	}
	switch class {
	case InlineMethod:
		if s := res.Method(tok); s != "" {
			return s
		}
	case InlineField:
		if s := res.Field(tok); s != "" {
			return s
		}
	case InlineType:
		if s := res.Type(tok); s != "" {
			return s
		}
	case InlineString:
		if s := res.UserString(tok); s != "" {
			return s
		}
	case InlineTok:
		// ldtoken: dispatch on table id.
		switch tok.TableID() {
		case clrtok.TblMethodDef, clrtok.TblMemberRef:
			if s := res.Method(tok); s != "" {
				return s
			}
		case clrtok.TblField:
			if s := res.Field(tok); s != "" {
				return s
			}
		case clrtok.TblTypeDef, clrtok.TblTypeRef:
			if s := res.Type(tok); s != "" {
				return s
			}
		}
	}
	return rawToken(tok)
}

func rawToken(tok Token) string {
	return fmt.Sprintf("/* token %#08x */", uint32(tok))
}

// callOpcodes are the opcodes whose method-token operand is a call-graph edge.
var callOpcodes = map[string]bool{
	"call": true, "callvirt": true, "newobj": true, "ldftn": true, "ldvirtftn": true,
}

// Disassemble renders IL text and extracts the call graph (callees), and the
// literal #US strings referenced by ldstr. Field/type tokens are rendered in
// the text but are not part of the callee edge set.
func Disassemble(b *MethodBody, res TokenResolver) (il string, callees []Token, strings []string) {
	if b.IsNative {
		return "// native/unmanaged body\n", nil, nil
	}
	ins, err := b.Instructions()
	if err != nil {
		return fmt.Sprintf("// <undecodable: %v>\n", err), nil, nil
	}
	var sb stringsBuilder
	seenCallee := map[uint32]bool{}
	for _, in := range ins {
		sb.line(in.Offset, in.Op.Name, renderInstr(in, res))
		tok, isTok := in.Operand.(Token)
		if !isTok {
			continue
		}
		if callOpcodes[in.Op.Name] {
			if !seenCallee[uint32(tok)] {
				seenCallee[uint32(tok)] = true
				callees = append(callees, tok)
			}
		}
		if in.Op.Name == "ldstr" {
			strings = append(strings, res.UserString(tok))
		}
	}
	return sb.String(), callees, strings
}

// renderInstr returns the operand text for an instruction (token-resolved).
func renderInstr(in Instruction, res TokenResolver) string {
	switch v := in.Operand.(type) {
	case nil:
		return ""
	case Token:
		return resolveOperand(in.Op.Operand, v, res)
	case []int32:
		parts := make([]string, len(v))
		for i, t := range v {
			parts[i] = fmt.Sprintf("IL_%04x", int(in.Offset)+int(t))
		}
		return "(" + strstd.Join(parts, ", ") + ")"
	case int8: // short branch target: relative to next instruction
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// stringsBuilder wraps strings.Builder with IL line formatting.
type stringsBuilder struct{ b strstd.Builder }

func (s *stringsBuilder) line(off uint32, name, operand string) {
	if operand == "" {
		fmt.Fprintf(&s.b, "IL_%04x: %s\n", off, name)
		return
	}
	fmt.Fprintf(&s.b, "IL_%04x: %-12s %s\n", off, name, operand)
}
func (s *stringsBuilder) String() string { return s.b.String() }
