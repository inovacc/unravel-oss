package attr

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// Code represents the Code attribute containing bytecode.
type Code struct {
	MaxStack       uint16
	MaxLocals      uint16
	Bytecode       []byte
	ExceptionTable []ExceptionEntry
	Attributes     *Map
}

func (*Code) Name() string { return "Code" }

// ExceptionEntry is one entry in the exception table.
type ExceptionEntry struct {
	StartPC   uint16
	EndPC     uint16
	HandlerPC uint16
	CatchType uint16 // 0 = finally, otherwise index into constant pool
}

func readCode(r *reader.Reader, cp *constantpool.Pool) (*Code, error) {
	maxStack, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read max_stack: %w", err)
	}

	maxLocals, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read max_locals: %w", err)
	}

	codeLen, err := r.ReadU4()
	if err != nil {
		return nil, fmt.Errorf("read code_length: %w", err)
	}

	bytecode, err := r.ReadBytes(int(codeLen))
	if err != nil {
		return nil, fmt.Errorf("read bytecode: %w", err)
	}

	exTableLen, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read exception_table_length: %w", err)
	}

	exTable := make([]ExceptionEntry, exTableLen)
	for i := range exTable {
		if exTable[i].StartPC, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if exTable[i].EndPC, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if exTable[i].HandlerPC, err = r.ReadU2(); err != nil {
			return nil, err
		}

		if exTable[i].CatchType, err = r.ReadU2(); err != nil {
			return nil, err
		}
	}

	attrCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read code attributes count: %w", err)
	}

	attrs, err := ReadAttributes(r, cp, attrCount)
	if err != nil {
		return nil, fmt.Errorf("read code attributes: %w", err)
	}

	return &Code{
		MaxStack:       maxStack,
		MaxLocals:      maxLocals,
		Bytecode:       bytecode,
		ExceptionTable: exTable,
		Attributes:     attrs,
	}, nil
}
