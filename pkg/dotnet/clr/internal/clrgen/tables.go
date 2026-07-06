/*
Copyright (c) 2026 Security Research
*/
package clrgen

import "github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"

// methodDefToken builds the clrtok.Token for the i-th MethodDef row (1-based
// RowID). The P/Invoke emitter uses clrtok.Token + the Tbl* consts for every
// cross-table reference (ECMA-335 II.22), so clrgen never imports package clr
// (which imports metadata/sig/il and would otherwise cycle).
func methodDefToken(rowID uint32) clrtok.Token {
	return clrtok.Token(uint32(clrtok.TblMethodDef)<<24 | (rowID & 0x00FFFFFF))
}

// emitPInvokeTables appends the ModuleRef (0x1A) and ImplMap (0x1C) rows for the
// builder's P/Invokes. Both tables index #Strings by 2-byte offset (HeapSizes=0).
//
//   - ModuleRef (II.22.31): Name(str). One row per distinct native module; here
//     each P/Invoke gets its own ModuleRef for a 1:1, deterministic layout.
//   - ImplMap (II.22.22): MappingFlags(u16), MemberForwarded(coded
//     ciMemberForwarded), ImportName(str), ImportScope(ModuleRef simple idx).
//
// MemberForwarded points at the forwarded MethodDef. ciMemberForwarded has the
// table set {Field=0x04, MethodDef=0x06} with tag 1 == MethodDef, so the raw
// coded value is (RowID<<1)|1. The forwarded MethodDef is the (methodBase+i)-th
// emitted method.
// emitPtrIndirection appends a single MethodPtr (Tbl 0x05) row when the builder's
// WithPtrIndirection knob is set. MethodPtr (II.22.27) is one column: a MethodDef
// index (2 bytes at HeapSizes=0). Its mere presence flips bit 0x05 in the #~ Valid
// mask, which the reader rejects via ErrIndirectionTablesUnsupported — proving the
// reader never silently parses through *Ptr indirection (spec §3 Must-fix #3).
func (b *Builder) emitPtrIndirection(tl *tableLayoutBuilder) {
	if !b.emitPtrTables {
		return
	}
	tl.row(0x05, u16b(1)...) // MethodPtr -> MethodDef rid 1
}

func (b *Builder) emitPInvokeTables(tl *tableLayoutBuilder, h *heapBuilder, methodBase uint16) {
	for i, pv := range b.pinvokes {
		moduleRef := uint16(i + 1) // 1-based ModuleRef rid for this P/Invoke

		// ModuleRef row: Name only.
		tl.row(0x1A, strIdx(h, pv.module)...)

		// ImplMap row.
		fwd := methodDefToken(uint32(methodBase) + uint32(i))
		coded := uint16(fwd.RowID()<<1) | 1 // ciMemberForwarded tag 1 == MethodDef
		row := concat(
			u16b(0),             // MappingFlags
			u16b(coded),         // MemberForwarded (coded ciMemberForwarded)
			strIdx(h, pv.entry), // ImportName
			u16b(moduleRef),     // ImportScope -> ModuleRef rid
		)
		tl.row(0x1C, row...)
	}
}
