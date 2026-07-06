/*
Copyright (c) 2026 Security Research
*/
package metadata

import (
	"encoding/binary"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok" // for clrtok.Token (leaf package; metadata must NOT import clr)
)

// colKind enumerates the metadata column families (II.22).
type colKind int

const (
	colUint16 colKind = iota
	colUint32
	colString
	colGUID
	colBlob
	colSimple // index into a single table (carries table id)
	colCoded  // coded index (carries codedKind)
)

type column struct {
	kind  colKind
	table byte      // for colSimple
	coded codedKind // for colCoded
}

// tableSchema maps an in-scope table id to its ordered columns. Tables not
// listed but present (e.g. CustomAttribute) still need a width: their schema is
// included so sizeTables can advance correctly even when we never decode rows.
//
// *Ptr tables (0x03/0x05/0x07/0x12/0x13) are intentionally absent — rejected in
// parseTilde before sizing (M0-7).
var tableSchema = map[byte][]column{
	0x00: {{kind: colUint16}, {kind: colString}, {kind: colGUID}, {kind: colGUID}, {kind: colGUID}},                                                                                 // Module
	0x01: {{kind: colCoded, coded: ciResolutionScope}, {kind: colString}, {kind: colString}},                                                                                        // TypeRef
	0x02: {{kind: colUint32}, {kind: colString}, {kind: colString}, {kind: colCoded, coded: ciTypeDefOrRef}, {kind: colSimple, table: 0x04}, {kind: colSimple, table: 0x06}},        // TypeDef
	0x04: {{kind: colUint16}, {kind: colString}, {kind: colBlob}},                                                                                                                   // Field
	0x06: {{kind: colUint32}, {kind: colUint16}, {kind: colUint16}, {kind: colString}, {kind: colBlob}, {kind: colSimple, table: 0x08}},                                             // MethodDef
	0x08: {{kind: colUint16}, {kind: colUint16}, {kind: colString}},                                                                                                                 // Param
	0x0A: {{kind: colCoded, coded: ciMemberRefParent}, {kind: colString}, {kind: colBlob}},                                                                                          // MemberRef
	0x0B: {{kind: colUint16}, {kind: colCoded, coded: ciHasConstant}, {kind: colBlob}},                                                                                              // Constant
	0x0C: {{kind: colCoded, coded: ciHasCustomAttr}, {kind: colCoded, coded: ciCustomAttrType}, {kind: colBlob}},                                                                    // CustomAttribute (present-only)
	0x1A: {{kind: colString}},                                                                                                                                                       // ModuleRef
	0x1C: {{kind: colUint16}, {kind: colCoded, coded: ciMemberForwarded}, {kind: colString}, {kind: colSimple, table: 0x1A}},                                                        // ImplMap
	0x20: {{kind: colUint32}, {kind: colUint16}, {kind: colUint16}, {kind: colUint16}, {kind: colUint16}, {kind: colUint32}, {kind: colBlob}, {kind: colString}, {kind: colString}}, // Assembly
	0x23: {{kind: colUint16}, {kind: colUint16}, {kind: colUint16}, {kind: colUint16}, {kind: colUint32}, {kind: colBlob}, {kind: colString}, {kind: colString}, {kind: colBlob}},   // AssemblyRef
	0x26: {{kind: colUint32}, {kind: colString}, {kind: colBlob}},                                                                                                                   // File
	0x27: {{kind: colUint32}, {kind: colUint32}, {kind: colString}, {kind: colString}, {kind: colCoded, coded: ciImplementation}},                                                   // ExportedType
}

// colWidth resolves a single column's byte width given current table sizes.
func (t *Tables) colWidth(c column) int {
	switch c.kind {
	case colUint16:
		return 2
	case colUint32:
		return 4
	case colString:
		return t.stringIdxWidth()
	case colGUID:
		return t.guidIdxWidth()
	case colBlob:
		return t.blobIdxWidth()
	case colSimple:
		return t.simpleIdxWidth(c.table)
	case colCoded:
		return t.codedIdxWidth(c.coded)
	}
	return 0
}

// rowWidthOf sums the column widths for table id (replaces the M0-2 stub).
func (t *Tables) rowWidthOf(id byte) int {
	w := 0
	for _, c := range tableSchema[id] {
		w += t.colWidth(c)
	}
	return w
}

// colOffsets returns the per-column byte offsets within a row of table id.
func (t *Tables) colOffsets(id byte) []int {
	offs := make([]int, len(tableSchema[id]))
	p := 0
	for i, c := range tableSchema[id] {
		offs[i] = p
		p += t.colWidth(c)
	}
	return offs
}

// readCol reads column ci of row (0-based) from table id as a raw uint32.
func (t *Tables) readCol(id byte, row int, ci int) uint32 {
	w := t.colWidth(tableSchema[id][ci])
	base := row*int(t.rowWidth[id]) + t.colOffsets(id)[ci]
	d := t.rowData[id]
	if base+w > len(d) {
		return 0
	}
	if w == 2 {
		return uint32(binary.LittleEndian.Uint16(d[base:]))
	}
	return binary.LittleEndian.Uint32(d[base:])
}

// Assembly decodes the single Assembly row (II.22.2).
func (t *Tables) Assembly() (AssemblyInfo, bool) {
	if t.rowCount[0x20] == 0 {
		return AssemblyInfo{}, false
	}
	var a AssemblyInfo
	a.Version = [4]uint16{
		uint16(t.readCol(0x20, 0, 1)), uint16(t.readCol(0x20, 0, 2)),
		uint16(t.readCol(0x20, 0, 3)), uint16(t.readCol(0x20, 0, 4)),
	}
	a.PublicKey = t.heaps.Blob(t.readCol(0x20, 0, 6))
	a.Name = t.heaps.Strings(t.readCol(0x20, 0, 7))
	a.Culture = t.heaps.Strings(t.readCol(0x20, 0, 8))
	return a, true
}

// AssemblyRefs decodes all AssemblyRef rows (II.22.5).
func (t *Tables) AssemblyRefs() []AssemblyRef {
	n := int(t.rowCount[0x23])
	out := make([]AssemblyRef, 0, n)
	for r := 0; r < n; r++ {
		out = append(out, AssemblyRef{
			Version: [4]uint16{
				uint16(t.readCol(0x23, r, 0)), uint16(t.readCol(0x23, r, 1)),
				uint16(t.readCol(0x23, r, 2)), uint16(t.readCol(0x23, r, 3)),
			},
			PublicKeyOrToken: t.heaps.Blob(t.readCol(0x23, r, 5)),
			Name:             t.heaps.Strings(t.readCol(0x23, r, 6)),
			Culture:          t.heaps.Strings(t.readCol(0x23, r, 7)),
		})
	}
	return out
}

// UserStrings returns every non-empty #US literal in heap order.
func (t *Tables) UserStrings() []string { return t.heaps.allUserStrings() }

// AssemblyInfo is the frozen typed view of the single Assembly row (II.22.2).
type AssemblyInfo struct {
	Name, Culture string
	Version       [4]uint16
	PublicKey     []byte
}

// AssemblyRef is the frozen typed view of an AssemblyRef row (II.22.5).
type AssemblyRef struct {
	Name, Culture    string
	Version          [4]uint16
	PublicKeyOrToken []byte
}

// FieldDef is the frozen typed view of a Field row (II.22.15).
type FieldDef struct {
	Name  string
	Flags uint16
	Sig   []byte
}

// MethodDef is the frozen typed view of a MethodDef row (II.22.26).
type MethodDef struct {
	Name      string
	RVA       uint32
	ImplFlags uint16
	Flags     uint16
	SigBlob   []byte
	Token     clrtok.Token
}

// TypeDef is the frozen typed view of a TypeDef row (II.22.37); owner ranges
// (Methods/Fields) are populated in M0-6.
type TypeDef struct {
	Namespace, Name string
	Flags           uint32
	Token           clrtok.Token
	Methods         []MethodDef
	Fields          []FieldDef
}

// ImplMap is the frozen typed view of an ImplMap row (II.22.22).
type ImplMap struct {
	MemberForwarded clrtok.Token
	ImportName      string
	ImportScope     string
	Flags           uint16
}

// ownerRange returns [start, end) of the child rows owned by row r (0-based) of
// owner table id, where childCol is the simple-index column pointing into the
// child table, and childTable is that table's id. The last owner row runs to
// the end of the child table (II.22).
func (t *Tables) ownerRange(id byte, r int, childCol int, childTable byte) (uint32, uint32) {
	start := t.readCol(id, r, childCol) // 1-based rid
	var end uint32
	if r+1 < int(t.rowCount[id]) {
		end = t.readCol(id, r+1, childCol)
	} else {
		end = t.rowCount[childTable] + 1
	}
	return start, end
}

// Types decodes every TypeDef with owner-resolved field/method ranges.
func (t *Tables) Types() []TypeDef {
	n := int(t.rowCount[0x02])
	out := make([]TypeDef, 0, n)
	for r := 0; r < n; r++ {
		td := TypeDef{
			Flags:     t.readCol(0x02, r, 0),
			Name:      t.heaps.Strings(t.readCol(0x02, r, 1)),
			Namespace: t.heaps.Strings(t.readCol(0x02, r, 2)),
			Token:     mkToken(0x02, uint32(r+1)),
		}
		// Field range: column index 4 -> Field(0x04).
		fs, fe := t.ownerRange(0x02, r, 4, 0x04)
		for fr := fs; fr < fe; fr++ {
			td.Fields = append(td.Fields, t.fieldAt(int(fr-1)))
		}
		// Method range: column index 5 -> MethodDef(0x06).
		ms, me := t.ownerRange(0x02, r, 5, 0x06)
		for mr := ms; mr < me; mr++ {
			td.Methods = append(td.Methods, t.methodAt(int(mr-1)))
		}
		out = append(out, td)
	}
	return out
}

func (t *Tables) fieldAt(r int) FieldDef {
	return FieldDef{
		Flags: uint16(t.readCol(0x04, r, 0)),
		Name:  t.heaps.Strings(t.readCol(0x04, r, 1)),
		Sig:   t.heaps.Blob(t.readCol(0x04, r, 2)),
	}
}

func (t *Tables) methodAt(r int) MethodDef {
	return MethodDef{
		RVA:       t.readCol(0x06, r, 0),
		ImplFlags: uint16(t.readCol(0x06, r, 1)),
		Flags:     uint16(t.readCol(0x06, r, 2)),
		Name:      t.heaps.Strings(t.readCol(0x06, r, 3)),
		SigBlob:   t.heaps.Blob(t.readCol(0x06, r, 4)),
		Token:     mkToken(0x06, uint32(r+1)),
	}
}

// PInvokes decodes the ImplMap table into the P/Invoke surface.
func (t *Tables) PInvokes() []ImplMap {
	n := int(t.rowCount[0x1C])
	out := make([]ImplMap, 0, n)
	for r := 0; r < n; r++ {
		fwTbl, fwRid := decodeCoded(ciMemberForwarded, t.readCol(0x1C, r, 1))
		scopeRid := t.readCol(0x1C, r, 3) // ModuleRef rid
		out = append(out, ImplMap{
			Flags:           uint16(t.readCol(0x1C, r, 0)),
			MemberForwarded: mkToken(fwTbl, fwRid),
			ImportName:      t.heaps.Strings(t.readCol(0x1C, r, 2)),
			ImportScope:     t.moduleRefName(scopeRid),
		})
	}
	return out
}

func (t *Tables) moduleRefName(rid uint32) string {
	if rid == 0 || rid > t.rowCount[0x1A] {
		return ""
	}
	return t.heaps.Strings(t.readCol(0x1A, int(rid-1), 0))
}

// mkToken builds a clrtok.Token from a table id + 1-based rid.
func mkToken(table byte, rid uint32) clrtok.Token {
	return clrtok.Token(uint32(table)<<24 | (rid & 0x00FFFFFF))
}

// joinTypeName joins namespace + name with a dot, omitting the dot when the
// namespace is empty (the ECMA display-name convention).
func joinTypeName(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "." + name
}

// MethodName resolves a MethodDef(0x06) or MemberRef(0x0A) token to its name and
// signature blob. ok=false for any other table or an out-of-range RID.
func (t *Tables) MethodName(tok clrtok.Token) (name string, sigBlob []byte, ok bool) {
	rid := tok.RowID()
	switch tok.TableID() {
	case clrtok.TblMethodDef:
		if rid == 0 || rid > t.rowCount[0x06] {
			return "", nil, false
		}
		r := int(rid - 1)
		return t.heaps.Strings(t.readCol(0x06, r, 3)), t.heaps.Blob(t.readCol(0x06, r, 4)), true
	case clrtok.TblMemberRef:
		if rid == 0 || rid > t.rowCount[0x0A] {
			return "", nil, false
		}
		r := int(rid - 1)
		return t.heaps.Strings(t.readCol(0x0A, r, 1)), t.heaps.Blob(t.readCol(0x0A, r, 2)), true
	default:
		return "", nil, false
	}
}

// FieldName resolves a Field(0x04) or MemberRef(0x0A) token to its name and
// signature blob. ok=false for any other table or an out-of-range RID.
func (t *Tables) FieldName(tok clrtok.Token) (name string, sigBlob []byte, ok bool) {
	rid := tok.RowID()
	switch tok.TableID() {
	case clrtok.TblField:
		if rid == 0 || rid > t.rowCount[0x04] {
			return "", nil, false
		}
		r := int(rid - 1)
		return t.heaps.Strings(t.readCol(0x04, r, 1)), t.heaps.Blob(t.readCol(0x04, r, 2)), true
	case clrtok.TblMemberRef:
		if rid == 0 || rid > t.rowCount[0x0A] {
			return "", nil, false
		}
		r := int(rid - 1)
		return t.heaps.Strings(t.readCol(0x0A, r, 1)), t.heaps.Blob(t.readCol(0x0A, r, 2)), true
	default:
		return "", nil, false
	}
}

// TypeName resolves a TypeDef(0x02) or TypeRef(0x01) token to its display name
// (Namespace.Name). ok=false for any other table or an out-of-range RID.
func (t *Tables) TypeName(tok clrtok.Token) (string, bool) {
	rid := tok.RowID()
	switch tok.TableID() {
	case clrtok.TblTypeDef:
		if rid == 0 || rid > t.rowCount[0x02] {
			return "", false
		}
		r := int(rid - 1)
		return joinTypeName(t.heaps.Strings(t.readCol(0x02, r, 2)), t.heaps.Strings(t.readCol(0x02, r, 1))), true
	case clrtok.TblTypeRef:
		if rid == 0 || rid > t.rowCount[0x01] {
			return "", false
		}
		r := int(rid - 1)
		// TypeRef cols: ResolutionScope(0), Name(1), Namespace(2).
		return joinTypeName(t.heaps.Strings(t.readCol(0x01, r, 2)), t.heaps.Strings(t.readCol(0x01, r, 1))), true
	default:
		return "", false
	}
}

// FileRow is a recorded File(0x26) row (II.22.19) — multi-module marker.
type FileRow struct {
	Flags uint32
	Name  string
}

// ExportedTypeRow is a recorded ExportedType(0x27) row (II.22.14) — type
// forwarder / external-module type. Implementation points at File/AssemblyRef/
// ExportedType but M0 does not resolve it.
type ExportedTypeRow struct {
	Flags          uint32
	Namespace      string
	Name           string
	Implementation clrtok.Token
}

// Files returns recorded File rows (no resolution).
func (t *Tables) Files() []FileRow {
	n := int(t.rowCount[0x26])
	out := make([]FileRow, 0, n)
	for r := 0; r < n; r++ {
		out = append(out, FileRow{
			Flags: t.readCol(0x26, r, 0),
			Name:  t.heaps.Strings(t.readCol(0x26, r, 1)),
		})
	}
	return out
}

// ExportedTypes returns recorded ExportedType rows (no resolution).
func (t *Tables) ExportedTypes() []ExportedTypeRow {
	n := int(t.rowCount[0x27])
	out := make([]ExportedTypeRow, 0, n)
	for r := 0; r < n; r++ {
		implTbl, implRid := decodeCoded(ciImplementation, t.readCol(0x27, r, 4))
		out = append(out, ExportedTypeRow{
			Flags:          t.readCol(0x27, r, 0),
			Name:           t.heaps.Strings(t.readCol(0x27, r, 2)),
			Namespace:      t.heaps.Strings(t.readCol(0x27, r, 3)),
			Implementation: mkToken(implTbl, implRid),
		})
	}
	return out
}
