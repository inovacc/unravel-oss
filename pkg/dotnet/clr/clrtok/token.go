/*
Copyright (c) 2026 Security Research
*/
// Package clrtok is the ECMA-335 metadata-token leaf: it owns the Token type,
// its TableID/RowID accessors, and the table-id constants. It imports nothing
// internal so that metadata, sig, and il can depend on it without importing
// package clr (which imports those packages and would otherwise cycle).
package clrtok

// Token is a 4-byte ECMA-335 metadata token (II.22): the high byte is the
// table id, the low 24 bits are a 1-based row id (RID). A zero token is the
// nil token.
type Token uint32

// TableID returns the high byte (the metadata table this token indexes).
func (t Token) TableID() byte { return byte(t >> 24) }

// RowID returns the low 24 bits: the 1-based row index (RID) within the table.
func (t Token) RowID() uint32 { return uint32(t) & 0x00FFFFFF }

// Table-id constants: the high byte of a Token (ECMA-335 II.22).
const (
	TblModule     byte = 0x00
	TblTypeRef    byte = 0x01
	TblTypeDef    byte = 0x02
	TblField      byte = 0x04
	TblMethodDef  byte = 0x06
	TblParam      byte = 0x08
	TblMemberRef  byte = 0x0A
	TblTypeSpec   byte = 0x1B
	TblMethodSpec byte = 0x2B
	TblUserString byte = 0x70
)
