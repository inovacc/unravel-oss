/*
Copyright (c) 2026 Security Research
*/
// Package clr is a pure-Go ECMA-335 reader: PE -> IMAGE_COR20_HEADER ->
// metadata region locate, plus the RVA->offset section map consumed by the
// M1 IL layer. No CGO, no external .NET tooling.
package clr
