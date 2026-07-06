/*
Copyright (c) 2026 Security Research
*/

// Package smali implements a pure Go Dalvik bytecode disassembler
// that outputs Smali assembly text compatible with baksmali format.
//
// It reads DEX files (already parsed by pkg/android/dex/) and decodes
// code_item structures, producing .smali files per class.
package smali
