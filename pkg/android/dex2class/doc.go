/*
Copyright (c) 2026 Security Research
*/

// Package dex2class translates Dalvik register-based bytecode into JVM
// stack-based .class files. This enables the full DEX → Java source pipeline:
//
//	DEX file → dex2class → .class files → Java decompiler → .java source
//
// The core challenge is the register-to-stack transformation: Dalvik uses
// registers while JVM uses an operand stack. Each Dalvik instruction maps
// to one or more JVM instructions:
//
//	move vA, vB         → aload B; astore A
//	invoke-virtual {vA} → aload A; invokevirtual Method
//	return vA           → aload A; areturn
//
// This package replaces the external dex2jar tool with a pure Go implementation.
package dex2class
