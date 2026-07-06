/*
Copyright (c) 2026 Security Research
*/
package smali

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// WriteSmali writes all disassembled classes as .smali files to the output directory.
// Returns the number of files written.
func WriteSmali(result *DisassembleResult, outputDir string) (int, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return 0, fmt.Errorf("creating output directory: %w", err)
	}

	// Group methods by class
	classMethods := make(map[string][]MethodCode)
	for _, mc := range result.Methods {
		classMethods[mc.ClassName] = append(classMethods[mc.ClassName], mc)
	}

	written := 0
	for _, cls := range result.DexFile.Classes {
		smaliPath := classToPath(cls.ClassName, outputDir)
		dir := filepath.Dir(smaliPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}

		f, err := os.Create(smaliPath)
		if err != nil {
			continue
		}

		methods := classMethods[cls.ClassName]
		writeClass(f, cls, methods)
		_ = f.Close()
		written++
	}

	return written, nil
}

// FormatClass formats a single class and its methods as Smali text.
func FormatClass(cls dex.ClassDef, methods []MethodCode) string {
	var sb strings.Builder
	writeClass(&sb, cls, methods)
	return sb.String()
}

func writeClass(w io.Writer, cls dex.ClassDef, methods []MethodCode) {
	// Class header
	accessStr := AccessFlagsToString(cls.AccessFlags, true)
	_, _ = fmt.Fprintf(w, ".class %s %s\n", accessStr, cls.ClassName)
	if cls.Superclass != "" {
		_, _ = fmt.Fprintf(w, ".super %s\n", cls.Superclass)
	}
	if cls.SourceFile != "" {
		_, _ = fmt.Fprintf(w, ".source %q\n", cls.SourceFile)
	}
	_, _ = fmt.Fprintln(w)

	// Methods
	for _, mc := range methods {
		writeMethod(w, mc)
		_, _ = fmt.Fprintln(w)
	}
}

func writeMethod(w io.Writer, mc MethodCode) {
	accessStr := AccessFlagsToString(mc.AccessFlags, false)
	descriptor := mc.Descriptor
	if descriptor == "" {
		descriptor = "()V" // fallback
	}
	_, _ = fmt.Fprintf(w, ".method %s %s%s\n", accessStr, mc.MethodName, descriptor)
	_, _ = fmt.Fprintf(w, "    .registers %d\n", mc.Registers)
	_, _ = fmt.Fprintln(w)

	for _, insn := range mc.Instructions {
		label := fmt.Sprintf("    :%04x", insn.Offset)
		_ = label // labels emitted on-demand for branch targets

		if insn.Operand != "" {
			_, _ = fmt.Fprintf(w, "    %s %s\n", insn.Info.Mnemonic, insn.Operand)
		} else {
			_, _ = fmt.Fprintf(w, "    %s\n", insn.Info.Mnemonic)
		}
	}

	_, _ = fmt.Fprintln(w, ".end method")
}

// classToPath converts a Dalvik class descriptor (e.g., "Lcom/example/MyClass;")
// to a filesystem path (e.g., "outputDir/com/example/MyClass.smali").
func classToPath(className, outputDir string) string {
	// Strip L prefix and ; suffix
	name := className
	if strings.HasPrefix(name, "L") {
		name = name[1:]
	}
	if strings.HasSuffix(name, ";") {
		name = name[:len(name)-1]
	}

	// Replace / with OS path separator
	name = strings.ReplaceAll(name, "/", string(filepath.Separator))

	return filepath.Join(outputDir, name+".smali")
}

// FormatInstruction formats a single instruction as a Smali line.
func FormatInstruction(insn Instruction) string {
	if insn.Operand != "" {
		return fmt.Sprintf("    %s %s", insn.Info.Mnemonic, insn.Operand)
	}
	return fmt.Sprintf("    %s", insn.Info.Mnemonic)
}
