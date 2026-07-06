package decompiler

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/attr"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/pipeline"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/writer"
)

// Decompiler can decompile .class files to .java source.
type Decompiler interface {
	Decompile(classPath string, outputDir string) error
	DecompileBytes(classData []byte) (string, error)
}

// NativeDecompiler is the built-in Go decompiler (CFR port).
type NativeDecompiler struct{}

// Decompile reads a .class file and writes a .java file to outputDir.
func (d *NativeDecompiler) Decompile(classPath string, outputDir string) error {
	data, err := os.ReadFile(classPath)
	if err != nil {
		return fmt.Errorf("read class file: %w", err)
	}

	source, err := d.DecompileBytes(data)
	if err != nil {
		return fmt.Errorf("decompile %s: %w", filepath.Base(classPath), err)
	}

	baseName := strings.TrimSuffix(filepath.Base(classPath), ".class") + ".java"
	outPath := filepath.Join(outputDir, baseName)

	if err := os.WriteFile(outPath, []byte(source), 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

// DecompileBytes decompiles raw .class bytes and returns Java source.
func (d *NativeDecompiler) DecompileBytes(classData []byte) (string, error) {
	cf, err := classfile.Parse(classData)
	if err != nil {
		return "", err
	}

	return decompileClass(cf)
}

// decompileClass runs the full decompilation pipeline on a parsed class file.
func decompileClass(cf *classfile.ClassFile) (string, error) {
	var b strings.Builder

	cp := newCPResolver(cf.ConstantPool)

	// Header comment
	_, _ = fmt.Fprintf(&b, "/*\n * Decompiled with unravel from %s (%s).\n", cf.ClassName(), cf.JavaVersion())
	if sf := cf.SourceFile(); sf != "" {
		_, _ = fmt.Fprintf(&b, " * Source: %s\n", sf)
	}

	b.WriteString(" */\n")

	// Package declaration
	className := cf.ClassNameDotted()

	thisPkg := ""
	if lastDot := strings.LastIndex(className, "."); lastDot >= 0 {
		thisPkg = className[:lastDot]
		_, _ = fmt.Fprintf(&b, "package %s;\n", thisPkg)
	}

	// Imports
	imports := collectImports(cf, thisPkg)
	if len(imports) > 0 {
		b.WriteString("\n")

		tracker := writer.NewImportTracker()
		for _, imp := range imports {
			tracker.Add(imp)
		}

		b.WriteString(tracker.WriteImports())
	}

	b.WriteString("\n")

	// Class-level annotations
	if ann := renderAnnotations(cf.Attributes, cf.ConstantPool, ""); ann != "" {
		b.WriteString(ann)
	}

	// Class declaration
	access := cf.AccessFlags.ClassAccessString()
	if access != "" {
		b.WriteString(access + " ")
	}

	if cf.IsInterface() {
		b.WriteString("interface ")
	} else if cf.IsEnum() {
		b.WriteString("enum ")
	} else if cf.IsAnnotation() {
		b.WriteString("@interface ")
	} else {
		b.WriteString("class ")
	}

	simpleName := className
	if lastDot := strings.LastIndex(className, "."); lastDot >= 0 {
		simpleName = className[lastDot+1:]
	}

	b.WriteString(simpleName)

	// Class-level generic signature
	var classSig *types.ClassSignature

	if sig := cf.Attributes.Get("Signature"); sig != nil {
		if s, ok := sig.(*attr.Signature); ok {
			cs, err := types.ParseClassSignature(s.SignatureValue)
			if err == nil {
				classSig = cs
			}
		}
	}

	if classSig != nil && len(classSig.FormalParams) > 0 {
		b.WriteString("<")

		for i, fp := range classSig.FormalParams {
			if i > 0 {
				b.WriteString(", ")
			}

			b.WriteString(fp.String())
		}

		b.WriteString(">")
	}

	// Superclass
	if classSig != nil {
		// Use generic superclass from signature
		superName := classSig.SuperClass.Name()
		if superName != "Object" && superName != "java.lang.Object" {
			b.WriteString("\nextends ")
			b.WriteString(types.SimplifyJavaLang(superName))
		}
	} else if sc := cf.SuperClassName(); sc != "" && sc != "java/lang/Object" {
		b.WriteString("\nextends ")
		b.WriteString(types.SimplifyJavaLang(strings.ReplaceAll(sc, "/", ".")))
	}

	// Interfaces
	if classSig != nil && len(classSig.Interfaces) > 0 {
		if cf.IsInterface() {
			b.WriteString("\nextends ")
		} else {
			b.WriteString("\nimplements ")
		}

		for i, iface := range classSig.Interfaces {
			if i > 0 {
				b.WriteString(", ")
			}

			b.WriteString(types.SimplifyJavaLang(iface.Name()))
		}
	} else if ifaces := cf.InterfaceNames(); len(ifaces) > 0 {
		if cf.IsInterface() {
			b.WriteString("\nextends ")
		} else {
			b.WriteString("\nimplements ")
		}

		for i, iface := range ifaces {
			if i > 0 {
				b.WriteString(", ")
			}

			b.WriteString(types.SimplifyJavaLang(strings.ReplaceAll(iface, "/", ".")))
		}
	}

	b.WriteString(" {\n")

	// Fields
	for _, f := range cf.Fields {
		// Field annotations
		if ann := renderAnnotations(f.Attributes, cf.ConstantPool, "    "); ann != "" {
			b.WriteString(ann)
		}

		b.WriteString("    ")

		if fa := f.AccessFlags.FieldAccessString(); fa != "" {
			b.WriteString(fa + " ")
		}

		fieldType := resolveFieldType(f)
		_, _ = fmt.Fprintf(&b, "%s %s;\n", fieldType, f.Name)
	}

	if len(cf.Fields) > 0 && len(cf.Methods) > 0 {
		b.WriteString("\n")
	}

	// Methods
	firstMethod := true

	for _, m := range cf.Methods {
		if isDefaultConstructor(cf, m) {
			continue
		}

		methodSrc, err := decompileMethod(cf, m, cp)
		if err != nil {
			if !firstMethod {
				b.WriteString("\n")
			}
			// On failure, emit the method as a stub with the error
			_, _ = fmt.Fprintf(&b, "    /* decompilation error: %s: %v */\n", m.Name, err)
			firstMethod = false

			continue
		}

		if !firstMethod {
			b.WriteString("\n")
		}

		b.WriteString(methodSrc)

		firstMethod = false
	}

	b.WriteString("}\n")

	return b.String(), nil
}

// decompileMethod decompiles a single method to Java source.
func decompileMethod(cf *classfile.ClassFile, m *classfile.Method, cp pipeline.CPResolver) (string, error) {
	var b strings.Builder

	className := cf.ClassNameDotted()

	simpleName := className
	if lastDot := strings.LastIndex(className, "."); lastDot >= 0 {
		simpleName = className[lastDot+1:]
	}

	// Static initializer
	if m.IsStaticInitializer() {
		code := m.Code()
		if code == nil {
			return "    static { }\n", nil
		}

		stmts, err := runPipeline(cf, m, code, cp)
		if err != nil {
			return fmt.Sprintf("    static { /* error: %v */ }\n", err), nil
		}

		w := writer.New()
		w.WriteStatements(stmts)

		return fmt.Sprintf("    static {\n%s    }\n", indentBlock(w.String(), 2)), nil
	}

	// Method annotations
	if ann := renderAnnotations(m.Attributes, cf.ConstantPool, "    "); ann != "" {
		b.WriteString(ann)
	}

	// Access modifiers
	b.WriteString("    ")

	if ma := m.AccessFlags.MethodAccessString(); ma != "" {
		b.WriteString(ma + " ")
	}

	// Build LVT names map for parameter naming
	var lvtNames map[int]string
	if code := m.Code(); code != nil {
		lvtNames = extractLocalVarNames(code, cf.ConstantPool)
	}

	// Check for generic method signature
	var methodSig *types.MethodSignature

	genSig := m.Signature()
	if genSig != m.Descriptor {
		ms, err := types.ParseMethodSignature(genSig)
		if err == nil {
			methodSig = ms
		}
	}

	// Method-level formal type params (e.g. <T>)
	if methodSig != nil && len(methodSig.FormalParams) > 0 {
		b.WriteString("<")

		for i, fp := range methodSig.FormalParams {
			if i > 0 {
				b.WriteString(", ")
			}

			b.WriteString(fp.String())
		}

		b.WriteString("> ")
	}

	// Constructor or regular method
	if m.IsConstructor() {
		b.WriteString(simpleName)

		if methodSig != nil {
			b.WriteString(formatGenericParams(methodSig.ParamTypes, m.IsStatic(), lvtNames))
		} else {
			b.WriteString(descriptorParamsJavaWithNames(m.Descriptor, m.IsStatic(), lvtNames))
		}
	} else {
		if methodSig != nil {
			b.WriteString(methodSig.ReturnType.Name())
			b.WriteByte(' ')
			b.WriteString(m.Name)
			b.WriteString(formatGenericParams(methodSig.ParamTypes, m.IsStatic(), lvtNames))
		} else {
			params, retType, err := types.ParseMethodDescriptor(m.Descriptor)
			if err != nil {
				return "", fmt.Errorf("parse descriptor %q: %w", m.Descriptor, err)
			}

			b.WriteString(retType.Name())
			b.WriteByte(' ')
			b.WriteString(m.Name)
			b.WriteString(formatParams(params, m.IsStatic(), lvtNames))
		}
	}

	// Throws clause
	if exTypes := m.ExceptionTypes(); len(exTypes) > 0 {
		b.WriteString(" throws ")

		for i, idx := range exTypes {
			if i > 0 {
				b.WriteString(", ")
			}

			name := cf.ConstantPool.ClassName(idx)
			b.WriteString(types.SimplifyJavaLang(strings.ReplaceAll(name, "/", ".")))
		}
	}

	// Abstract/native methods have no body
	if m.IsAbstract() || m.IsNative() {
		b.WriteString(";\n")
		return b.String(), nil
	}

	code := m.Code()
	if code == nil {
		b.WriteString(" { }\n")
		return b.String(), nil
	}

	stmts, err := runPipeline(cf, m, code, cp)
	if err != nil {
		_, _ = fmt.Fprintf(&b, " { /* error: %v */ }\n", err)
		return b.String(), nil
	}

	// Strip trailing void return (implicit in Java)
	stmts = stripTrailingVoidReturn(stmts)

	// In constructors, strip the implicit super() call (no-arg)
	if m.IsConstructor() {
		stmts = stripNoArgSuperCall(stmts)
	}

	// JVM local slots occupied by `this` + the parameters — already declared in
	// the signature, so they must not be re-declared by the body hoister.
	paramSlots := map[int]bool{}
	slot := 0
	if !m.IsStatic() {
		paramSlots[0] = true
		slot = 1
	}
	if params, _, perr := types.ParseMethodDescriptor(m.Descriptor); perr == nil {
		for _, p := range params {
			paramSlots[slot] = true
			slot += p.StackCategory()
		}
	}

	w := writer.New()
	w.WriteBody(stmts, paramSlots)
	body := w.String()

	if body == "" {
		b.WriteString(" { }\n")
	} else {
		b.WriteString(" {\n")
		b.WriteString(indentBlock(body, 2))
		b.WriteString("    }\n")
	}

	return b.String(), nil
}

// runPipeline executes the full decompilation pipeline for a method's bytecode.
func runPipeline(cf *classfile.ClassFile, m *classfile.Method, code *attr.Code, cp pipeline.CPResolver) ([]stmt.Statement, error) {
	className := cf.ClassNameDotted()

	params, retType, err := types.ParseMethodDescriptor(m.Descriptor)
	if err != nil {
		return nil, fmt.Errorf("parse descriptor: %w", err)
	}

	methodInfo := &pipeline.MethodInfo{
		ClassName:     className,
		MethodName:    m.Name,
		Descriptor:    m.Descriptor,
		IsStatic:      m.IsStatic(),
		ReturnType:    retType,
		ParamTypes:    params,
		MaxLocals:     int(code.MaxLocals),
		MaxStack:      int(code.MaxStack),
		LocalVarNames: extractLocalVarNames(code, cf.ConstantPool),
	}

	// Convert exception entries
	exceptions := convertExceptions(cf, code.ExceptionTable)

	result, err := pipeline.Decompile(code.Bytecode, methodInfo, cp, exceptions)
	if err != nil {
		return nil, err
	}

	return result.Statements, nil
}

// convertExceptions converts classfile exception entries to pipeline format.
func convertExceptions(cf *classfile.ClassFile, entries []attr.ExceptionEntry) []pipeline.ExceptionEntry {
	result := make([]pipeline.ExceptionEntry, len(entries))
	for i, e := range entries {
		catchType := ""
		if e.CatchType != 0 {
			catchType = strings.ReplaceAll(cf.ConstantPool.ClassName(e.CatchType), "/", ".")
		}

		result[i] = pipeline.ExceptionEntry{
			StartPC:   int(e.StartPC),
			EndPC:     int(e.EndPC),
			HandlerPC: int(e.HandlerPC),
			CatchType: catchType,
		}
	}

	return result
}

// formatParams builds a parameter list string "(Type name, ...)" using LVT names when available.
func formatParams(params []types.JavaType, isStatic bool, lvtNames map[int]string) string {
	var b strings.Builder
	b.WriteByte('(')

	slot := 0
	if !isStatic {
		slot = 1 // skip 'this'
	}

	for i, p := range params {
		if i > 0 {
			b.WriteString(", ")
		}

		// Fall back to the slot-based name the method body uses for this local
		// (ast.NewLocalVariable → "var{slot}"). Keying the declaration off the
		// parameter index ("arg{i}") instead diverges from the body whenever no
		// LocalVariableTable is present — e.g. declaring `add(int arg0, int arg1)`
		// but emitting `return var1 + var2`, which does not compile. Slot-based
		// naming keeps declaration and references identical.
		name := fmt.Sprintf("var%d", slot)

		if lvtNames != nil {
			if n, ok := lvtNames[slot]; ok {
				name = n
			}
		}

		_, _ = fmt.Fprintf(&b, "%s %s", p.Name(), name)
		slot += p.StackCategory()
	}

	b.WriteByte(')')

	return b.String()
}

// formatGenericParams builds a parameter list using generic types from a method signature.
func formatGenericParams(paramTypes []types.JavaType, isStatic bool, lvtNames map[int]string) string {
	var b strings.Builder
	b.WriteByte('(')

	slot := 0
	if !isStatic {
		slot = 1
	}

	for i, p := range paramTypes {
		if i > 0 {
			b.WriteString(", ")
		}

		// Fall back to the slot-based name the method body uses for this local
		// (ast.NewLocalVariable → "var{slot}"). Keying the declaration off the
		// parameter index ("arg{i}") instead diverges from the body whenever no
		// LocalVariableTable is present — e.g. declaring `add(int arg0, int arg1)`
		// but emitting `return var1 + var2`, which does not compile. Slot-based
		// naming keeps declaration and references identical.
		name := fmt.Sprintf("var%d", slot)

		if lvtNames != nil {
			if n, ok := lvtNames[slot]; ok {
				name = n
			}
		}

		_, _ = fmt.Fprintf(&b, "%s %s", p.Name(), name)
		// For slot counting, use the underlying descriptor category
		slot += p.StackCategory()
	}

	b.WriteByte(')')

	return b.String()
}

// descriptorParamsJavaWithNames converts a method descriptor to "(Type1 name1, Type2 name2)" form.
func descriptorParamsJavaWithNames(desc string, isStatic bool, lvtNames map[int]string) string {
	params, _, err := types.ParseMethodDescriptor(desc)
	if err != nil {
		return "()"
	}

	return formatParams(params, isStatic, lvtNames)
}

// extractLocalVarNames extracts variable names from the LocalVariableTable attribute.
// Returns a map from slot index to variable name, or nil if no LVT is present.
func extractLocalVarNames(code *attr.Code, cp *constantpool.Pool) map[int]string {
	if code.Attributes == nil {
		return nil
	}

	lvtAttr := code.Attributes.Get("LocalVariableTable")
	if lvtAttr == nil {
		return nil
	}

	lvt, ok := lvtAttr.(*attr.LocalVariableTable)
	if !ok {
		return nil
	}

	names := make(map[int]string, len(lvt.Entries))
	for _, e := range lvt.Entries {
		name := cp.UTF8(e.NameIndex)
		if name != "" && name != "this" {
			names[int(e.Index)] = name
		}
	}

	if len(names) == 0 {
		return nil
	}

	return names
}

// isDefaultConstructor returns true if the method is a no-arg constructor whose
// bytecode is just `aload_0; invokespecial <super>.<init>:()V; return`.
// CFR omits these from output since they're generated by javac automatically.
func isDefaultConstructor(_ *classfile.ClassFile, m *classfile.Method) bool {
	if !m.IsConstructor() || m.Descriptor != "()V" {
		return false
	}

	code := m.Code()
	if code == nil {
		return false
	}
	// Default constructor bytecode: aload_0 (2a) + invokespecial (b7 xx xx) + return (b1) = 5 bytes
	bc := code.Bytecode
	if len(bc) != 5 {
		return false
	}

	return bc[0] == 0x2a && bc[1] == 0xb7 && bc[4] == 0xb1
}

// stripTrailingVoidReturn removes a trailing "return;" from a void method body,
// since it's implicit in Java. This matches CFR's behavior.
func stripTrailingVoidReturn(stmts []stmt.Statement) []stmt.Statement {
	if len(stmts) == 0 {
		return stmts
	}

	last := stmts[len(stmts)-1]
	if last.Kind() == stmt.KindReturnVoid {
		return stmts[:len(stmts)-1]
	}

	return stmts
}

// stripNoArgSuperCall removes the leading super() call from constructors
// since CFR omits it when it's the implicit no-arg super constructor call.
func stripNoArgSuperCall(stmts []stmt.Statement) []stmt.Statement {
	if len(stmts) == 0 {
		return stmts
	}

	first := stmts[0]
	if first.Kind() != stmt.KindExpression {
		return stmts
	}

	exprStmt, ok := first.(*stmt.ExpressionStatement)
	if !ok {
		return stmts
	}
	// Check if expression is super() with no arguments
	s := exprStmt.Expr.String()
	if s == "super()" {
		return stmts[1:]
	}

	return stmts
}

// indentBlock adds extra indentation to each line of a block.
func indentBlock(s string, levels int) string {
	if s == "" {
		return ""
	}

	indent := strings.Repeat("    ", levels)
	lines := strings.Split(s, "\n")

	var b strings.Builder

	for _, line := range lines {
		if line == "" {
			continue
		}

		b.WriteString(indent)
		b.WriteString(line)
		b.WriteByte('\n')
	}

	return b.String()
}

// resolveFieldType returns the generic type if a Signature attribute is present,
// otherwise falls back to the descriptor.
func resolveFieldType(f *classfile.Field) string {
	genSig := f.Signature()
	if genSig != f.Descriptor {
		ft, err := types.ParseFieldSignature(genSig)
		if err == nil {
			return ft.Name()
		}
	}

	return types.DescriptorToJava(f.Descriptor)
}

// collectImports scans the constant pool for all referenced class types and
// returns a sorted, deduplicated list of FQN imports, excluding java.lang.*,
// same-package classes, primitives, and array types.
func collectImports(cf *classfile.ClassFile, thisPkg string) []string {
	seen := make(map[string]bool)
	add := func(internalName string) {
		if internalName == "" {
			return
		}
		// Skip arrays — peel off leading [
		if strings.HasPrefix(internalName, "[") {
			return
		}

		dotted := strings.ReplaceAll(internalName, "/", ".")
		// Skip primitives and no-package classes
		if !strings.Contains(dotted, ".") {
			return
		}
		// Skip java.lang.* (auto-imported)
		pkg := dotted[:strings.LastIndex(dotted, ".")]
		if pkg == "java.lang" {
			return
		}
		// Skip same-package
		if pkg == thisPkg {
			return
		}

		seen[dotted] = true
	}

	// Superclass
	if cf.SuperClass != 0 {
		add(cf.ConstantPool.ClassName(cf.SuperClass))
	}

	// Interfaces
	for _, idx := range cf.Interfaces {
		add(cf.ConstantPool.ClassName(idx))
	}

	// Scan all constant pool entries for Class refs
	for i := uint16(1); i < cf.ConstantPool.Count(); i++ {
		e := cf.ConstantPool.Get(i)
		if e == nil {
			continue
		}

		if e.Tag == constantpool.TagClass {
			name := cf.ConstantPool.ClassName(i)
			add(name)
		}
	}

	// Also scan field and method descriptors for embedded type refs
	for _, f := range cf.Fields {
		extractDescriptorRefs(f.Descriptor, add)
		// Scan field signature for generic type refs
		if genSig := f.Signature(); genSig != f.Descriptor {
			extractSignatureRefs(genSig, add)
		}
	}

	for _, m := range cf.Methods {
		extractDescriptorRefs(m.Descriptor, add)
		// Scan method signature for generic type refs
		if genSig := m.Signature(); genSig != m.Descriptor {
			extractSignatureRefs(genSig, add)
		}
		// Exception types
		for _, idx := range m.ExceptionTypes() {
			add(cf.ConstantPool.ClassName(idx))
		}
	}

	// Also add annotation type refs
	collectAnnotationImports(cf.Attributes, cf.ConstantPool, add)

	for _, f := range cf.Fields {
		collectAnnotationImports(f.Attributes, cf.ConstantPool, add)
	}

	for _, m := range cf.Methods {
		collectAnnotationImports(m.Attributes, cf.ConstantPool, add)
	}

	// Build sorted list
	tracker := writer.NewImportTracker()
	for fqn := range seen {
		tracker.Add(fqn)
	}

	return tracker.Imports()
}

// extractDescriptorRefs finds all L....; class references in a descriptor string.
func extractDescriptorRefs(desc string, add func(string)) {
	for i := 0; i < len(desc); i++ {
		if desc[i] == 'L' {
			end := strings.IndexByte(desc[i:], ';')
			if end < 0 {
				break
			}

			add(desc[i+1 : i+end])
			i += end
		}
	}
}

// extractSignatureRefs finds all L....; class references in a generic signature.
func extractSignatureRefs(sig string, add func(string)) {
	for i := 0; i < len(sig); i++ {
		if sig[i] == 'L' {
			// Find the matching ';' but skip over '<' '>' nested generics
			depth := 0
			end := -1

			for j := i + 1; j < len(sig); j++ {
				switch sig[j] {
				case '<':
					depth++
				case '>':
					depth--
				case ';':
					if depth == 0 {
						end = j
					}
				}

				if end >= 0 {
					break
				}
			}

			if end < 0 {
				break
			}
			// Extract base class name (before any '<')
			raw := sig[i+1 : end]
			if lt := strings.IndexByte(raw, '<'); lt >= 0 {
				raw = raw[:lt]
			}
			// Convert inner class separators '.' to '$' for FQN
			add(raw)

			i = end
		}
	}
}

// collectAnnotationImports adds annotation type names to the import set.
func collectAnnotationImports(attrs *attr.Map, cp *constantpool.Pool, add func(string)) {
	if attrs == nil {
		return
	}

	for _, name := range []string{"RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations"} {
		a := attrs.Get(name)
		if a == nil {
			continue
		}

		annots, ok := a.(*attr.Annotations)
		if !ok {
			continue
		}

		for _, ae := range annots.Annots {
			desc := cp.UTF8(ae.TypeIndex)
			// Annotation type descriptor is like "Ljava/lang/Override;"
			if len(desc) > 2 && desc[0] == 'L' && desc[len(desc)-1] == ';' {
				add(desc[1 : len(desc)-1])
			}
		}
	}
}

// renderAnnotations returns annotation lines for the given attribute map.
func renderAnnotations(attrs *attr.Map, cp *constantpool.Pool, indent string) string {
	if attrs == nil {
		return ""
	}

	a := attrs.Get("RuntimeVisibleAnnotations")
	if a == nil {
		return ""
	}

	annots, ok := a.(*attr.Annotations)
	if !ok {
		return ""
	}

	var b strings.Builder

	for _, ae := range annots.Annots {
		desc := cp.UTF8(ae.TypeIndex)
		annotName := annotationDescToName(desc)

		b.WriteString(indent)
		b.WriteString("@")
		b.WriteString(annotName)

		if len(ae.Pairs) > 0 {
			b.WriteString("(")

			for i, p := range ae.Pairs {
				if i > 0 {
					b.WriteString(", ")
				}

				pairName := cp.UTF8(p.NameIndex)
				// Single "value" parameter can be written without name
				if len(ae.Pairs) == 1 && pairName == "value" {
					b.WriteString(renderElementValue(p.Value, cp))
				} else {
					_, _ = fmt.Fprintf(&b, "%s=%s", pairName, renderElementValue(p.Value, cp))
				}
			}

			b.WriteString(")")
		}

		b.WriteString("\n")
	}

	return b.String()
}

// annotationDescToName converts "Ljava/lang/Override;" to "Override".
func annotationDescToName(desc string) string {
	if len(desc) < 3 {
		return desc
	}

	if desc[0] == 'L' && desc[len(desc)-1] == ';' {
		name := desc[1 : len(desc)-1]
		name = strings.ReplaceAll(name, "/", ".")

		return types.SimplifyJavaLang(name)
	}

	return desc
}

// renderElementValue converts an annotation element value to its string form.
func renderElementValue(ev attr.ElementValue, cp *constantpool.Pool) string {
	switch ev.Tag {
	case 'B':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			return fmt.Sprintf("(byte)%d", e.IntValue)
		}
	case 'C':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			return fmt.Sprintf("'%c'", rune(e.IntValue))
		}
	case 'D':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			return formatDouble(e.DoubleValue)
		}
	case 'F':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			return formatFloat(e.FloatValue)
		}
	case 'I':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			return fmt.Sprintf("%d", e.IntValue)
		}
	case 'J':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			return fmt.Sprintf("%dL", e.LongValue)
		}
	case 'S':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			return fmt.Sprintf("(short)%d", e.IntValue)
		}
	case 'Z':
		e := cp.Get(ev.ConstValueIdx)
		if e != nil {
			if e.IntValue != 0 {
				return "true"
			}

			return "false"
		}
	case 's':
		return fmt.Sprintf("%q", cp.UTF8(ev.ConstValueIdx))
	case 'e':
		enumType := annotationDescToName(cp.UTF8(ev.EnumTypeIdx))
		enumConst := cp.UTF8(ev.EnumConstIdx)

		return enumType + "." + enumConst
	case 'c':
		classDesc := cp.UTF8(ev.ClassInfoIdx)
		return types.DescriptorToJava(classDesc) + ".class"
	case '@':
		if ev.AnnotationVal != nil {
			annotName := annotationDescToName(cp.UTF8(ev.AnnotationVal.TypeIndex))
			return "@" + annotName
		}
	case '[':
		var items []string
		for _, v := range ev.ArrayValues {
			items = append(items, renderElementValue(v, cp))
		}

		return "{" + strings.Join(items, ", ") + "}"
	}

	return "/* unknown */"
}

// formatFloat formats a float32 for Java source output.
func formatFloat(f float32) string {
	if math.IsInf(float64(f), 1) {
		return "Float.POSITIVE_INFINITY"
	}

	if math.IsInf(float64(f), -1) {
		return "Float.NEGATIVE_INFINITY"
	}

	if math.IsNaN(float64(f)) {
		return "Float.NaN"
	}

	return fmt.Sprintf("%gf", f)
}

// formatDouble formats a float64 for Java source output.
func formatDouble(d float64) string {
	if math.IsInf(d, 1) {
		return "Double.POSITIVE_INFINITY"
	}

	if math.IsInf(d, -1) {
		return "Double.NEGATIVE_INFINITY"
	}

	if math.IsNaN(d) {
		return "Double.NaN"
	}

	return fmt.Sprintf("%g", d)
}
