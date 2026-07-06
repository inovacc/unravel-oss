/*
Copyright (c) 2026 Security Research
*/
package dex2class

import (
	"bytes"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// TranslateResult holds the output of translating a DEX file to .class files.
type TranslateResult struct {
	ClassFiles []ClassOutput `json:"class_files"`
	Errors     []string      `json:"errors,omitempty"`
}

// ClassOutput holds a single translated .class file.
type ClassOutput struct {
	ClassName string `json:"class_name"` // internal form: com/example/MyClass
	Data      []byte `json:"-"`          // raw .class bytes
	Methods   int    `json:"methods"`
	Fields    int    `json:"fields"`
}

// Translator converts Dalvik bytecode to JVM bytecode.
type Translator struct {
	// Options
	Verbose bool
}

// ClassHandler is called for each translated class. The handler should
// process the class immediately — the ClassOutput may be reused after return.
type ClassHandler func(output *ClassOutput) error

// TranslateStreaming converts DEX classes one at a time, calling handler for each.
// This avoids accumulating all .class bytes in memory simultaneously.
func (t *Translator) TranslateStreaming(dexFile *dex.DexFile, rawDEX []byte, handler ClassHandler) (errors []string, err error) {
	if dexFile == nil {
		return nil, fmt.Errorf("dex2class: nil DexFile")
	}

	r := bytes.NewReader(rawDEX)

	for _, cls := range dexFile.Classes {
		classData, err := t.translateClass(dexFile, &cls, r)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", cls.ClassName, err))
			continue
		}

		if herr := handler(classData); herr != nil {
			errors = append(errors, fmt.Sprintf("%s: handler: %v", cls.ClassName, herr))
		}
	}

	return errors, nil
}

// Translate converts all classes in a parsed DEX file to .class bytes.
// WARNING: For large DEX files (10K+ classes), use TranslateStreaming instead
// to avoid excessive memory usage.
func (t *Translator) Translate(dexFile *dex.DexFile, rawDEX []byte) (*TranslateResult, error) {
	if dexFile == nil {
		return nil, fmt.Errorf("dex2class: nil DexFile")
	}

	result := &TranslateResult{}
	r := bytes.NewReader(rawDEX)

	for _, cls := range dexFile.Classes {
		classData, err := t.translateClass(dexFile, &cls, r)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", cls.ClassName, err))
			continue
		}

		result.ClassFiles = append(result.ClassFiles, *classData)
	}

	return result, nil
}

// TranslateNoRaw converts classes that have no bytecode (e.g., no class_data).
// This is the simpler entry point when you only have parsed metadata.
func (t *Translator) TranslateNoRaw(dexFile *dex.DexFile) (*TranslateResult, error) {
	if dexFile == nil {
		return nil, fmt.Errorf("dex2class: nil DexFile")
	}

	result := &TranslateResult{}

	for _, cls := range dexFile.Classes {
		classData, err := t.translateClassNoCode(dexFile, &cls)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", cls.ClassName, err))
			continue
		}

		result.ClassFiles = append(result.ClassFiles, *classData)
	}

	return result, nil
}

// translateClass converts a single DEX class definition to .class bytes.
func (t *Translator) translateClass(dexFile *dex.DexFile, cls *dex.ClassDef, r *bytes.Reader) (*ClassOutput, error) {
	cw := newClassWriter()
	conv := newConverter(cw, dexFile)

	internalName := validClassName(cls.ClassName)

	// Add this class and super class to constant pool
	thisClassIdx := cw.addClass(internalName)
	superName := "java/lang/Object"
	if cls.Superclass != "" {
		superName = dexTypeToInternal(cls.Superclass)
	}
	superClassIdx := cw.addClass(superName)

	var jvmFields []fieldInfo
	var jvmMethods []methodInfo

	// If class has bytecode data, read it
	if cls.ClassDataOff != 0 {
		cd, err := readClassDataItem(r, cls.ClassDataOff)
		if err != nil {
			return nil, formatClassFileError(internalName, "reading class_data: %v", err)
		}

		// Read static field initializers from static_values_off
		staticVals := readStaticValues(r, cls.StaticValuesOff, dexFile.Strings)

		// Translate static fields with initializer values
		for i, ef := range cd.staticFields {
			fi := t.translateField(cw, dexFile, ef)
			// Attach ConstantValue attribute if a static value exists
			if i < len(staticVals) {
				sv := staticVals[i]
				if sv.Type != evNull {
					attrName, valIdx := cw.addConstantValueAttr(sv, fi.descriptor)
					if attrName != 0 {
						fi.cvAttrName = attrName
						fi.cvValueIdx = valIdx
					}
				}
			}
			jvmFields = append(jvmFields, fi)
		}
		for _, ef := range cd.instanceFields {
			fi := t.translateField(cw, dexFile, ef)
			jvmFields = append(jvmFields, fi)
		}

		// Translate direct methods
		for _, em := range cd.directMethods {
			mi, err := t.translateMethod(cw, conv, dexFile, r, em)
			if err != nil {
				if t.Verbose {
					// Log but continue
				}
				continue
			}
			jvmMethods = append(jvmMethods, mi)
		}

		// Translate virtual methods
		for _, em := range cd.virtualMethods {
			mi, err := t.translateMethod(cw, conv, dexFile, r, em)
			if err != nil {
				continue
			}
			jvmMethods = append(jvmMethods, mi)
		}
	}

	accessFlags := uint16(cls.AccessFlags & 0xFFFF)
	// Strip Dalvik-specific ACC_CONSTRUCTOR / ACC_DECLARED_SYNCHRONIZED
	accessFlags &= 0x7FFF

	data := cw.buildClassFile(accessFlags, thisClassIdx, superClassIdx, jvmFields, jvmMethods)

	return &ClassOutput{
		ClassName: internalName,
		Data:      data,
		Methods:   len(jvmMethods),
		Fields:    len(jvmFields),
	}, nil
}

// translateClassNoCode builds a .class file for a class with no bytecode.
func (t *Translator) translateClassNoCode(dexFile *dex.DexFile, cls *dex.ClassDef) (*ClassOutput, error) {
	cw := newClassWriter()

	internalName := validClassName(cls.ClassName)
	thisClassIdx := cw.addClass(internalName)
	superName := "java/lang/Object"
	if cls.Superclass != "" {
		superName = dexTypeToInternal(cls.Superclass)
	}
	superClassIdx := cw.addClass(superName)

	accessFlags := uint16(cls.AccessFlags & 0x7FFF)
	data := cw.buildClassFile(accessFlags, thisClassIdx, superClassIdx, nil, nil)

	return &ClassOutput{
		ClassName: internalName,
		Data:      data,
	}, nil
}

// translateField builds a fieldInfo from an encoded DEX field.
func (t *Translator) translateField(cw *classWriter, dexFile *dex.DexFile, ef encodedField) fieldInfo {
	name := "field"
	desc := "Ljava/lang/Object;"

	if int(ef.fieldIdx) < len(dexFile.Fields) {
		f := dexFile.Fields[ef.fieldIdx]
		name = f.Name
		desc = dexTypeToDescriptor(f.TypeName)
	}

	nameIdx := cw.addUTF8(name)
	descIdx := cw.addUTF8(desc)

	return fieldInfo{
		accessFlags: uint16(ef.accessFlags & 0xFFFF),
		nameIdx:     nameIdx,
		descIdx:     descIdx,
		descriptor:  desc,
	}
}

// translateMethod builds a methodInfo by converting Dalvik bytecode to JVM bytecode.
func (t *Translator) translateMethod(cw *classWriter, conv *converter, dexFile *dex.DexFile, r *bytes.Reader, em encodedMethod) (methodInfo, error) {
	name := "method"
	desc := "()V"

	if int(em.methodIdx) < len(dexFile.Methods) {
		m := dexFile.Methods[em.methodIdx]
		name = m.Name
		if m.Descriptor != "" {
			desc = m.Descriptor
		} else {
			desc = resolveMethodDescriptor(m.Name)
		}
	}

	nameIdx := cw.addUTF8(name)
	descIdx := cw.addUTF8(desc)

	mi := methodInfo{
		accessFlags: uint16(em.accessFlags & 0xFFFF),
		nameIdx:     nameIdx,
		descIdx:     descIdx,
		maxLocals:   1,
	}

	if em.codeOff != 0 {
		ci, err := readCodeItem(r, em.codeOff)
		if err != nil {
			return mi, err
		}

		if ci.insnsSize > 0 && len(ci.insns) > 0 {
			jvmCode := conv.translate(ci.insns, ci.registersSize)
			mi.code = jvmCode
			mi.maxStack = uint16(conv.maxStack)
			mi.maxLocals = ci.registersSize
			if mi.maxLocals == 0 {
				mi.maxLocals = 1
			}
		} else {
			// Empty method body: return void
			mi.code = []byte{jvmReturn}
			mi.maxStack = 1
		}
	}

	return mi, nil
}
