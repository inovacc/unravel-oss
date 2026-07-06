package analysis

import (
	"os"
	"slices"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/ast"
)

// SymbolTable aggregates all symbols extracted from a C++ codebase.
type SymbolTable struct {
	Classes    map[string]*ClassInfo     `json:"classes,omitempty"`
	Functions  map[string]*FunctionInfo  `json:"functions,omitempty"`
	Enums      map[string]*EnumInfo      `json:"enums,omitempty"`
	Namespaces map[string]*NamespaceInfo `json:"namespaces,omitempty"`
	Typedefs   map[string]*TypedefInfo   `json:"typedefs,omitempty"`
}

// ClassInfo describes a class/struct/union discovered in the codebase.
type ClassInfo struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"` // class, struct, union
	File           string   `json:"file"`
	Line           int      `json:"line"`
	BaseClasses    []string `json:"base_classes,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	Fields         []string `json:"fields,omitempty"`
	HasVirtual     bool     `json:"has_virtual,omitempty"`
	HasPure        bool     `json:"has_pure,omitempty"`
	HasDestructor  bool     `json:"has_destructor,omitempty"`
	HasConstructor bool     `json:"has_constructor,omitempty"`
	TemplateParams []string `json:"template_params,omitempty"`
}

// FunctionInfo describes a free function.
type FunctionInfo struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	ReturnType string   `json:"return_type"`
	Params     []string `json:"params,omitempty"`
	IsTemplate bool     `json:"is_template,omitempty"`
}

// EnumInfo describes an enum declaration.
type EnumInfo struct {
	Name   string   `json:"name"`
	File   string   `json:"file"`
	Line   int      `json:"line"`
	Scoped bool     `json:"scoped,omitempty"`
	Values []string `json:"values,omitempty"`
}

// NamespaceInfo describes a namespace declaration.
type NamespaceInfo struct {
	Name  string   `json:"name"`
	Files []string `json:"files"` // files declaring this namespace
}

// TypedefInfo describes a typedef or using alias.
type TypedefInfo struct {
	Name       string `json:"name"`
	Underlying string `json:"underlying"`
	File       string `json:"file"`
	Line       int    `json:"line"`
}

// BuildSymbolTable extracts symbols from all source files using the AST builder.
func BuildSymbolTable(files []*SourceFile) *SymbolTable {
	st := &SymbolTable{
		Classes:    make(map[string]*ClassInfo),
		Functions:  make(map[string]*FunctionInfo),
		Enums:      make(map[string]*EnumInfo),
		Namespaces: make(map[string]*NamespaceInfo),
		Typedefs:   make(map[string]*TypedefInfo),
	}

	builder := ast.NewBuilder()

	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}

		tu := builder.BuildFromSource(f.RelPath, string(data))
		extractSymbols(st, tu, f.RelPath)
	}

	return st
}

// extractSymbols walks a TranslationUnit and populates the symbol table.
func extractSymbols(st *SymbolTable, tu *ast.TranslationUnit, relPath string) {
	for _, decl := range tu.Decls {
		switch d := decl.(type) {
		case *ast.Class:
			extractClass(st, d, relPath)
		case *ast.Function:
			extractFunction(st, d, relPath)
		case *ast.Enum:
			extractEnum(st, d, relPath)
		case *ast.Namespace:
			extractNamespace(st, d, relPath)
		case *ast.TypedefDecl:
			extractTypedef(st, d, relPath)
		}
	}
}

func extractClass(st *SymbolTable, cls *ast.Class, relPath string) {
	key := cls.Name
	if _, exists := st.Classes[key]; exists {
		// Use file-qualified key for duplicate class names
		key = relPath + ":" + cls.Name
	}

	info := &ClassInfo{
		Name: cls.Name,
		Kind: string(cls.Kind),
		File: relPath,
		Line: cls.Pos().Line,
	}

	for _, base := range cls.BaseClasses {
		info.BaseClasses = append(info.BaseClasses, base.Name)
	}

	for _, m := range cls.Methods {
		info.Methods = append(info.Methods, m.Name)
		if m.Virtual {
			info.HasVirtual = true
		}

		if m.Pure {
			info.HasPure = true
		}
	}

	for _, f := range cls.Fields {
		info.Fields = append(info.Fields, f.Name)
	}

	if cls.Destructor != nil {
		info.HasDestructor = true
	}

	if len(cls.Constructors) > 0 {
		info.HasConstructor = true
	}

	for _, tp := range cls.TemplateParams {
		info.TemplateParams = append(info.TemplateParams, tp.Name)
	}

	st.Classes[key] = info
}

func extractFunction(st *SymbolTable, fn *ast.Function, relPath string) {
	key := fn.Name
	if _, exists := st.Functions[key]; exists {
		key = relPath + ":" + fn.Name
	}

	info := &FunctionInfo{
		Name: fn.Name,
		File: relPath,
		Line: fn.Pos().Line,
	}

	if fn.ReturnType != nil {
		info.ReturnType = fn.ReturnType.Name
	}

	for _, p := range fn.Params {
		param := p.Name
		if p.Type != nil {
			param = p.Type.Name + " " + p.Name
		}

		info.Params = append(info.Params, param)
	}

	if len(fn.TemplateParams) > 0 {
		info.IsTemplate = true
	}

	st.Functions[key] = info
}

func extractEnum(st *SymbolTable, en *ast.Enum, relPath string) {
	key := en.Name
	if _, exists := st.Enums[key]; exists {
		key = relPath + ":" + en.Name
	}

	info := &EnumInfo{
		Name:   en.Name,
		File:   relPath,
		Line:   en.Pos().Line,
		Scoped: en.Scoped,
	}

	for _, v := range en.Values {
		info.Values = append(info.Values, v.Name)
	}

	st.Enums[key] = info
}

func extractNamespace(st *SymbolTable, ns *ast.Namespace, relPath string) {
	info, ok := st.Namespaces[ns.Name]
	if !ok {
		info = &NamespaceInfo{Name: ns.Name}
		st.Namespaces[ns.Name] = info
	}

	// Track which files declare this namespace
	if slices.Contains(info.Files, relPath) {
		return
	}

	info.Files = append(info.Files, relPath)
}

func extractTypedef(st *SymbolTable, td *ast.TypedefDecl, relPath string) {
	info := &TypedefInfo{
		Name: td.Name,
		File: relPath,
		Line: td.Pos().Line,
	}

	if td.Underlying != nil {
		info.Underlying = td.Underlying.Name
	}

	st.Typedefs[td.Name] = info
}
