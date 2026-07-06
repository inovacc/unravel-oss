package analysis

import (
	"os"

	pyparser "github.com/inovacc/unravel-oss/pkg/transpile/languages/python/parser"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/pymodel"
)

// PythonSymbolTable aggregates all symbols extracted from a Python codebase.
type PythonSymbolTable struct {
	Classes   map[string]*PythonClassInfo    `json:"classes,omitempty"`
	Functions map[string]*PythonFunctionInfo `json:"functions,omitempty"`
	Modules   map[string]*PythonModuleInfo   `json:"modules,omitempty"`
}

// PythonClassInfo describes a class discovered in the codebase.
type PythonClassInfo struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Bases      []string `json:"bases,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	Decorators []string `json:"decorators,omitempty"`
	IsAbstract bool     `json:"is_abstract,omitempty"`
}

// PythonFunctionInfo describes a top-level function.
type PythonFunctionInfo struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Params     []string `json:"params,omitempty"`
	ReturnType string   `json:"return_type,omitempty"`
	Decorators []string `json:"decorators,omitempty"`
	IsAsync    bool     `json:"is_async,omitempty"`
}

// PythonModuleInfo tracks which files contribute to a module.
type PythonModuleInfo struct {
	Name string `json:"name"`
	File string `json:"file"`
}

// BuildPythonSymbolTable extracts symbols from all Python source files.
func BuildPythonSymbolTable(files []*SourceFile) *PythonSymbolTable {
	st := &PythonSymbolTable{
		Classes:   make(map[string]*PythonClassInfo),
		Functions: make(map[string]*PythonFunctionInfo),
		Modules:   make(map[string]*PythonModuleInfo),
	}

	parser := pyparser.New()

	for _, f := range files {
		data, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}

		mod, err := parser.ParseFile(f.RelPath, data)
		if err != nil {
			continue
		}

		modName := pathToModule(f.RelPath)
		if modName != "" {
			st.Modules[modName] = &PythonModuleInfo{
				Name: modName,
				File: f.RelPath,
			}
		}

		extractPythonSymbols(st, mod, f.RelPath)
	}

	return st
}

// extractPythonSymbols walks a Module's body and populates the symbol table.
func extractPythonSymbols(st *PythonSymbolTable, mod *pymodel.Module, relPath string) {
	for _, node := range mod.Body {
		switch node.Type {
		case pymodel.NodeClass:
			extractPythonClass(st, node, relPath)
		case pymodel.NodeFunction:
			extractPythonFunction(st, node, relPath)
		}
	}
}

func extractPythonClass(st *PythonSymbolTable, node *pymodel.Node, relPath string) {
	key := node.Name
	if _, exists := st.Classes[key]; exists {
		key = relPath + ":" + node.Name
	}

	info := &PythonClassInfo{
		Name:       node.Name,
		File:       relPath,
		Line:       node.Line,
		Decorators: node.Decorators,
	}

	// Extract bases from metadata
	if bases, ok := node.Metadata["bases"]; ok && bases != "" {
		info.Bases = append(info.Bases, splitComma(bases)...)
	}

	// Check if abstract (inherits ABC or has ABCMeta or abstractmethod decorator)
	for _, base := range info.Bases {
		if base == "ABC" || base == "ABCMeta" {
			info.IsAbstract = true
		}
	}

	for _, dec := range info.Decorators {
		if dec == "abstractmethod" {
			info.IsAbstract = true
		}
	}

	// Extract methods from children
	for _, child := range node.Children {
		if child.Type == pymodel.NodeFunction {
			info.Methods = append(info.Methods, child.Name)
		}
	}

	st.Classes[key] = info
}

func extractPythonFunction(st *PythonSymbolTable, node *pymodel.Node, relPath string) {
	key := node.Name
	if _, exists := st.Functions[key]; exists {
		key = relPath + ":" + node.Name
	}

	info := &PythonFunctionInfo{
		Name:       node.Name,
		File:       relPath,
		Line:       node.Line,
		Decorators: node.Decorators,
	}

	if rt, ok := node.Metadata["return_type"]; ok {
		info.ReturnType = rt
	}

	if async, ok := node.Metadata["async"]; ok && async == "true" {
		info.IsAsync = true
	}

	for _, p := range node.Params {
		param := p.Name
		if p.TypeHint != "" {
			param += ": " + p.TypeHint
		}

		info.Params = append(info.Params, param)
	}

	st.Functions[key] = info
}

// splitComma splits a comma-separated string and trims whitespace.
func splitComma(s string) []string {
	var result []string

	for _, part := range splitOn(s, ',') {
		trimmed := trimLeftSpace(part)
		// Trim right
		for len(trimmed) > 0 && (trimmed[len(trimmed)-1] == ' ' || trimmed[len(trimmed)-1] == '\t') {
			trimmed = trimmed[:len(trimmed)-1]
		}

		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// splitOn splits a string on a delimiter byte.
func splitOn(s string, delim byte) []string {
	var result []string

	start := 0

	for i := 0; i < len(s); i++ {
		if s[i] == delim {
			result = append(result, s[start:i])
			start = i + 1
		}
	}

	result = append(result, s[start:])

	return result
}
