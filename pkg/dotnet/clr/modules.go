/*
Copyright (c) 2026 Security Research
*/
package clr

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/il"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/metadata"
)

// TypeModule is one KB module: a type's IL plus its call graph and literals.
type TypeModule struct {
	Name, IL         string
	Callees, Strings []string
	Vendored         bool
}

// ExtractModules reads metadata + disassembles every TypeDef into one module
// per type. It returns assembly identity, AssemblyRef edges and the P/Invoke
// surface alongside the modules.
func ExtractModules(img *Image) (mods []TypeModule, asm metadata.AssemblyInfo, refs []metadata.AssemblyRef, pinvokes []metadata.ImplMap, err error) {
	tbls, heaps, perr := metadata.Parse(img.Metadata())
	if perr != nil {
		return nil, asm, nil, nil, fmt.Errorf("parse metadata: %w", perr)
	}
	asm, _ = tbls.Assembly()
	refs = tbls.AssemblyRefs()
	pinvokes = tbls.PInvokes()

	// All types emitted from this image share the assembly's vendored status:
	// a framework/runtime/common-vendored assembly contains only vendored types.
	vendored := isFrameworkAssembly(asm.Name)

	res := newResolver(tbls, heaps)
	for _, td := range tbls.Types() {
		mod := TypeModule{Name: moduleName(td.Namespace, td.Name), Vendored: vendored}
		var sb stringBuf
		for _, m := range td.Methods {
			body, berr := il.ReadMethodBody(img.ReaderAt(), img.RVAToOffset, m.RVA, m.ImplFlags)
			if berr != nil {
				sb.add(fmt.Sprintf("// %s: <body error: %v>\n", m.Name, berr))
				continue
			}
			text, callees, strs := il.Disassemble(body, res)
			sb.add(fmt.Sprintf(".method %s\n%s\n", m.Name, text))
			for _, c := range callees {
				mod.Callees = append(mod.Callees, res.Method(c))
			}
			mod.Strings = append(mod.Strings, strs...)
		}
		mod.IL = sb.String()
		mods = append(mods, mod)
	}
	return mods, asm, refs, pinvokes, nil
}

// isFrameworkAssembly reports whether an assembly identity is a framework,
// runtime, or commonly-vendored library — i.e. code that ships with .NET or is
// a well-known third-party dependency rather than first-party application code.
// It is intentionally clr-local (no kb/scanner import) to keep clr self-contained.
func isFrameworkAssembly(name string) bool {
	switch name {
	case "netstandard", "mscorlib":
		return true
	}
	for _, p := range []string{
		"System.",
		"Microsoft.",
		"Windows.",
		"WinRT",
		"CommunityToolkit",
		"protobuf-net",
	} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// moduleName builds the assembly-qualified full type name (backtick arity is
// already embedded in name by the metadata layer, e.g. "List`1").
func moduleName(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "." + name
}

type stringBuf struct{ b []byte }

func (s *stringBuf) add(t string)   { s.b = append(s.b, t...) }
func (s *stringBuf) String() string { return string(s.b) }
