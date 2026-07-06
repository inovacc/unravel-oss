/*
Copyright (c) 2026 Security Research
*/
package clr

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/il"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/metadata"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/sig"
)

// resolver adapts metadata tables + heaps + the sig printer to il.TokenResolver.
type resolver struct {
	t *metadata.Tables
	h *metadata.Heaps
}

func newResolver(t *metadata.Tables, h *metadata.Heaps) il.TokenResolver {
	return &resolver{t: t, h: h}
}

func (r *resolver) Method(tok il.Token) string {
	name, blob, ok := r.t.MethodName(tok)
	if !ok {
		return ""
	}
	ms, err := sig.DecodeMethodSig(blob)
	if err != nil {
		return name
	}
	// Render the fully-typed callee: "<ret> <Type::Method>(<params>)". The sig
	// printer owns the canonical type rendering so the IL text and call-graph
	// edges carry the resolved signature (no INT-phase follow-up — complete here).
	return formatCallee(name, ms)
}

// formatCallee renders a resolved method as "<ret> name(<params>)" using the
// canonical sig type printer. name is the already-qualified "Type::Method".
func formatCallee(name string, ms sig.MethodSig) string {
	params := make([]string, len(ms.Params))
	for i, p := range ms.Params {
		params[i] = p.String()
	}
	return ms.Ret.String() + " " + name + "(" + strings.Join(params, ", ") + ")"
}

func (r *resolver) Field(tok il.Token) string { n, _, _ := r.t.FieldName(tok); return n }
func (r *resolver) Type(tok il.Token) string  { n, _ := r.t.TypeName(tok); return n }
func (r *resolver) UserString(tok il.Token) string {
	return `"` + r.h.UserString(uint32(tok.RowID())) + `"`
}
