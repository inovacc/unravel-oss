/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/metadata"
)

// DotNetInfoInput is the typed input for the pure-Go M0 identity+deps reader.
//
// Path points at a managed .NET assembly (.dll/.exe). It is served by the
// existing unravel_dotnet_info tool: when Path is set the handler reads
// identity + AssemblyRef edges + P/Invoke names straight from the pure-Go clr
// reader (no external tool, no DB); when Path is empty the handler falls back
// to the legacy directory scan of .deps.json / .runtimeconfig.json files.
type DotNetInfoInput struct {
	Path string `json:"path" jsonschema:"absolute path to a managed .NET assembly (.dll/.exe)"`
}

// DotNetRef is one AssemblyRef dependency edge. It projects the
// metadata.AssemblyRef fields returned by clr.ExtractModules into the MCP wire
// shape (clr.ExtractModules returns metadata.AssemblyInfo / []metadata.AssemblyRef
// / []metadata.ImplMap — package clr does NOT define those types).
type DotNetRef struct {
	Name    string    `json:"name"`
	Version [4]uint16 `json:"version"`
	Culture string    `json:"culture,omitempty"`
}

// DotNetInfoOutput is the identity + dependency surface from M0.
type DotNetInfoOutput struct {
	AssemblyName string      `json:"assembly_name"`
	Version      [4]uint16   `json:"version"`
	Culture      string      `json:"culture,omitempty"`
	AssemblyRefs []DotNetRef `json:"assembly_refs"`
	PInvokes     []string    `json:"pinvokes,omitempty"`
}

// dotnetInfo reads identity + AssemblyRef deps + P/Invoke names from a managed
// PE using the pure-Go clr reader. No external tool, no DB.
func dotnetInfo(_ context.Context, in DotNetInfoInput) (DotNetInfoOutput, error) {
	img, err := clr.Open(in.Path)
	if err != nil {
		return DotNetInfoOutput{}, fmt.Errorf("dotnet info: open: %w", err)
	}
	// asm is metadata.AssemblyInfo, refs is []metadata.AssemblyRef, pinvokes is
	// []metadata.ImplMap (types owned by unravel/pkg/dotnet/clr/metadata, not clr).
	// SEC: clr.ExtractModules drives metadata-table decoders over a hostile PE
	// and can panic; this MCP handler runs in a goroutine with no server-level
	// recover, so an escaping panic would crash the whole process. Convert it to
	// an error (mirrors clr.Open and analyze_dotnet_decompile.go).
	_, asm, refs, pinvokes, err := safeExtractModules(img)
	if err != nil {
		return DotNetInfoOutput{}, fmt.Errorf("dotnet info: extract: %w", err)
	}
	out := DotNetInfoOutput{
		AssemblyName: asm.Name,
		Version:      asm.Version,
		Culture:      asm.Culture,
	}
	for _, r := range refs {
		out.AssemblyRefs = append(out.AssemblyRefs, DotNetRef{Name: r.Name, Version: r.Version, Culture: r.Culture})
	}
	for _, p := range pinvokes {
		out.PInvokes = append(out.PInvokes, p.ImportScope+"!"+p.ImportName)
	}
	return out, nil
}

// safeExtractModules wraps clr.ExtractModules in a recover so a panic from
// decoding a hostile PE is converted to an error rather than crashing the
// process. The MCP server (go-sdk) has no production-level recover around tool
// handlers, so an escaping panic would take down the whole server.
func safeExtractModules(img *clr.Image) (mods []clr.TypeModule, asm metadata.AssemblyInfo, refs []metadata.AssemblyRef, pinvokes []metadata.ImplMap, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("dotnet extract modules panicked: %v", r)
		}
	}()
	return clr.ExtractModules(img)
}
