/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"fmt"
	"time"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
)

// runNative decompiles each assembly with the pure-Go clr reader. It never
// spawns a subprocess and never writes .cs files; modules flow to the KB via
// IngestModules(Sink) (INT-3). For ModeSingle the per-type modules are also
// buffered into AssemblyResult.Modules (bounded by INT-4's cap).
func (d *Decompiler) runNative(ctx context.Context, opts Options, mode Mode, asms []Assembly) (*Result, error) {
	res := &Result{StartedAt: time.Now().UTC(), Engine: EngineNative}
	defer func() { res.EndedAt = time.Now().UTC() }()

	// FullApp/capture must stream via Sink; buffering LinkedIn-scale trees OOMs.
	if mode == ModeFullApp && opts.Sink == nil {
		return nil, fmt.Errorf("run native: %w", ErrSinkRequired)
	}

	for _, asm := range asms {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("run native: %w", err)
		}
		ar := AssemblyResult{Name: asm.Name, Path: asm.Path, SHA256: hashFile(asm.Path)}

		img, err := clr.Open(asm.Path)
		if err != nil {
			ar.Err = fmt.Sprintf("clr open: %v", err)
			res.Assemblies = append(res.Assemblies, ar)
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", ar.Name, ar.Err))
			continue
		}

		// SEC: clr.ExtractModules can panic on a hostile PE; convert it to an
		// error so a single crafted assembly cannot crash the decompile run.
		mods, err := safeExtractModules(img)
		if err != nil {
			ar.Err = fmt.Sprintf("extract modules: %v", err)
			res.Assemblies = append(res.Assemblies, ar)
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", ar.Name, ar.Err))
			continue
		}

		ar.ModuleCount = len(mods)
		ar.Decompiled = true
		switch mode {
		case ModeFullApp:
			for _, m := range mods {
				if err := opts.Sink.EmitModule(m); err != nil {
					ar.Err = fmt.Sprintf("sink emit: %v", err)
					res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", ar.Name, ar.Err))
					break
				}
			}
		case ModeSingle:
			if len(mods) > MaxSingleBufferModules {
				return res, fmt.Errorf("run native %s: %w (%d>%d)", asm.Name, ErrSingleBufferCap, len(mods), MaxSingleBufferModules)
			}
			if opts.Sink != nil { // CLI may still pass a sink; honor it too
				for _, m := range mods {
					if err := opts.Sink.EmitModule(m); err != nil {
						ar.Err = fmt.Sprintf("sink emit: %v", err)
						break
					}
				}
			}
			ar.Modules = mods
		}
		res.Assemblies = append(res.Assemblies, ar)
	}
	return res, nil
}

// safeExtractModules wraps clr.ExtractModules in a recover so a panic from
// decoding a hostile PE becomes an error instead of crashing the process. Only
// the module slice is needed here; identity/ref/pinvoke returns are discarded.
func safeExtractModules(img *clr.Image) (mods []clr.TypeModule, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("clr extract modules panicked: %v", r)
		}
	}()
	mods, _, _, _, err = clr.ExtractModules(img)
	return mods, err
}
