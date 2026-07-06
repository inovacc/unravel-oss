/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"errors"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
)

// MaxSingleBufferModules caps in-memory module buffering for ModeSingle CLI
// calls. FullApp/capture must stream via Sink (LinkedIn-scale would OOM).
const MaxSingleBufferModules = 2000

var (
	// ErrSinkRequired is returned when ModeFullApp/capture runs without a Sink.
	ErrSinkRequired = errors.New("native engine requires a Sink for full-app/capture mode")
	// ErrSingleBufferCap is returned when a ModeSingle assembly exceeds the cap.
	ErrSingleBufferCap = errors.New("single-assembly type count exceeds in-memory buffer cap")
)

// Sink receives native per-type modules as they are decompiled. ModeFullApp and
// capture stream every module through a Sink instead of buffering, so a
// LinkedIn-scale assembly tree never accumulates in memory.
type Sink interface {
	// EmitModule is called once per decompiled type module. Returning a non-nil
	// error aborts emission for the current assembly.
	EmitModule(m clr.TypeModule) error
}
