//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package visual

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Window-affinity constants from winuser.h.
const (
	WDA_NONE               = 0x00000000
	WDA_MONITOR            = 0x00000001
	WDA_EXCLUDEFROMCAPTURE = 0x00000011
)

// ContentProtected returns true when the target HWND has DisplayAffinity != WDA_NONE.
// hwnd is a uintptr to remain platform-portable in callers; on non-Windows the
// stub returns (false, nil). Wraps user32!GetWindowDisplayAffinity via lazy DLL.
func ContentProtected(hwnd uintptr) (bool, error) {
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("GetWindowDisplayAffinity")
	var affinity uint32
	r1, _, err := proc.Call(hwnd, uintptr(unsafe.Pointer(&affinity)))
	if r1 == 0 {
		// Windows returns 0 on failure (e.g. invalid HWND). Surface ignored
		// errors as nil — the caller treats this as "unknown, not protected".
		_ = err
		return false, nil
	}
	return affinity != WDA_NONE, nil
}
