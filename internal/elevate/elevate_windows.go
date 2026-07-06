//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package elevate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsElevated reports whether the current process token has Administrator
// privileges. False on any error (treat unknown as non-elevated).
func IsElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return false
	}
	defer func() { _ = token.Close() }()

	var elevation uint32
	var size uint32
	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&size,
	)
	if err != nil {
		return false
	}
	return elevation != 0
}

// pathLikelyNeedsElevation returns true if path lives under a Windows
// directory that typically requires Administrator to read. The check is
// purely path-based — false positives are possible (e.g. user has explicit
// ACL grant) — but EnsureReadable falls back to a stat probe before
// triggering UAC, so a false positive here just means an extra stat.
func pathLikelyNeedsElevation(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	abs = strings.ToLower(filepath.Clean(abs))
	roots := []string{
		strings.ToLower(filepath.Clean(os.Getenv("ProgramFiles") + `\WindowsApps`)),
		strings.ToLower(filepath.Clean(os.Getenv("SystemRoot") + `\WinSxS`)),
		strings.ToLower(filepath.Clean(os.Getenv("SystemRoot") + `\System32\config`)),
		strings.ToLower(filepath.Clean(os.Getenv("ProgramData") + `\Microsoft\Windows\AppRepository`)),
	}
	for _, r := range roots {
		if r == "" || r == "." {
			continue
		}
		if strings.HasPrefix(abs, r+string(filepath.Separator)) || abs == r {
			return true
		}
	}
	return false
}

// canRead probes a path with a stat + (if dir) a sample file body read to
// detect EACCES. Plain ReadDir is insufficient on Windows because LIST
// FOLDER can be granted while READ on individual files is denied
// (default ACL on `C:\Program Files\WindowsApps`). Returns nil when the
// path is fully readable.
func canRead(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_ = f.Close()
		return nil
	}

	// Try a known UWP artifact first. If the dir is a UWP installed app,
	// AppxManifest.xml is the file the analyzer will actually try to read,
	// so probing it is the most accurate signal. Stat-then-Open: stat may
	// succeed on metadata-only access while Open fails with EACCES on the
	// body — that's exactly the WindowsApps default ACL pattern.
	for _, sample := range []string{"AppxManifest.xml", "package.json", "Info.plist"} {
		p := filepath.Join(path, sample)
		if _, err := os.Stat(p); err == nil {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			buf := make([]byte, 1)
			_, _ = f.Read(buf)
			_ = f.Close()
			return nil
		}
	}

	// Fallback: open + read one entry. Empty dir is acceptable (no files
	// to read = nothing to fail on).
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	names, err := d.Readdirnames(1)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		if err.Error() == "EOF" {
			return nil
		}
		return err
	}
	if len(names) == 0 {
		return nil
	}

	// Probe the first listed file. Skip subdirs because their contents
	// don't bear on whether THIS dir is readable.
	first := filepath.Join(path, names[0])
	st, err := os.Stat(first)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return nil
	}
	f, err := os.Open(first)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}

// ElevateChildFlag is the hidden CLI flag injected into the elevated
// child's argv. cmd/root.go detects it during PersistentPreRun and
// redirects os.Stdout + os.Stderr to the named file so the parent
// (which is closing its console) can relay output back to the user.
const ElevateChildFlag = "--__elevate-child"

// ShellExecuteInfoW mirrors SHELLEXECUTEINFOW from shellapi.h. Used so we
// can obtain a process handle from the elevated child for wait + exit-code
// relay (basic ShellExecute returns nothing).
type shellExecuteInfoW struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const seeMaskNoCloseProcess = 0x00000040

var (
	procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
)

func shellExecuteEx(info *shellExecuteInfoW) error {
	r1, _, lastErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(info)))
	if r1 == 0 {
		return lastErr
	}
	return nil
}

// ReExec re-launches the current process under UAC with identical
// command-line arguments + a hidden --__elevate-child flag pointing at a
// temp output file. The function:
//
//  1. Generates the relay file path
//  2. Calls ShellExecuteExW with verb=runas and SEE_MASK_NOCLOSEPROCESS
//  3. Waits on the elevated child's process handle
//  4. Streams the relay file contents back to the parent's own
//     stdout/stderr
//  5. Exits the parent with the child's exit code
//
// Returns ErrAlreadyElevated if the caller is already admin, ErrUserDeclined
// if UAC is dismissed. On success the parent process never returns.
func ReExec(reason string) error {
	if IsElevated() {
		return ErrAlreadyElevated
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}

	relayFile, err := os.CreateTemp("", "unravel-elevate-*.log")
	if err != nil {
		return fmt.Errorf("create relay file: %w", err)
	}
	relayPath := relayFile.Name()
	_ = relayFile.Close()
	defer func() { _ = os.Remove(relayPath) }()

	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}

	// Build child args: original args + hidden relay flag. Skip os.Args[0]
	// — exe is already the binary path. Quote args so spaces survive the
	// shell-execute round trip.
	childArgs := append([]string{}, os.Args[1:]...)
	childArgs = append(childArgs, ElevateChildFlag, relayPath)
	var sb strings.Builder
	for i, a := range childArgs {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if strings.ContainsAny(a, " \t\"") {
			sb.WriteString(`"`)
			sb.WriteString(strings.ReplaceAll(a, `"`, `\"`))
			sb.WriteString(`"`)
		} else {
			sb.WriteString(a)
		}
	}
	argsPtr, err := windows.UTF16PtrFromString(sb.String())
	if err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cwdPtr, err := windows.UTF16PtrFromString(cwd)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "elevate: requesting Administrator (%s)\n", reason)

	info := &shellExecuteInfoW{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verbPtr,
		lpFile:       exePtr,
		lpParameters: argsPtr,
		lpDirectory:  cwdPtr,
		nShow:        syscall.SW_HIDE, // hide the new console; output flows via relay file
	}
	info.cbSize = uint32(unsafe.Sizeof(*info))

	if err := shellExecuteEx(info); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			if errno == 1223 || errno == 5 {
				return ErrUserDeclined
			}
		}
		return fmt.Errorf("ShellExecute runas: %w", err)
	}

	// Wait on the elevated child + stream relay file output back to
	// parent's stdout/stderr. Tail-style: poll the file every 200ms,
	// print new bytes as they arrive, until child exits.
	if info.hProcess != 0 {
		defer windows.CloseHandle(info.hProcess)
		var offset int64
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		done := false
		for !done {
			select {
			case <-ticker.C:
				offset = streamRelay(relayPath, offset)
				st, _ := windows.WaitForSingleObject(info.hProcess, 0)
				if st == windows.WAIT_OBJECT_0 {
					done = true
				}
			}
		}
		// Final flush after child exits.
		streamRelay(relayPath, offset)
		var exitCode uint32
		if err := windows.GetExitCodeProcess(info.hProcess, &exitCode); err == nil {
			os.Exit(int(exitCode))
		}
	}
	os.Exit(0)
	return nil // unreachable
}

// streamRelay reads new bytes appended since `offset` from the relay file
// and copies them to os.Stderr (so they don't pollute structured stdout
// JSON when callers pipe results). Returns the new offset.
func streamRelay(path string, offset int64) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(offset, 0); err != nil {
		return offset
	}
	n, err := io.Copy(os.Stderr, f)
	_ = err
	return offset + n
}

// EnsureReadable verifies that path is readable from the current process.
// On Windows, if the path is under a known elevated-only directory or
// a stat probe returns EACCES, the function calls ReExec to re-launch
// the process under UAC and exits the current process. Returns nil when
// the path is already readable or the caller is already elevated.
//
// If `optional` is true and elevation is declined, returns ErrUserDeclined
// without exiting (caller can proceed with degraded scope). If false,
// returns the original EACCES so the caller can fail-loud.
func EnsureReadable(path, reason string, optional bool) error {
	// Path-based fast path: if the target lives under a known
	// Administrator-only directory (WindowsApps, WinSxS, etc.) and we're
	// not already elevated, re-exec immediately. Don't trust canRead
	// here — WindowsApps default ACL grants FILE_TRAVERSE but denies
	// LIST_DIRECTORY, so Readdirnames returns an empty list with no
	// error and we'd otherwise conclude the path is "readable".
	if pathLikelyNeedsElevation(path) && !IsElevated() {
		if err := ReExec(reason); err != nil {
			if errors.Is(err, ErrUserDeclined) && optional {
				return ErrUserDeclined
			}
			return err
		}
		return nil // unreachable — ReExec exits the parent
	}

	if err := canRead(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrPermission) {
		// Some other error (does-not-exist, etc.) — pass it through to caller.
		return err
	}
	if IsElevated() {
		// Already elevated and still failing — pass through.
		return canRead(path)
	}
	if err := ReExec(reason); err != nil {
		if errors.Is(err, ErrUserDeclined) && optional {
			return ErrUserDeclined
		}
		return err
	}
	return nil // unreachable — ReExec exits the parent
}
