/*
Copyright (c) 2026 Security Research
*/
package launch

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// LaunchTauri assembles an *exec.Cmd that launches a Tauri binary on Windows
// with CDP enabled via WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS. On non-Windows
// hosts Tauri uses WKWebView/webkit2gtk and does not support CDP — callers
// must use --cdp directly. (Pitfall 7)
func LaunchTauri(path string, port int, userDataDir string) (*exec.Cmd, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("%w: Tauri uses WKWebView/webkit2gtk on %s and does not support CDP; use --cdp directly", ErrUnsupported, runtime.GOOS)
	}
	abs, err := validatePath(path)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(abs)
	extra := "--remote-debugging-port=" + itoa(port) + " --user-data-dir=" + userDataDir
	cmd.Env = append(os.Environ(),
		"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="+extra,
		"WEBVIEW2_USER_DATA_FOLDER="+userDataDir,
	)
	return cmd, nil
}
