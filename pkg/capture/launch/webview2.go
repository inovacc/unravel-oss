/*
Copyright (c) 2026 Security Research
*/
package launch

import (
	"os"
	"os/exec"
)

// LaunchWebView2 assembles an *exec.Cmd for a WebView2-hosted application,
// passing CDP options via WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS and
// WEBVIEW2_USER_DATA_FOLDER (T-08-06 isolation). WebView2 is Windows-only in
// practice; this helper does not enforce a runtime guard so cross-platform
// Edge variants remain usable, but expect failure on macOS/Linux hosts that
// lack the Microsoft Edge WebView2 runtime.
func LaunchWebView2(path string, port int, userDataDir string) (*exec.Cmd, error) {
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
