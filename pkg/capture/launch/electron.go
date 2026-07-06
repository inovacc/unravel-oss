/*
Copyright (c) 2026 Security Research
*/
package launch

import "os/exec"

// LaunchElectron assembles an *exec.Cmd that launches an Electron binary with
// CDP enabled on `port` and Chromium profile state isolated to userDataDir
// (T-08-06).
func LaunchElectron(path string, port int, userDataDir string) (*exec.Cmd, error) {
	abs, err := validatePath(path)
	if err != nil {
		return nil, err
	}
	args := []string{
		"--remote-debugging-port=" + itoa(port),
		"--user-data-dir=" + userDataDir,
	}
	return exec.Command(abs, args...), nil
}
