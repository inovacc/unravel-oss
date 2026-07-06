package replay

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// Shell manages a minimal Electron process for replay.
type Shell struct {
	dir     string
	proxy   *Proxy
	cmd     *exec.Cmd
	session *capture.CaptureSession
}

// NewShell creates a replay shell for the given capture session.
func NewShell(session *capture.CaptureSession) *Shell {
	return &Shell{
		session: session,
		proxy:   NewProxy(session),
	}
}

// Start writes the Electron app to a temp dir, starts the proxy, and spawns Electron.
func (s *Shell) Start(ctx context.Context) error {
	addr, err := s.proxy.Start()
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "unravel-replay-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	s.dir = dir

	packageJSON := `{"name":"unravel-replay","version":"1.0.0","main":"main.js"}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0o644); err != nil {
		return err
	}

	startURL := findStartURL(s.session)

	mainJS := fmt.Sprintf(`const { app, BrowserWindow } = require('electron');
app.commandLine.appendSwitch('proxy-server', '%s');
app.commandLine.appendSwitch('ignore-certificate-errors');

app.whenReady().then(() => {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    webPreferences: {
      preload: require('path').join(__dirname, 'preload.js'),
      nodeIntegration: true,
      contextIsolation: false,
    },
    title: '[REPLAY] %s',
  });
  win.loadURL('%s');
  console.log('[unravel-replay] Replay started for %s');
});

app.on('window-all-closed', () => app.quit());
`, addr, s.session.App.Name, startURL, s.session.App.Name)

	if err := os.WriteFile(filepath.Join(dir, "main.js"), []byte(mainJS), 0o644); err != nil {
		return err
	}

	preload := GeneratePreload(s.session)
	if err := os.WriteFile(filepath.Join(dir, "preload.js"), []byte(preload), 0o644); err != nil {
		return err
	}

	s.cmd = exec.CommandContext(ctx, "npx", "electron", ".")
	s.cmd.Dir = dir
	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("spawn electron: %w (is electron installed? npm install -g electron)", err)
	}

	return nil
}

// Wait waits for the Electron process to exit.
func (s *Shell) Wait() error {
	if s.cmd != nil {
		return s.cmd.Wait()
	}
	return nil
}

// Stop terminates the replay shell and cleans up.
func (s *Shell) Stop() error {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.proxy.Stop()
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
	return nil
}

// ProxyAddr returns the proxy address.
func (s *Shell) ProxyAddr() string {
	return s.proxy.Addr()
}

func findStartURL(session *capture.CaptureSession) string {
	for _, evt := range session.Events {
		if evt.Type == capture.EventWindowState {
			var ws capture.WindowStateData
			if err := capture.DecodeEventData(evt, &ws); err == nil && ws.Property == "navigation" {
				return ws.Value
			}
		}
	}
	for _, evt := range session.Events {
		if evt.Type == capture.EventNetworkRequest {
			var req capture.NetworkRequestData
			if err := capture.DecodeEventData(evt, &req); err == nil {
				return req.URL
			}
		}
	}
	return "about:blank"
}
