package cdp

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// RegisterRuntimeHandlers registers CDP Runtime domain event handlers.
// Intercepts console messages and parses __capture-prefixed IPC messages.
func (c *Client) RegisterRuntimeHandlers() {
	c.OnEvent("Runtime.consoleAPICalled", func(params json.RawMessage) {
		var data struct {
			Type string `json:"type"`
			Args []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"args"`
		}
		if err := json.Unmarshal(params, &data); err != nil {
			return
		}

		if len(data.Args) == 0 {
			return
		}

		msg := data.Args[0].Value

		// Check for __capture IPC messages
		if strings.HasPrefix(msg, `{"__capture":"ipc"`) {
			var ipcData struct {
				Channel   string `json:"channel"`
				Args      []any  `json:"args"`
				Direction string `json:"dir"`
			}
			if err := json.Unmarshal([]byte(msg), &ipcData); err == nil {
				evt, err := capture.NewEvent(c.seqFn(), time.Now(), capture.EventIPCMessage, capture.SourceCDP,
					capture.IPCMessageData{
						Channel:   ipcData.Channel,
						Args:      ipcData.Args,
						Direction: ipcData.Direction,
					})
				if err != nil {
					return
				}
				c.Emit(evt)
				return
			}
		}

		// Regular console message
		args := make([]string, 0, len(data.Args))
		for _, a := range data.Args {
			args = append(args, a.Value)
		}

		evt, err := capture.NewEvent(c.seqFn(), time.Now(), capture.EventConsoleLog, capture.SourceCDP,
			capture.ConsoleLogData{
				Level:   data.Type,
				Message: msg,
				Args:    args,
			})
		if err != nil {
			return
		}
		c.Emit(evt)
	})
}

// IpcMonitorScript is the JavaScript injected via Runtime.evaluate to
// intercept Electron IPC calls from the renderer process.
const IpcMonitorScript = `
(function() {
  try {
    const {ipcRenderer} = require('electron');
    if (ipcRenderer && !ipcRenderer.__capturePatched) {
      const origSend = ipcRenderer.send.bind(ipcRenderer);
      ipcRenderer.send = function(channel) {
        var args = Array.prototype.slice.call(arguments, 1);
        console.log(JSON.stringify({"__capture":"ipc","channel":channel,"args":args,"dir":"renderer_to_main"}));
        return origSend.apply(ipcRenderer, arguments);
      };
      const origInvoke = ipcRenderer.invoke.bind(ipcRenderer);
      ipcRenderer.invoke = function(channel) {
        var args = Array.prototype.slice.call(arguments, 1);
        console.log(JSON.stringify({"__capture":"ipc","channel":channel,"args":args,"dir":"renderer_to_main_invoke"}));
        return origInvoke.apply(ipcRenderer, arguments);
      };
      ipcRenderer.__capturePatched = true;
    }
  } catch(e) {}
})();
`

// InjectIPCMonitor injects the IPC monitor script into the current execution context.
func (c *Client) InjectIPCMonitor(ctx context.Context) error {
	_, err := c.Send(ctx, "Runtime.evaluate", map[string]any{
		"expression": IpcMonitorScript,
	})
	return err
}
