package replay

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// GeneratePreload generates a preload.js that replays IPC messages
// at their original relative timestamps.
func GeneratePreload(session *capture.CaptureSession) string {
	var ipcEvents []struct {
		DelayMs   int64
		Channel   string
		Args      string
		Direction string
	}

	baseTime := session.Capture.StartedAt

	for _, evt := range session.Events {
		if evt.Type != capture.EventIPCMessage {
			continue
		}

		var ipc capture.IPCMessageData
		if err := json.Unmarshal(evt.Data, &ipc); err != nil {
			continue
		}

		argsJSON, _ := json.Marshal(ipc.Args)
		delayMs := max(evt.TS.Sub(baseTime).Milliseconds(), 0)

		ipcEvents = append(ipcEvents, struct {
			DelayMs   int64
			Channel   string
			Args      string
			Direction string
		}{
			DelayMs:   delayMs,
			Channel:   ipc.Channel,
			Args:      string(argsJSON),
			Direction: ipc.Direction,
		})
	}

	var sb strings.Builder
	sb.WriteString(`// Auto-generated IPC replay preload
const { ipcRenderer } = require('electron');

console.log('[unravel-replay] IPC replay preload loaded');

`)

	for _, evt := range ipcEvents {
		if evt.Direction == "renderer_to_main" || evt.Direction == "renderer_to_main_invoke" {
			sb.WriteString(fmt.Sprintf(`setTimeout(() => {
  console.log('[unravel-replay] IPC: %s');
  ipcRenderer.send(%q, ...%s);
}, %d);

`, evt.Channel, evt.Channel, evt.Args, evt.DelayMs))
		}
	}

	return sb.String()
}
