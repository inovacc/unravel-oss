/*
Copyright (c) 2026 Security Research
*/
package clients

import (
	"context"
	"encoding/json"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// DaemonClient wraps the supervisor daemon.* verb family. v2.17 thin-client
// B7-P3 introduces the first verb (daemon.doctor); more daemon-side verbs
// (logs, stop, restart, version) land in PG-V17-8.
type DaemonClient struct {
	bus ipc.Bus
}

// NewDaemonClient constructs a DaemonClient over the given bus.
func NewDaemonClient(bus ipc.Bus) *DaemonClient {
	return &DaemonClient{bus: bus}
}

// Doctor calls daemon.doctor.
func (c *DaemonClient) Doctor(ctx context.Context, p supervisor.DaemonDoctorParams) (*supervisor.DaemonDoctorResult, error) {
	raw, err := c.bus.Call(ctx, "daemon.doctor", p)
	if err != nil {
		// daemon.doctor never returns a sentinel-mappable error from the
		// supervisor side — DB problems surface as
		// KBReachable=false/PingError on the payload, not as a wire error.
		// Treat any wire error as transport-class (translateErr fallthrough).
		return nil, translateErr(err, nil)
	}
	var out supervisor.DaemonDoctorResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
