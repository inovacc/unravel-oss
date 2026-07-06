/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// helper: spin up a supervisor + in-memory net.Pipe transport. Returns a
// client + a cleanup that closes both ends.
func newTestBus(t *testing.T) (*ipc.Client, *Supervisor, func()) {
	t.Helper()
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srvConn, cliConn := net.Pipe()
	go sv.server.ServeConn(context.Background(), srvConn)
	cli := ipc.NewClient(cliConn)
	cleanup := func() {
		_ = cli.Close()
		_ = srvConn.Close()
	}
	return cli, sv, cleanup
}

// call is a small helper that JSON-decodes the result into out (if non-nil).
func call(t *testing.T, cli *ipc.Client, method string, params any, out any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := cli.Call(ctx, method, params)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s: unmarshal: %v", method, err)
		}
	}
}

// TestLifecycle_FullCycle walks the canonical happy path described in the
// PG-V17-4 plan: agent.register → session.connect → workspace.activate →
// workspace.list → workspace.deactivate → workspace.list (gone) →
// session.disconnect → agent.unregister.
func TestLifecycle_FullCycle(t *testing.T) {
	cli, sv, cleanup := newTestBus(t)
	defer cleanup()
	_ = sv

	// 1. agent.register
	var reg AgentRegisterResult
	call(t, cli, "agent.register", AgentRegisterParams{ClientKind: "claude_code", CWD: "/tmp/proj"}, &reg)
	if reg.AgentID == "" {
		t.Fatal("agent.register: empty agent_id")
	}

	// 2. agent.list shows the new agent
	var list AgentListResult
	call(t, cli, "agent.list", map[string]any{}, &list)
	if len(list.Agents) != 1 || list.Agents[0].AgentID != reg.AgentID {
		t.Fatalf("agent.list = %+v", list.Agents)
	}

	// 3. session.connect
	var sconn SessionConnectResult
	call(t, cli, "session.connect", SessionConnectParams{
		AgentID: reg.AgentID, CWD: "/tmp/proj",
	}, &sconn)
	if sconn.SessionID == "" {
		t.Fatal("session.connect: empty session_id")
	}

	// 4. workspace.activate
	var wact WorkspaceActivateResult
	call(t, cli, "workspace.activate", WorkspaceActivateParams{
		SessionID: sconn.SessionID, App: "com.example.testapp",
	}, &wact)
	if wact.WorkspaceID == "" {
		t.Fatal("workspace.activate: empty workspace_id")
	}

	// 5. workspace.list → pin_count == 1
	var wlist WorkspaceListResult
	call(t, cli, "workspace.list", map[string]any{}, &wlist)
	if len(wlist.Workspaces) != 1 {
		t.Fatalf("workspace.list len = %d, want 1", len(wlist.Workspaces))
	}
	if wlist.Workspaces[0].PinCount != 1 {
		t.Errorf("pin_count = %d, want 1", wlist.Workspaces[0].PinCount)
	}

	// 6. session.show reflects the binding
	var srec SessionRecord
	call(t, cli, "session.show", SessionIDParams{SessionID: sconn.SessionID}, &srec)
	if srec.WorkspaceID != wact.WorkspaceID {
		t.Errorf("session.show WorkspaceID = %q, want %q", srec.WorkspaceID, wact.WorkspaceID)
	}

	// 7. workspace.deactivate → workspace gone
	call(t, cli, "workspace.deactivate", SessionIDParams{SessionID: sconn.SessionID}, nil)
	call(t, cli, "workspace.list", map[string]any{}, &wlist)
	if len(wlist.Workspaces) != 0 {
		t.Errorf("workspace.list after deactivate = %d, want 0", len(wlist.Workspaces))
	}

	// 8. session.disconnect
	call(t, cli, "session.disconnect", SessionIDParams{SessionID: sconn.SessionID}, nil)

	// 9. agent.unregister
	call(t, cli, "agent.unregister", AgentUnregisterParams{AgentID: reg.AgentID}, nil)

	call(t, cli, "agent.list", map[string]any{}, &list)
	if len(list.Agents) != 0 {
		t.Errorf("agent.list after unregister = %d, want 0", len(list.Agents))
	}
}

// TestLifecycle_AgentUnregister_CascadesSessions confirms that
// unregistering an agent cleans up its sessions (and their workspace
// pins) automatically.
func TestLifecycle_AgentUnregister_CascadesSessions(t *testing.T) {
	cli, _, cleanup := newTestBus(t)
	defer cleanup()

	var reg AgentRegisterResult
	call(t, cli, "agent.register", AgentRegisterParams{ClientKind: "claude_code"}, &reg)

	var s1, s2 SessionConnectResult
	call(t, cli, "session.connect", SessionConnectParams{AgentID: reg.AgentID, CWD: "/a"}, &s1)
	call(t, cli, "session.connect", SessionConnectParams{AgentID: reg.AgentID, CWD: "/b"}, &s2)

	var w WorkspaceActivateResult
	call(t, cli, "workspace.activate", WorkspaceActivateParams{
		SessionID: s1.SessionID, App: "com.example.app",
	}, &w)

	call(t, cli, "agent.unregister", AgentUnregisterParams{AgentID: reg.AgentID}, nil)

	// Sessions gone.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := cli.Call(ctx, "session.show", SessionIDParams{SessionID: s1.SessionID}); err == nil {
		t.Errorf("session.show s1: want NotFound, got nil")
	}

	// Workspace gone (only one agent was pinning it).
	var wlist WorkspaceListResult
	call(t, cli, "workspace.list", map[string]any{}, &wlist)
	if len(wlist.Workspaces) != 0 {
		t.Errorf("workspaces after cascade = %d, want 0", len(wlist.Workspaces))
	}
}

// TestLifecycle_UnknownIDs_ReturnNotFound covers the not-found path for
// every state verb that takes an id.
func TestLifecycle_UnknownIDs_ReturnNotFound(t *testing.T) {
	cli, _, cleanup := newTestBus(t)
	defer cleanup()

	cases := []struct {
		verb   string
		params any
	}{
		{"agent.unregister", AgentUnregisterParams{AgentID: "deadbeef"}},
		{"session.disconnect", SessionIDParams{SessionID: "deadbeef"}},
		{"session.rebind_cwd", SessionRebindParams{SessionID: "deadbeef", CWD: "/x"}},
		{"session.heartbeat", SessionIDParams{SessionID: "deadbeef"}},
		{"session.show", SessionIDParams{SessionID: "deadbeef"}},
		{"workspace.show", WorkspaceIDParams{WorkspaceID: "deadbeef"}},
	}
	for _, tc := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := cli.Call(ctx, tc.verb, tc.params)
		cancel()
		var eb *ipc.ErrorBody
		if !errors.As(err, &eb) || eb.Code != ipc.CodeNotFound {
			t.Errorf("%s: err = %v, want CodeNotFound", tc.verb, err)
		}
	}
}

// TestLifecycle_HeartbeatUpdatesLastHeartbeat verifies that the heartbeat
// verb advances LastHeartbeat on the session record via the injected clock.
func TestLifecycle_HeartbeatUpdatesLastHeartbeat(t *testing.T) {
	cli, sv, cleanup := newTestBus(t)
	defer cleanup()

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sv.now = func() time.Time { return t0 }

	var reg AgentRegisterResult
	call(t, cli, "agent.register", AgentRegisterParams{ClientKind: "x"}, &reg)
	var sconn SessionConnectResult
	call(t, cli, "session.connect", SessionConnectParams{AgentID: reg.AgentID}, &sconn)

	t1 := t0.Add(30 * time.Second)
	sv.now = func() time.Time { return t1 }
	call(t, cli, "session.heartbeat", SessionIDParams{SessionID: sconn.SessionID}, nil)

	var srec SessionRecord
	call(t, cli, "session.show", SessionIDParams{SessionID: sconn.SessionID}, &srec)
	if !srec.LastHeartbeat.Equal(t1) {
		t.Errorf("LastHeartbeat = %v, want %v", srec.LastHeartbeat, t1)
	}
}

// TestLifecycle_WorkspaceSharedByTwoAgents confirms ref-counting: two
// agents pinning the same app share one WorkspaceRecord, and the row
// only goes away when the last agent detaches.
func TestLifecycle_WorkspaceSharedByTwoAgents(t *testing.T) {
	cli, _, cleanup := newTestBus(t)
	defer cleanup()

	var a1, a2 AgentRegisterResult
	call(t, cli, "agent.register", AgentRegisterParams{ClientKind: "x"}, &a1)
	call(t, cli, "agent.register", AgentRegisterParams{ClientKind: "x"}, &a2)

	var s1, s2 SessionConnectResult
	call(t, cli, "session.connect", SessionConnectParams{AgentID: a1.AgentID}, &s1)
	call(t, cli, "session.connect", SessionConnectParams{AgentID: a2.AgentID}, &s2)

	var w1, w2 WorkspaceActivateResult
	call(t, cli, "workspace.activate", WorkspaceActivateParams{SessionID: s1.SessionID, App: "app.x"}, &w1)
	call(t, cli, "workspace.activate", WorkspaceActivateParams{SessionID: s2.SessionID, App: "app.x"}, &w2)
	if w1.WorkspaceID != w2.WorkspaceID {
		t.Fatalf("expected shared workspace id, got %q vs %q", w1.WorkspaceID, w2.WorkspaceID)
	}

	var wlist WorkspaceListResult
	call(t, cli, "workspace.list", map[string]any{}, &wlist)
	if len(wlist.Workspaces) != 1 || wlist.Workspaces[0].PinCount != 2 {
		t.Fatalf("pin_count after 2 activates = %+v, want 1 row pin_count=2", wlist.Workspaces)
	}

	call(t, cli, "workspace.deactivate", SessionIDParams{SessionID: s1.SessionID}, nil)
	call(t, cli, "workspace.list", map[string]any{}, &wlist)
	if len(wlist.Workspaces) != 1 || wlist.Workspaces[0].PinCount != 1 {
		t.Fatalf("after one deactivate, want pin_count=1, got %+v", wlist.Workspaces)
	}

	call(t, cli, "workspace.deactivate", SessionIDParams{SessionID: s2.SessionID}, nil)
	call(t, cli, "workspace.list", map[string]any{}, &wlist)
	if len(wlist.Workspaces) != 0 {
		t.Fatalf("after both deactivates, want 0 workspaces, got %+v", wlist.Workspaces)
	}
}

// TestLifecycle_RebindCWD updates the session's CWD field.
func TestLifecycle_RebindCWD(t *testing.T) {
	cli, _, cleanup := newTestBus(t)
	defer cleanup()

	var reg AgentRegisterResult
	call(t, cli, "agent.register", AgentRegisterParams{ClientKind: "x"}, &reg)
	var sconn SessionConnectResult
	call(t, cli, "session.connect", SessionConnectParams{AgentID: reg.AgentID, CWD: "/old"}, &sconn)
	call(t, cli, "session.rebind_cwd", SessionRebindParams{SessionID: sconn.SessionID, CWD: "/new"}, nil)
	var srec SessionRecord
	call(t, cli, "session.show", SessionIDParams{SessionID: sconn.SessionID}, &srec)
	if srec.CWD != "/new" {
		t.Errorf("CWD = %q, want /new", srec.CWD)
	}
}
