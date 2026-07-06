/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockFrameSource struct {
	frames int
	err    error
	calls  int
}

func (m *mockFrameSource) Capture(ctx context.Context, port int, dur time.Duration) (int, error) {
	m.calls++
	if m.err != nil {
		return 0, m.err
	}
	return m.frames, nil
}

func TestDispatch_WireWithFrames(t *testing.T) {
	src := &mockFrameSource{frames: 42}
	res, err := dispatch(context.Background(), &DissectTarget{CDPPort: 9222}, []string{"wire"}, src)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(res) != 1 || !res[0].OK || res[0].FramesCaptured != 42 || res[0].Pass != "wire" {
		t.Fatalf("unexpected: %+v", res)
	}
	if res[0].Note != "" {
		t.Errorf("expected empty note, got %q", res[0].Note)
	}
}

func TestDispatch_AuthZeroFrames(t *testing.T) {
	src := &mockFrameSource{frames: 0}
	res, err := dispatch(context.Background(), &DissectTarget{}, []string{"auth"}, src)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(res) != 1 || res[0].OK || res[0].Note != "no frames" {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestDispatch_BehaviorNoOp(t *testing.T) {
	src := &mockFrameSource{}
	res, err := dispatch(context.Background(), &DissectTarget{}, []string{"behavior"}, src)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(res) != 1 || res[0].OK || res[0].Note != noOpBehaviorNote {
		t.Fatalf("unexpected: %+v", res)
	}
	if src.calls != 0 {
		t.Errorf("behavior must not invoke frameSource; calls=%d", src.calls)
	}
}

func TestDispatch_UnknownDimSkipped(t *testing.T) {
	src := &mockFrameSource{frames: 1}
	res, err := dispatch(context.Background(), &DissectTarget{}, []string{"binary_surface", "wire"}, src)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(res) != 1 || res[0].Pass != "wire" {
		t.Fatalf("unknown dim not skipped: %+v", res)
	}
}

func TestDispatch_CtxCancelMidLoop(t *testing.T) {
	src := &mockFrameSource{frames: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dispatch(ctx, &DissectTarget{}, []string{"wire"}, src)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected wrapped Canceled, got %v", err)
	}
}

func TestDispatch_NilSource(t *testing.T) {
	if _, err := dispatch(context.Background(), &DissectTarget{}, []string{"wire"}, nil); err == nil {
		t.Fatal("expected error on nil source")
	}
}

func TestCapFor(t *testing.T) {
	for _, tc := range []struct {
		dim  string
		want int
	}{
		{"wire", 85},
		{"auth", 80},
		{"state_machines", 80},
		{"ipc", 80},
		{"behavior", 0},
		{"crypto", 0},
	} {
		if got := capFor(tc.dim); got != tc.want {
			t.Errorf("capFor(%q) = %d, want %d", tc.dim, got, tc.want)
		}
	}
}

func TestDispatch_CaptureErrorDeadlinePropagates(t *testing.T) {
	src := &mockFrameSource{err: context.DeadlineExceeded}
	_, err := dispatch(context.Background(), &DissectTarget{}, []string{"wire"}, src)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected wrapped DeadlineExceeded, got %v", err)
	}
}

func TestDispatch_NonFatalCaptureErrorContinues(t *testing.T) {
	src := &mockFrameSource{err: errors.New("transient")}
	res, err := dispatch(context.Background(), &DissectTarget{}, []string{"wire", "auth"}, src)
	if err != nil {
		t.Fatalf("transient error must not stop loop: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	for _, r := range res {
		if r.OK {
			t.Errorf("expected OK=false on transient err: %+v", r)
		}
	}
}
