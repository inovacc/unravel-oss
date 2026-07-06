package session

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	"github.com/inovacc/unravel-oss/pkg/capture/fswatch"
)

// Config holds parameters for starting a capture session.
type Config struct {
	AppName         string
	AppPath         string
	Framework       string
	ElectronVersion string
	PID             int
	CDPHost         string
	DataDir         string
	OutputPath      string
}

// Session manages a live capture.
type Session struct {
	config  Config
	events  chan capture.Event
	seq     int64
	started time.Time
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// Start begins a capture session.
func Start(ctx context.Context, cfg Config) (*Session, error) {
	ctx, cancel := context.WithCancel(ctx)

	s := &Session{
		config:  cfg,
		events:  make(chan capture.Event, 1000),
		started: time.Now(),
		cancel:  cancel,
	}

	seqFn := func() int { return int(atomic.AddInt64(&s.seq, 1)) }

	cdpClient := cdp.New(cfg.CDPHost, s.events, seqFn)

	targets, err := cdpClient.DiscoverTargets(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("discover CDP targets: %w", err)
	}

	if len(targets) == 0 {
		cancel()
		return nil, fmt.Errorf("no CDP targets found at %s", cfg.CDPHost)
	}

	var wsURL string
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebugURL != "" {
			wsURL = t.WebSocketDebugURL
			break
		}
	}
	if wsURL == "" {
		wsURL = targets[0].WebSocketDebugURL
	}

	if err := cdpClient.Connect(ctx, wsURL); err != nil {
		cancel()
		return nil, err
	}

	cdpClient.RegisterNetworkHandlers()
	cdpClient.RegisterRuntimeHandlers()
	cdpClient.RegisterPageHandlers()

	if err := cdpClient.EnableDomains(ctx); err != nil {
		_ = cdpClient.Close()
		cancel()
		return nil, err
	}

	_ = cdpClient.InjectIPCMonitor(ctx)

	s.wg.Go(func() {
		_ = cdpClient.Listen(ctx)
		_ = cdpClient.Close()
	})

	if cfg.DataDir != "" {
		if _, err := os.Stat(cfg.DataDir); err == nil {
			watcher := fswatch.New(cfg.DataDir, s.events, seqFn)
			s.wg.Go(func() {
				_ = watcher.Watch(ctx)
			})
		}
	}

	return s, nil
}

// Stop ends the capture session and writes the capture file.
func (s *Session) Stop() (*capture.CaptureSession, error) {
	s.cancel()
	s.wg.Wait()
	close(s.events)

	var events []capture.Event
	for evt := range s.events {
		events = append(events, evt)
	}

	capture.SortEvents(events)

	now := time.Now()
	cs := &capture.CaptureSession{
		Version: capture.FormatVersion,
		App: capture.AppInfo{
			Name:            s.config.AppName,
			Path:            s.config.AppPath,
			Framework:       s.config.Framework,
			ElectronVersion: s.config.ElectronVersion,
			PID:             s.config.PID,
		},
		Capture: capture.CaptureMetadata{
			StartedAt:   s.started,
			EndedAt:     now,
			DurationMs:  now.Sub(s.started).Milliseconds(),
			Host:        runtime.GOOS,
			ToolVersion: "1.0.0",
		},
		Events: events,
	}

	if s.config.OutputPath != "" {
		if err := capture.WriteFile(s.config.OutputPath, cs); err != nil {
			return cs, fmt.Errorf("write capture: %w", err)
		}
	}

	return cs, nil
}

// EventCount returns the current number of collected events.
func (s *Session) EventCount() int {
	return int(atomic.LoadInt64(&s.seq))
}
