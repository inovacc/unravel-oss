/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// TestCaptureWebView2Attach proves, deterministically and hermetically (no
// live WhatsApp, no real CDP port, no external network, sub-second bounded
// context), that the cmd-level attach handling:
//   - Test A: on a connect/dial failure emits an honest D-09 BLOCK on stderr,
//     returns a non-nil wrapped error, never prints "Attached", never panics.
//   - Test B: on a genuine connect prints "Attached (Network.enable)" and
//     returns nil.
//
// The injectable attachFn seam intercepts before any real websocket dial, so
// the fake cdp.Client never touches the network. The fake attachFn cancels
// the attach ctx before returning, which is the only thing that unblocks a
// nil-conn Listen (cdp/client.go) — so attachAndReport's bounded join
// terminates the Listen goroutine WITHIN the subtest. Verified leak-free
// under `go test -race` (no detached goroutine touching the garbage
// cdp.Client after the subtest returns). stderr is captured via an injected
// io.Writer (no process-global os.Stderr swap), so it is concurrency-safe.
func TestCaptureWebView2Attach(t *testing.T) {
	origAttachFn := attachFn
	t.Cleanup(func() { attachFn = origAttachFn })

	cases := []struct {
		name        string
		injectErr   error
		wantErr     bool
		wantStderr  string
		wantStdout  string
		notInStdout string
	}{
		{
			name:        "honest BLOCK on dial failure",
			injectErr:   errors.New("listen: websocket not connected before ctx done"),
			wantErr:     true,
			wantStderr:  "BLOCKED",
			notInStdout: "Attached",
		},
		{
			name:       "success only on genuine connect",
			injectErr:  nil,
			wantErr:    false,
			wantStdout: "Attached (Network.enable)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			// The fake attachFn cancels the attach ctx before returning. This
			// is the deterministic signal that lets attachAndReport's bounded
			// join terminate the Listen goroutine inside this subtest (Listen
			// against a never-connected client only returns on ctx.Done()).
			attachFn = func(actx context.Context, _ *cdp.Client, _ cdp.Target) error {
				cancel()
				return tc.injectErr
			}

			// stdout is an *os.File seam param; capture via a pipe. stderr is
			// an injected io.Writer — capture via a buffer, no global swap.
			outR, outW, _ := os.Pipe()
			var errBuf bytes.Buffer

			var err error
			panicked := func() (p bool) {
				defer func() {
					if r := recover(); r != nil {
						p = true
					}
				}()
				err = attachAndReport(ctx, "127.0.0.1:0", "ws://127.0.0.1:0/devtools/page/x", "wa-desktop", outW, &errBuf)
				return false
			}()

			_ = outW.Close()
			outBuf, _ := io.ReadAll(outR)
			_ = outR.Close()

			if panicked {
				t.Fatalf("attachAndReport panicked (must never panic)")
			}
			if tc.wantErr && err == nil {
				t.Fatalf("want non-nil error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil error, got %v", err)
			}
			if tc.wantStderr != "" && !strings.Contains(errBuf.String(), tc.wantStderr) {
				t.Fatalf("stderr missing %q; got: %s", tc.wantStderr, errBuf.String())
			}
			if tc.wantStdout != "" && !strings.Contains(string(outBuf), tc.wantStdout) {
				t.Fatalf("stdout missing %q; got: %s", tc.wantStdout, outBuf)
			}
			if tc.notInStdout != "" && strings.Contains(string(outBuf), tc.notInStdout) {
				t.Fatalf("stdout must not contain %q (no fabricated success); got: %s", tc.notInStdout, outBuf)
			}
		})
	}
}
