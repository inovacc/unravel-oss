/*
Copyright (c) 2026 Security Research
*/

package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func quickCmd(t *testing.T) *exec.Cmd {
	t.Helper()
	if runtime.GOOS == "windows" {
		return exec.Command("cmd.exe", "/c", "ver")
	}
	return exec.Command("/bin/sh", "-c", "true")
}

func longCmd(t *testing.T) *exec.Cmd {
	t.Helper()
	if runtime.GOOS == "windows" {
		// ping -n 60 ~ 60 seconds
		return exec.Command("cmd.exe", "/c", "ping", "-n", "60", "127.0.0.1")
	}
	return exec.Command("/bin/sh", "-c", "sleep 30")
}

func TestRunWithTimeout_Exits(t *testing.T) {
	cmd := quickCmd(t)
	err := RunWithTimeout(context.Background(), cmd, ProcessOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("RunWithTimeout returned %v, want nil", err)
	}
}

func TestRunWithTimeout_TimesOut(t *testing.T) {
	cmd := longCmd(t)
	start := time.Now()
	err := RunWithTimeout(context.Background(), cmd, ProcessOptions{Timeout: 250 * time.Millisecond})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrProcessTimeout) {
		t.Fatalf("got %v, want ErrProcessTimeout", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("took %v — timeout did not fire", elapsed)
	}
}

func TestRunWithTimeout_NoLeak(t *testing.T) {
	cmd := longCmd(t)
	_ = RunWithTimeout(context.Background(), cmd, ProcessOptions{Timeout: 200 * time.Millisecond})
	// Within 5s, ProcessState must be set (D-19).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("ProcessState not set within 5s after timeout — D-19 violation")
}

func TestRunWithTimeout_OnReadyFires(t *testing.T) {
	cmd := quickCmd(t)
	called := false
	err := RunWithTimeout(context.Background(), cmd, ProcessOptions{
		Timeout: 5 * time.Second,
		OnReady: func() { called = true },
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !called {
		t.Fatal("OnReady was not invoked")
	}
}
