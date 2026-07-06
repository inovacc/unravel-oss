/* Copyright (c) 2026 Security Research */
package msi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// TestReadAllLimit_BombRejected verifies a hostile metadata stream that exceeds
// the per-stream cap is rejected rather than materialized into RAM (#17a).
func TestReadAllLimit_BombRejected(t *testing.T) {
	// 64 KiB stream, 1 KiB injected cap.
	big := bytes.NewReader(make([]byte, 64<<10))
	if _, err := readAllLimit(big, 1024); !errors.Is(err, safeio.ErrLimitExceeded) {
		t.Fatalf("want ErrLimitExceeded, got %v", err)
	}

	// Under cap passes.
	small := bytes.NewReader(make([]byte, 512))
	if _, err := readAllLimit(small, 1024); err != nil {
		t.Fatalf("under-cap read should pass: %v", err)
	}
}

// TestDecodeStringPool_NumStringsCapped verifies that an attacker-controlled
// _StringPool length cannot drive an oversized make([]string, n) (#17b).
func TestDecodeStringPool_NumStringsCapped(t *testing.T) {
	old := maxStrings
	maxStrings = 4
	defer func() { maxStrings = old }()

	// poolData implies 100 strings (400 bytes / 4), but cap is 4.
	poolData := make([]byte, 400)
	pool := decodeStringPool(poolData, nil)
	if len(pool) != 4 {
		t.Fatalf("pool len = %d, want capped at 4", len(pool))
	}
}

// TestDecodeRows_RowCapStops verifies a tiny rowSize over a large buffer stops
// at the row cap instead of materializing millions of map allocations (#18).
func TestDecodeRows_RowCapStops(t *testing.T) {
	old := maxRows
	maxRows = 10
	defer func() { maxRows = old }()

	tr := &tableReader{}
	cols := []column{{Name: "x", Type: colShortInt, Width: 2}}
	// 100 rows worth of 2-byte data, cap is 10.
	data := make([]byte, 200)

	rows, err := tr.decodeRows("Bomb", cols, data)
	if err == nil {
		t.Fatal("expected row-cap error, got nil")
	}
	if !strings.Contains(err.Error(), "row cap") {
		t.Fatalf("error %q does not mention row cap", err.Error())
	}
	if len(rows) != 10 {
		t.Fatalf("rows = %d, want 10 (capped)", len(rows))
	}
}

// TestDecodeRows_NormalPasses confirms a legitimate small table is unaffected.
func TestDecodeRows_NormalPasses(t *testing.T) {
	tr := &tableReader{}
	cols := []column{{Name: "x", Type: colShortInt, Width: 2}}
	data := make([]byte, 6) // 3 rows
	binary.LittleEndian.PutUint16(data[0:], 1)
	binary.LittleEndian.PutUint16(data[2:], 2)
	binary.LittleEndian.PutUint16(data[4:], 3)

	rows, err := tr.decodeRows("Ok", cols, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
}
