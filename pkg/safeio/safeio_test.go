package safeio

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func TestReadAllLimit(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		max     int64
		wantErr bool
		wantLen int
	}{
		{"under cap", "hello", 100, false, 5},
		{"exactly at cap", "hello", 5, false, 5},
		{"one over cap", "hello!", 5, true, 5},
		{"empty stream", "", 10, false, 0},
		{"zero cap empty", "", 0, false, 0},
		{"zero cap nonempty", "x", 0, true, 0},
		{"negative cap nonempty", "x", -1, true, 0},
		{"bomb large stream small cap", strings.Repeat("A", 1<<20), 1024, true, 1024},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadAllLimit(strings.NewReader(tc.input), tc.max)
			if tc.wantErr {
				if !errors.Is(err, ErrLimitExceeded) {
					t.Fatalf("want ErrLimitExceeded, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tc.wantLen)
			}
		})
	}
}

func TestCopyLimit(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		max     int64
		wantErr bool
		wantN   int64
	}{
		{"under cap", "data", 100, false, 4},
		{"exactly at cap", "data", 4, false, 4},
		{"over cap", "datax", 4, true, 4},
		{"zero cap nonempty", "x", 0, true, 0},
		{"negative cap nonempty", "x", -5, true, 0},
		{"bomb", strings.Repeat("Z", 1<<20), 256, true, 256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := CopyLimit(&buf, strings.NewReader(tc.input), tc.max)
			if tc.wantErr {
				if !errors.Is(err, ErrLimitExceeded) {
					t.Fatalf("want ErrLimitExceeded, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != tc.wantN {
				t.Fatalf("n = %d, want %d", n, tc.wantN)
			}
		})
	}
}

func TestCheckSize(t *testing.T) {
	tests := []struct {
		name    string
		n, max  int64
		wantErr bool
	}{
		{"valid", 100, 1000, false},
		{"at max", 1000, 1000, false},
		{"over max", 1001, 1000, true},
		{"negative", -1, 1000, true},
		{"zero ok", 0, 1000, false},
		{"attacker max uint32", math.MaxUint32, 1 << 20, true},
		{"default max when zero", 100, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSize(tc.n, tc.max)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidSize) {
					t.Fatalf("want ErrInvalidSize, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestMakeBounded(t *testing.T) {
	t.Run("valid allocates", func(t *testing.T) {
		b, err := MakeBounded(16, 1024)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(b) != 16 {
			t.Fatalf("len = %d, want 16", len(b))
		}
	})
	t.Run("attacker oversized rejected without allocating", func(t *testing.T) {
		// 4 GiB length claim, 64 MiB cap -> must error, not allocate.
		_, err := MakeBounded(math.MaxUint32, 64<<20)
		if !errors.Is(err, ErrInvalidSize) {
			t.Fatalf("want ErrInvalidSize, got %v", err)
		}
	})
	t.Run("negative rejected", func(t *testing.T) {
		_, err := MakeBounded(-1, 1024)
		if !errors.Is(err, ErrInvalidSize) {
			t.Fatalf("want ErrInvalidSize, got %v", err)
		}
	})
}

func TestBudgetAddPerEntryCap(t *testing.T) {
	b := &Budget{MaxTotalBytes: 1 << 30, MaxEntries: 100, MaxEntryBytes: 1024}
	if err := b.Add(1024); err != nil {
		t.Fatalf("entry at cap should pass: %v", err)
	}
	if err := b.Add(1025); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("oversized entry: want ErrBudgetExceeded, got %v", err)
	}
}

func TestBudgetAddAggregate(t *testing.T) {
	b := &Budget{MaxTotalBytes: 2048, MaxEntries: 1000, MaxEntryBytes: 4096}
	if err := b.Add(1024); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := b.Add(1024); err != nil {
		t.Fatalf("second add reaching exactly total: %v", err)
	}
	if err := b.Add(1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over aggregate: want ErrBudgetExceeded, got %v", err)
	}
	if b.Total() != 2048 {
		t.Fatalf("total = %d, want 2048", b.Total())
	}
}

func TestBudgetAddEntryCount(t *testing.T) {
	b := &Budget{MaxTotalBytes: 1 << 30, MaxEntries: 2, MaxEntryBytes: 4096}
	_ = b.Add(1)
	_ = b.Add(1)
	if err := b.Add(1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("over entry count: want ErrBudgetExceeded, got %v", err)
	}
	if b.Entries() != 3 {
		t.Fatalf("entries = %d, want 3", b.Entries())
	}
}

func TestBudgetAddNegative(t *testing.T) {
	b := NewBudget()
	if err := b.Add(-1); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("negative size: want ErrInvalidSize, got %v", err)
	}
}

func TestBudgetAddOverflowSafe(t *testing.T) {
	// total near MaxInt64; an attacker-sized add must not wrap to a small
	// positive and slip past.
	b := &Budget{MaxTotalBytes: math.MaxInt64, MaxEntries: 1 << 20, MaxEntryBytes: math.MaxInt64}
	if err := b.Add(math.MaxInt64 - 10); err != nil {
		t.Fatalf("first big add: %v", err)
	}
	if err := b.Add(100); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("overflow add: want ErrBudgetExceeded, got %v", err)
	}
}

func TestBudgetCheckRatio(t *testing.T) {
	b := NewBudget() // floor 64 MiB, ratio 1000:1
	tests := []struct {
		name                     string
		decompressed, compressed int64
		wantErr                  bool
	}{
		// Small file, huge ratio -> must PASS (below floor).
		{"tiny high ratio passes", 1024, 1, false},
		// Below floor even at extreme ratio passes.
		{"just under floor passes", 64 << 20, 1, false},
		// Above floor AND egregious ratio -> bomb.
		{"egregious bomb trips", 1 << 30, 1, true},
		// Above floor but modest ratio -> ordinary well-compressed data passes.
		{"large modest ratio passes", 1 << 30, 100 << 20, false},
		// Unknown compressed size -> skip.
		{"unknown compressed skipped", 1 << 30, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := b.CheckRatio(tc.decompressed, tc.compressed)
			if tc.wantErr {
				if !errors.Is(err, ErrBudgetExceeded) {
					t.Fatalf("want ErrBudgetExceeded, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBudgetCheckRatioDisabled(t *testing.T) {
	b := NewBudget()
	b.MaxRatio = 0 // disabled
	if err := b.CheckRatio(1<<40, 1); err != nil {
		t.Fatalf("ratio guard disabled should pass: %v", err)
	}
}

// errReader always returns a non-EOF error, to confirm we propagate it.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReadAllLimitPropagatesError(t *testing.T) {
	_, err := ReadAllLimit(errReader{}, 100)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want ErrUnexpectedEOF, got %v", err)
	}
}
