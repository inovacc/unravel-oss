package fsutil

import (
	"strings"
	"testing"
)

func TestEncodeKsID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "happy path colons to underscores",
			input: "aaaa1111aaaa1111:1.0.0:1714694400",
			want:  "aaaa1111aaaa1111_1.0.0_1714694400",
		},
		{
			name:    "missing colon separator",
			input:   "no-colons-here",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeKsID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeKsID(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("EncodeKsID(%q)=%q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEncodeKsID_ReservedChars(t *testing.T) {
	// every reserved char: < > : | ? * " \ /
	// note: input is parsed as kb:version:capturedAt, so chars must live in version segment
	in := `kb1234:` + `<>|?*"\/` + `:1714694400`
	got, err := EncodeKsID(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// reserved chars in the version segment should all collapse to a single underscore run
	// expected: kb1234_ _ _1714694400 (after collapsing to one underscore)
	want := "kb1234_" + "_" + "_1714694400"
	if got != want {
		t.Fatalf("reserved-chars: got %q want %q", got, want)
	}
}

func TestEncodeKsID_ControlChars(t *testing.T) {
	version := "v\x00\x01\x02\x1f1"
	in := "kb1234:" + version + ":1714694400"
	got, err := EncodeKsID(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := "kb1234_v_1_1714694400"
	if got != want {
		t.Fatalf("control-chars: got %q want %q", got, want)
	}
}

func TestEncodeKsID_TrailingDotSpace(t *testing.T) {
	in := "kb1234:1.0. :1714694400"
	got, err := EncodeKsID(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := "kb1234_1.0_1714694400"
	if got != want {
		t.Fatalf("trailing dots/spaces: got %q want %q", got, want)
	}
}

func TestEncodeKsID_LongVersionTruncated(t *testing.T) {
	version := strings.Repeat("v", 200)
	in := "kb1234:" + version + ":1714694400"
	got, err := EncodeKsID(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	parts := strings.Split(got, "_")
	if len(parts) != 4 {
		t.Fatalf("expected 4 segments after split; got %d (%q)", len(parts), got)
	}
	verSeg := parts[1] + "_" + parts[2]
	// 64-char truncated body + "_" + 8 hex chars = 73 chars total
	if len(verSeg) != 64+1+8 {
		t.Fatalf("expected version segment len 73, got %d (%q)", len(verSeg), verSeg)
	}
	if !strings.HasPrefix(verSeg, strings.Repeat("v", 64)+"_") {
		t.Fatalf("expected truncated body prefix, got %q", verSeg)
	}
}

func TestEncodeKsID_LongVersionUnique(t *testing.T) {
	v1 := strings.Repeat("v", 64) + "ALPHA"
	v2 := strings.Repeat("v", 64) + "BETA"
	g1, err := EncodeKsID("kb1234:" + v1 + ":17")
	if err != nil {
		t.Fatal(err)
	}
	g2, err := EncodeKsID("kb1234:" + v2 + ":17")
	if err != nil {
		t.Fatal(err)
	}
	if g1 == g2 {
		t.Fatalf("expected distinct sha8 suffixes for distinct long versions; both got %q", g1)
	}
}

func TestEncodeKsID_Exactly64NoSha8(t *testing.T) {
	version := strings.Repeat("v", 64)
	in := "kb1234:" + version + ":1714694400"
	got, err := EncodeKsID(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := "kb1234_" + version + "_1714694400"
	if got != want {
		t.Fatalf("exactly-64: got %q want %q", got, want)
	}
}

func TestEncodeKsID_EmptyVersion(t *testing.T) {
	in := "kb1234::1714694400"
	got, err := EncodeKsID(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := "kb1234_unknown_1714694400"
	if got != want {
		t.Fatalf("empty version: got %q want %q", got, want)
	}
}
