/* Copyright (c) 2026 Security Research */
package deb

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// arMember appends one ar member (header + body + padding) to buf.
func arMember(name string, body []byte) []byte {
	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d%s",
		name+"/", 0, 0, 0, "100644", len(body), arEntryMagic)
	out := append([]byte(hdr), body...)
	if len(body)%2 != 0 {
		out = append(out, '\n')
	}
	return out
}

// TestReadArArchive_MemberCountCapped verifies that an ar archive declaring
// more than maxArMembers members is rejected, rather than buffering an
// unbounded number of members in memory.
func TestReadArArchive_MemberCountCapped(t *testing.T) {
	orig := maxArMembers
	maxArMembers = 3
	defer func() { maxArMembers = orig }()

	var data []byte
	data = append(data, []byte(arMagic)...)
	for i := 0; i < maxArMembers+5; i++ {
		data = append(data, arMember(fmt.Sprintf("m%d", i), []byte("x"))...)
	}

	dir := t.TempDir()
	f := filepath.Join(dir, "many.ar")
	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := readArArchive(f)
	if err == nil {
		t.Fatal("expected error for too many ar members, got nil")
	}
	if !strings.Contains(err.Error(), "members") {
		t.Fatalf("expected member-count error, got %v", err)
	}
}

// TestReadArEntry_OversizedRejected verifies that an ar member declaring a size
// above maxArMemberBytes is rejected before allocating.
func TestReadArEntry_OversizedRejected(t *testing.T) {
	orig := maxArMemberBytes
	maxArMemberBytes = 1024
	defer func() { maxArMemberBytes = orig }()

	// Declare size 1<<20 (> 1024 cap) but supply no body — must reject on the
	// size check before any io.ReadFull/allocation.
	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8s%-10d%s",
		"big/", 0, 0, 0, "100644", 1<<20, arEntryMagic)
	r := bytes.NewReader([]byte(hdr))

	_, err := readArEntry(r)
	if err == nil {
		t.Fatal("expected error for oversized ar member, got nil")
	}
}

// TestParseControlArchive_ControlBomb verifies that a control member that
// decompresses beyond maxControlBytes does not get fully materialized.
func TestParseControlArchive_ControlBomb(t *testing.T) {
	orig := maxControlBytes
	maxControlBytes = 1024
	defer func() { maxControlBytes = orig }()

	// control file far larger than the 1 KiB cap.
	big := strings.Repeat("A", 64*1024)
	data := buildTarGz(t, []tarEntry{
		{name: "control", typeflag: tar.TypeReg, content: big},
	})

	ctrl, _, err := parseControlArchive(data, "control.tar.gz")
	if err != nil {
		t.Fatalf("parseControlArchive returned error: %v", err)
	}
	// On overflow the control read is skipped (treated as malformed), so ctrl
	// must be nil — the giant control was NOT parsed.
	if ctrl != nil {
		t.Fatalf("expected control to be skipped on overflow, got %+v", ctrl)
	}
}

// TestExtractTar_AggregateByteCap verifies that extractTar hard-stops once the
// aggregate written-byte budget is exceeded, instead of writing unbounded data.
func TestExtractTar_AggregateByteCap(t *testing.T) {
	orig := maxDebTotalBytes
	maxDebTotalBytes = 4096
	defer func() { maxDebTotalBytes = orig }()

	// Three 4 KiB files; the first puts us at the 4 KiB cap, the second trips it.
	chunk := strings.Repeat("Z", 4096)
	data := buildTarGz(t, []tarEntry{
		{name: "a.bin", typeflag: tar.TypeReg, content: chunk},
		{name: "b.bin", typeflag: tar.TypeReg, content: chunk},
		{name: "c.bin", typeflag: tar.TypeReg, content: chunk},
	})

	dest := t.TempDir()
	files, _, _, errs := extractTar(data, "data.tar.gz", dest)

	if len(errs) == 0 {
		t.Fatal("expected an aggregate-limit error, got none")
	}
	foundLimit := false
	for _, e := range errs {
		if strings.Contains(e, "aggregate extraction limit") {
			foundLimit = true
		}
	}
	if !foundLimit {
		t.Fatalf("expected aggregate extraction limit error, got %v", errs)
	}
	if files >= 3 {
		t.Fatalf("expected extraction to stop early, but wrote %d files", files)
	}
}

// TestExtractTar_EntryCountCap verifies that extractTar hard-stops once the
// entry-count budget is exceeded (inode/header-flood guard).
func TestExtractTar_EntryCountCap(t *testing.T) {
	orig := maxDebEntries
	maxDebEntries = 5
	defer func() { maxDebEntries = orig }()

	entries := make([]tarEntry, 0, 20)
	for i := 0; i < 20; i++ {
		entries = append(entries, tarEntry{
			name:     fmt.Sprintf("d%d", i),
			typeflag: tar.TypeDir,
		})
	}
	data := buildTarGz(t, entries)

	dest := t.TempDir()
	_, dirs, _, errs := extractTar(data, "data.tar.gz", dest)

	if len(errs) == 0 {
		t.Fatal("expected an entry-count limit error, got none")
	}
	if int64(dirs) > maxDebEntries {
		t.Fatalf("expected at most %d dirs before stop, got %d", maxDebEntries, dirs)
	}
}
