package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCategorizer_DefaultPatterns(t *testing.T) {
	files := []*SourceFile{
		{RelPath: "HttpRequest.cpp"},
		{RelPath: "HttpResponse.cpp"},
		{RelPath: "FtpClient.cpp"},
		{RelPath: "BtPeerMessage.cpp"},
		{RelPath: "DHTBucket.cpp"},
		{RelPath: "utils.cpp"},
		{RelPath: "main.cpp"},
	}

	cat := NewCategorizer(nil) // use defaults
	subsystems := cat.Categorize(files)

	subsystemMap := make(map[string]*Subsystem)
	for _, s := range subsystems {
		subsystemMap[s.Name] = s
	}

	// HTTP should have 2 files
	if http, ok := subsystemMap["HTTP"]; !ok {
		t.Error("HTTP subsystem not found")
	} else if len(http.Files) != 2 {
		t.Errorf("HTTP files = %d, want 2", len(http.Files))
	}

	// FTP should have 1 file
	if ftp, ok := subsystemMap["FTP"]; !ok {
		t.Error("FTP subsystem not found")
	} else if len(ftp.Files) != 1 {
		t.Errorf("FTP files = %d, want 1", len(ftp.Files))
	}

	// BitTorrent should have 1 file (BtPeerMessage matches "Bt" and "Peer")
	if bt, ok := subsystemMap["BitTorrent"]; !ok {
		t.Error("BitTorrent subsystem not found")
	} else if len(bt.Files) < 1 {
		t.Errorf("BitTorrent files = %d, want >= 1", len(bt.Files))
	}

	// DHT should have 1 file
	if dht, ok := subsystemMap["DHT"]; !ok {
		t.Error("DHT subsystem not found")
	} else if len(dht.Files) != 1 {
		t.Errorf("DHT files = %d, want 1", len(dht.Files))
	}

	// Uncategorized should have utils.cpp and main.cpp
	if uncat, ok := subsystemMap["Uncategorized"]; !ok {
		t.Error("Uncategorized subsystem not found")
	} else if len(uncat.Files) != 2 {
		t.Errorf("Uncategorized files = %d, want 2", len(uncat.Files))
	}
}

func TestCategorizer_CustomPatterns(t *testing.T) {
	files := []*SourceFile{
		{RelPath: "AudioPlayer.cpp"},
		{RelPath: "VideoDecoder.cpp"},
		{RelPath: "main.cpp"},
	}

	defs := []*SubsystemDef{
		{Name: "Audio", Patterns: []string{"Audio"}},
		{Name: "Video", Patterns: []string{"Video"}},
	}

	cat := NewCategorizer(defs)
	subsystems := cat.Categorize(files)

	if len(subsystems) != 3 { // Audio, Video, Uncategorized
		t.Errorf("got %d subsystems, want 3", len(subsystems))
	}
}

func TestCategorizer_NoUncategorized(t *testing.T) {
	files := []*SourceFile{
		{RelPath: "HttpClient.cpp"},
	}

	cat := NewCategorizer(nil)
	subsystems := cat.Categorize(files)

	for _, s := range subsystems {
		if s.Name == "Uncategorized" {
			t.Error("should not have Uncategorized when all files match")
		}
	}
}

func TestDetectLibraries(t *testing.T) {
	dir := t.TempDir()

	// Create files with various includes
	writeTestFile(t, dir, "stl.cpp", `#include <vector>
#include <map>
#include <string>
int main() {}`)

	writeTestFile(t, dir, "boost.cpp", `#include <boost/asio.hpp>
void run() {}`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "stl.cpp"), RelPath: "stl.cpp"},
		{Path: filepath.Join(dir, "boost.cpp"), RelPath: "boost.cpp"},
	}

	libs := DetectLibraries(files)

	// Should detect at least "stl" and "asio"
	libSet := make(map[string]bool)
	for _, lib := range libs {
		libSet[lib] = true
	}

	if !libSet["stl"] {
		t.Error("expected 'stl' library to be detected")
	}

	if !libSet["asio"] {
		t.Error("expected 'asio' library to be detected")
	}
}

func TestSortStrings(t *testing.T) {
	s := []string{"cherry", "apple", "banana"}
	sortStrings(s)

	if s[0] != "apple" || s[1] != "banana" || s[2] != "cherry" {
		t.Errorf("sortStrings() = %v", s)
	}
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
