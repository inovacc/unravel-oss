package archive

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// createTestZIP writes a ZIP archive to a temp file containing the given entries
// (map of path -> content). Returns the file path and a cleanup function.
func createTestZIP(t *testing.T, name string, entries map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp zip: %v", err)
	}

	w := zip.NewWriter(f)

	for entryName, content := range entries {
		fw, err := w.Create(entryName)
		if err != nil {
			_ = w.Close()
			_ = f.Close()
			t.Fatalf("create zip entry %q: %v", entryName, err)
		}

		if _, err := fw.Write([]byte(content)); err != nil {
			_ = w.Close()
			_ = f.Close()
			t.Fatalf("write zip entry %q: %v", entryName, err)
		}
	}

	if err := w.Close(); err != nil {
		_ = f.Close()
		t.Fatalf("close zip writer: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	return path
}

// ---------------------------------------------------------------------------
// Test: DetectType — JAR
// ---------------------------------------------------------------------------

func TestDetectType_JAR(t *testing.T) {
	path := createTestZIP(t, "sample.jar", map[string]string{
		"META-INF/MANIFEST.MF":   "Manifest-Version: 1.0\nMain-Class: com.example.Main\n",
		"com/example/Main.class": "fake class data",
	})

	got := DetectType(path)
	if got != ArchiveJAR {
		t.Errorf("DetectType(%q) = %v, want ArchiveJAR", path, got)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectType — WAR (by extension)
// ---------------------------------------------------------------------------

func TestDetectType_WAR_ByExtension(t *testing.T) {
	path := createTestZIP(t, "webapp.war", map[string]string{
		"WEB-INF/web.xml": "<web-app/>",
		"index.html":      "<html/>",
	})

	got := DetectType(path)
	if got != ArchiveWAR {
		t.Errorf("DetectType(%q) = %v, want ArchiveWAR", path, got)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectType — WAR (JAR extension but WEB-INF inside)
// ---------------------------------------------------------------------------

func TestDetectType_WAR_InsideJAR(t *testing.T) {
	path := createTestZIP(t, "webapp.jar", map[string]string{
		"WEB-INF/web.xml":         "<web-app/>",
		"WEB-INF/classes/A.class": "fake",
	})

	got := DetectType(path)
	if got != ArchiveWAR {
		t.Errorf("DetectType(%q) = %v, want ArchiveWAR (detected by WEB-INF content)", path, got)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectType — EAR (by extension)
// ---------------------------------------------------------------------------

func TestDetectType_EAR_ByExtension(t *testing.T) {
	path := createTestZIP(t, "enterprise.ear", map[string]string{
		"META-INF/application.xml": "<application/>",
		"lib/common.jar":           "fake jar",
	})

	got := DetectType(path)
	if got != ArchiveEAR {
		t.Errorf("DetectType(%q) = %v, want ArchiveEAR", path, got)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectType — EAR (JAR extension but application.xml inside)
// ---------------------------------------------------------------------------

func TestDetectType_EAR_InsideJAR(t *testing.T) {
	path := createTestZIP(t, "enterprise.jar", map[string]string{
		"META-INF/application.xml": "<application/>",
	})

	got := DetectType(path)
	if got != ArchiveEAR {
		t.Errorf("DetectType(%q) = %v, want ArchiveEAR (detected by application.xml)", path, got)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectType — Unknown extension
// ---------------------------------------------------------------------------

func TestDetectType_UnknownExtension(t *testing.T) {
	path := createTestZIP(t, "data.zip", map[string]string{
		"random.txt": "hello",
	})

	got := DetectType(path)
	if got != ArchiveUnknown {
		t.Errorf("DetectType(%q) = %v, want ArchiveUnknown", path, got)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectType — non-existent file
// ---------------------------------------------------------------------------

func TestDetectType_NonExistent(t *testing.T) {
	got := DetectType("/nonexistent/file.jar")
	if got != ArchiveUnknown {
		t.Errorf("DetectType(nonexistent) = %v, want ArchiveUnknown", got)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectType — non-ZIP file with .jar extension
// ---------------------------------------------------------------------------

func TestDetectType_NonZIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.jar")

	if err := os.WriteFile(path, []byte("this is not a zip file"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := DetectType(path)
	if got != ArchiveUnknown {
		t.Errorf("DetectType(non-zip .jar) = %v, want ArchiveUnknown", got)
	}
}

// ---------------------------------------------------------------------------
// Test: IsArchive
// ---------------------------------------------------------------------------

func TestIsArchive(t *testing.T) {
	t.Run("valid JAR", func(t *testing.T) {
		path := createTestZIP(t, "test.jar", map[string]string{
			"A.class": "fake",
		})

		if !IsArchive(path) {
			t.Error("expected IsArchive=true for .jar")
		}
	})

	t.Run("valid WAR", func(t *testing.T) {
		path := createTestZIP(t, "test.war", map[string]string{
			"WEB-INF/web.xml": "<web-app/>",
		})

		if !IsArchive(path) {
			t.Error("expected IsArchive=true for .war")
		}
	})

	t.Run("wrong extension", func(t *testing.T) {
		path := createTestZIP(t, "test.zip", map[string]string{
			"A.class": "fake",
		})

		if IsArchive(path) {
			t.Error("expected IsArchive=false for .zip")
		}
	})

	t.Run("non-existent", func(t *testing.T) {
		if IsArchive("/no/such/file.jar") {
			t.Error("expected IsArchive=false for non-existent file")
		}
	})
}

// ---------------------------------------------------------------------------
// Test: ArchiveType.String()
// ---------------------------------------------------------------------------

func TestArchiveTypeString(t *testing.T) {
	tests := []struct {
		at   ArchiveType
		want string
	}{
		{ArchiveJAR, "JAR"},
		{ArchiveWAR, "WAR"},
		{ArchiveEAR, "EAR"},
		{ArchiveUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.at.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: ParseManifest — basic
// ---------------------------------------------------------------------------

func TestParseManifest_Basic(t *testing.T) {
	data := []byte("Manifest-Version: 1.0\nMain-Class: com.example.Main\n\n")

	info, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest error: %v", err)
	}

	if info.MainClass != "com.example.Main" {
		t.Errorf("MainClass = %q, want %q", info.MainClass, "com.example.Main")
	}

	if v, ok := info.Entries["Manifest-Version"]; !ok || v != "1.0" {
		t.Errorf("Manifest-Version entry = %q, want %q", v, "1.0")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseManifest — Class-Path
// ---------------------------------------------------------------------------

func TestParseManifest_ClassPath(t *testing.T) {
	data := []byte("Manifest-Version: 1.0\nClass-Path: lib/a.jar lib/b.jar\n")

	info, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest error: %v", err)
	}

	if len(info.ClassPath) != 2 {
		t.Fatalf("ClassPath length = %d, want 2", len(info.ClassPath))
	}

	if info.ClassPath[0] != "lib/a.jar" || info.ClassPath[1] != "lib/b.jar" {
		t.Errorf("ClassPath = %v, want [lib/a.jar lib/b.jar]", info.ClassPath)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseManifest — continuation lines
// ---------------------------------------------------------------------------

func TestParseManifest_ContinuationLines(t *testing.T) {
	// In MANIFEST.MF, lines starting with a single space are continuations.
	data := []byte("Main-Class: com.example.very.long.packa\n ge.name.Main\n")

	info, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest error: %v", err)
	}

	if info.MainClass != "com.example.very.long.package.name.Main" {
		t.Errorf("MainClass = %q, want %q", info.MainClass, "com.example.very.long.package.name.Main")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseManifest — Implementation-Version and Title
// ---------------------------------------------------------------------------

func TestParseManifest_ImplementationFields(t *testing.T) {
	data := []byte("Implementation-Title: MyApp\nImplementation-Version: 2.0.1\n")

	info, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest error: %v", err)
	}

	if info.ImplementationTitle != "MyApp" {
		t.Errorf("ImplementationTitle = %q, want %q", info.ImplementationTitle, "MyApp")
	}

	if info.ImplementationVersion != "2.0.1" {
		t.Errorf("ImplementationVersion = %q, want %q", info.ImplementationVersion, "2.0.1")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseManifest — empty input
// ---------------------------------------------------------------------------

func TestParseManifest_Empty(t *testing.T) {
	info, err := ParseManifest([]byte{})
	if err != nil {
		t.Fatalf("ParseManifest error: %v", err)
	}

	if info.MainClass != "" {
		t.Errorf("expected empty MainClass, got %q", info.MainClass)
	}

	if len(info.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(info.Entries))
	}
}
