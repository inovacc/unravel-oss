package archive

import (
	"archive/zip"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// createTestJAR creates a minimal JAR file with a MANIFEST.MF and a .java file.
func createTestJAR(t *testing.T, dir string) string {
	t.Helper()

	jarPath := filepath.Join(dir, "test.jar")

	f, err := os.Create(jarPath)
	if err != nil {
		t.Fatalf("create jar: %v", err)
	}

	w := zip.NewWriter(f)

	// MANIFEST.MF
	mf, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("create manifest entry: %v", err)
	}

	_, _ = mf.Write([]byte("Manifest-Version: 1.0\nMain-Class: com.example.Main\n"))

	// A .java file
	jf, err := w.Create("com/example/Main.java")
	if err != nil {
		t.Fatalf("create java entry: %v", err)
	}

	_, _ = jf.Write([]byte(`package com.example;
public class Main {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
`))

	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	return jarPath
}

// createTestWAR creates a minimal WAR file with web.xml and a servlet.
func createTestWAR(t *testing.T, dir string) string {
	t.Helper()

	warPath := filepath.Join(dir, "test.war")

	f, err := os.Create(warPath)
	if err != nil {
		t.Fatalf("create war: %v", err)
	}

	w := zip.NewWriter(f)

	// MANIFEST.MF
	mf, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("create manifest entry: %v", err)
	}

	_, _ = mf.Write([]byte("Manifest-Version: 1.0\n"))

	// web.xml
	wx, err := w.Create("WEB-INF/web.xml")
	if err != nil {
		t.Fatalf("create web.xml entry: %v", err)
	}

	_, _ = wx.Write([]byte(`<?xml version="1.0"?>
<web-app>
    <servlet>
        <servlet-name>Hello</servlet-name>
        <servlet-class>com.example.HelloServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>Hello</servlet-name>
        <url-pattern>/hello</url-pattern>
    </servlet-mapping>
</web-app>
`))

	// A .java file in WEB-INF/classes
	jf, err := w.Create("WEB-INF/classes/com/example/HelloServlet.java")
	if err != nil {
		t.Fatalf("create java entry: %v", err)
	}

	_, _ = jf.Write([]byte(`package com.example;
import javax.servlet.http.HttpServlet;
public class HelloServlet extends HttpServlet {
    protected void doGet(javax.servlet.http.HttpServletRequest req,
                         javax.servlet.http.HttpServletResponse resp) {
        resp.getWriter().println("Hello");
    }
}
`))

	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	return warPath
}

// createTestEAR creates a minimal EAR file with application.xml.
func createTestEAR(t *testing.T, dir string) string {
	t.Helper()

	earPath := filepath.Join(dir, "test.ear")

	f, err := os.Create(earPath)
	if err != nil {
		t.Fatalf("create ear: %v", err)
	}

	w := zip.NewWriter(f)

	// MANIFEST.MF
	mf, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("create manifest entry: %v", err)
	}

	_, _ = mf.Write([]byte("Manifest-Version: 1.0\n"))

	// application.xml
	ax, err := w.Create("META-INF/application.xml")
	if err != nil {
		t.Fatalf("create app.xml entry: %v", err)
	}

	_, _ = ax.Write([]byte(`<?xml version="1.0"?>
<application>
    <module>
        <web>
            <web-uri>webapp.war</web-uri>
            <context-root>/app</context-root>
        </web>
    </module>
    <module>
        <ejb>ejb-module.jar</ejb>
    </module>
</application>
`))

	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	return earPath
}

func TestIsArchive(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"JAR file", createTestJAR(t, dir), true},
		{"WAR file", createTestWAR(t, dir), true},
		{"EAR file", createTestEAR(t, dir), true},
		{"non-archive", filepath.Join(dir, "test.txt"), false},
		{"nonexistent", filepath.Join(dir, "missing.jar"), false},
	}

	// Create a non-archive text file
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("create text file: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsArchive(tt.path)
			if got != tt.want {
				t.Errorf("IsArchive(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectType(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
		want ArchiveType
	}{
		{"JAR", createTestJAR(t, dir), ArchiveJAR},
		{"WAR", createTestWAR(t, dir), ArchiveWAR},
		{"EAR", createTestEAR(t, dir), ArchiveEAR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectType(tt.path)
			if got != tt.want {
				t.Errorf("DetectType(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractJAR(t *testing.T) {
	dir := t.TempDir()
	jarPath := createTestJAR(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ext := New(logger)

	info, err := ext.Extract(context.Background(), jarPath)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	defer func() { _ = info.Cleanup() }()

	if info.Type != ArchiveJAR {
		t.Errorf("Type = %v, want %v", info.Type, ArchiveJAR)
	}

	if len(info.JavaFiles) == 0 {
		t.Error("expected at least one Java file")
	}

	if info.Manifest == nil {
		t.Error("expected manifest to be parsed")
	} else if info.Manifest.MainClass != "com.example.Main" {
		t.Errorf("MainClass = %q, want %q", info.Manifest.MainClass, "com.example.Main")
	}
}

func TestExtractWAR(t *testing.T) {
	dir := t.TempDir()
	warPath := createTestWAR(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ext := New(logger)

	info, err := ext.Extract(context.Background(), warPath)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	defer func() { _ = info.Cleanup() }()

	if info.Type != ArchiveWAR {
		t.Errorf("Type = %v, want %v", info.Type, ArchiveWAR)
	}

	if info.WebXML == nil {
		t.Error("expected web.xml to be parsed")
	} else {
		if len(info.WebXML.Servlets) != 1 {
			t.Errorf("Servlets count = %d, want 1", len(info.WebXML.Servlets))
		}
	}

	if len(info.JavaFiles) == 0 {
		t.Error("expected at least one Java file")
	}
}

func TestExtractEAR(t *testing.T) {
	dir := t.TempDir()
	earPath := createTestEAR(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ext := New(logger)

	info, err := ext.Extract(context.Background(), earPath)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	defer func() { _ = info.Cleanup() }()

	if info.Type != ArchiveEAR {
		t.Errorf("Type = %v, want %v", info.Type, ArchiveEAR)
	}

	if info.AppXML == nil {
		t.Error("expected application.xml to be parsed")
	} else {
		if len(info.AppXML.Modules) != 2 {
			t.Errorf("Modules count = %d, want 2", len(info.AppXML.Modules))
		}
	}
}

func TestCleanup(t *testing.T) {
	dir := t.TempDir()
	jarPath := createTestJAR(t, dir)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ext := New(logger)

	info, err := ext.Extract(context.Background(), jarPath)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	extractDir := info.ExtractDir

	// Verify dir exists
	if _, err := os.Stat(extractDir); os.IsNotExist(err) {
		t.Fatal("extract dir should exist before cleanup")
	}

	if err := info.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}

	// Verify dir is removed
	if _, err := os.Stat(extractDir); !os.IsNotExist(err) {
		t.Error("extract dir should be removed after cleanup")
	}
}

func TestArchiveTypeString(t *testing.T) {
	tests := []struct {
		t    ArchiveType
		want string
	}{
		{ArchiveJAR, "JAR"},
		{ArchiveWAR, "WAR"},
		{ArchiveEAR, "EAR"},
		{ArchiveUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.t.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
