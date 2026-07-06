/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"bytes"
	"strings"
	"testing"

	javabeautify "github.com/inovacc/unravel-oss/pkg/java/beautify"
)

// ── PrintJavaBeautifyReport ───────────────────────────────────────────────────

func TestPrintJavaBeautifyReport_NilReport(t *testing.T) {
	var buf bytes.Buffer
	PrintJavaBeautifyReport(nil, &buf)
	out := buf.String()
	if !strings.Contains(out, "nil report") {
		t.Errorf("expected 'nil report', got: %q", out)
	}
}

func TestPrintJavaBeautifyReport_Variants(t *testing.T) {
	tests := []struct {
		name   string
		report *javabeautify.BeautifyReport
		checks []string
	}{
		{
			name: "empty report",
			report: &javabeautify.BeautifyReport{
				RunID:     "run-001",
				OutputDir: "/out",
				RawTree:   "/raw",
			},
			checks: []string{"JAVA BEAUTIFY", "run-001", "/out", "/raw", "JARs:           0"},
		},
		{
			name: "with beautified tree and jars",
			report: &javabeautify.BeautifyReport{
				RunID:          "run-002",
				OutputDir:      "/out2",
				RawTree:        "/raw2",
				BeautifiedTree: "/beautiful",
				Jars: []javabeautify.JarManifestEntry{
					{Name: "app.jar", Beautified: true, FileCount: 10},
					{Name: "lib.jar", Beautified: false, FileCount: 5},
				},
				Errors: []string{"failed to parse Foo.java"},
			},
			checks: []string{
				"run-002",
				"/beautiful",
				"JARs:           2 (beautified: 1)",
				"Files:          15 total",
				"Errors:         1",
				"failed to parse Foo.java",
			},
		},
		{
			name: "long paths truncated",
			report: &javabeautify.BeautifyReport{
				RunID:     "run-003",
				OutputDir: strings.Repeat("a", 200),
				RawTree:   "/r",
			},
			checks: []string{"run-003", "..."},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			PrintJavaBeautifyReport(tc.report, &buf)
			out := buf.String()
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}

// ── PrintJavaClassInfo ────────────────────────────────────────────────────────

func TestPrintJavaClassInfo(t *testing.T) {
	tests := []struct {
		name   string
		info   *JavaClassDisplay
		checks []string
	}{
		{
			name: "minimal class",
			info: &JavaClassDisplay{
				ClassName:        "com.example.Foo",
				ConstantPoolSize: 42,
			},
			checks: []string{"com.example.Foo", "JAVA CLASS", "42"},
		},
		{
			name: "full class with interfaces",
			info: &JavaClassDisplay{
				ClassName:        "com.example.Bar",
				JavaVersion:      "Java 11",
				AccessFlags:      "public final",
				SuperClass:       "java.lang.Object",
				SourceFile:       "Bar.java",
				ConstantPoolSize: 100,
				FieldCount:       5,
				MethodCount:      12,
				Interfaces:       []string{"java.io.Serializable", "java.lang.Runnable"},
			},
			checks: []string{
				"com.example.Bar",
				"Java 11",
				"public final",
				"java.lang.Object",
				"Bar.java",
				"100",
				"5",
				"12",
				"java.io.Serializable",
				"java.lang.Runnable",
				"INTERFACES (2)",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				PrintJavaClassInfo(tc.info)
			})
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}

// ── PrintJavaArchiveInfo ──────────────────────────────────────────────────────

func TestPrintJavaArchiveInfo(t *testing.T) {
	tests := []struct {
		name   string
		info   *JavaArchiveDisplay
		checks []string
	}{
		{
			name: "simple JAR",
			info: &JavaArchiveDisplay{
				Type:       "JAR",
				Path:       "/path/to/app.jar",
				ClassCount: 20,
			},
			checks: []string{"JAR ARCHIVE", "/path/to/app.jar", "20"},
		},
		{
			name: "WAR with nested JARs and dependencies",
			info: &JavaArchiveDisplay{
				Type:              "WAR",
				Path:              "/app.war",
				ClassCount:        50,
				JavaCount:         10,
				NestedJARs:        []string{"WEB-INF/lib/dep.jar", "WEB-INF/lib/util.jar"},
				ManifestMainClass: "com.example.Main",
				ManifestVersion:   "1.0",
				SpringBoot:        true,
				HasWebXML:         true,
				HasPOM:            true,
				Dependencies:      []string{"org.springframework:spring-core:5.3"},
			},
			checks: []string{
				"WAR ARCHIVE",
				"/app.war",
				"com.example.Main",
				"Yes", // SpringBoot, HasWebXML
				"NESTED JARS (2)",
				"dep.jar",
				"DEPENDENCIES (1)",
				"spring-core",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				PrintJavaArchiveInfo(tc.info)
			})
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}

// ── PrintJavaDecompileSummary ─────────────────────────────────────────────────

func TestPrintJavaDecompileSummary(t *testing.T) {
	tests := []struct {
		name    string
		summary *JavaDecompileSummary
		checks  []string
	}{
		{
			name: "all decompiled",
			summary: &JavaDecompileSummary{
				TotalClasses: 10,
				Decompiled:   10,
				Errors:       0,
				OutputDir:    "/out",
			},
			// Format is %-*.1f%% so the number is left-padded then % at end of row
			checks: []string{"10", "0", "/out", "100.0"},
		},
		{
			name: "partial with errors",
			summary: &JavaDecompileSummary{
				TotalClasses: 20,
				Decompiled:   15,
				Errors:       5,
				OutputDir:    "/out2",
				ErrorDetails: []string{"ClassName: bad class file", "AnotherClass: unsupported"},
			},
			checks: []string{"15", "5", "ERRORS (2)", "bad class file", "unsupported", "75.0"},
		},
		{
			name: "zero classes (no percent line)",
			summary: &JavaDecompileSummary{
				TotalClasses: 0,
				Decompiled:   0,
				Errors:       0,
				OutputDir:    "/none",
			},
			checks: []string{"/none"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				PrintJavaDecompileSummary(tc.summary)
			})
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}

// ── PrintJavaManifest ─────────────────────────────────────────────────────────

func TestPrintJavaManifest(t *testing.T) {
	tests := []struct {
		name   string
		info   *JavaManifestDisplay
		checks []string
	}{
		{
			name: "manifest with all sections",
			info: &JavaManifestDisplay{
				MainClass:       "com.example.App",
				ClassPath:       "lib/dep.jar",
				ManifestVersion: "1.0",
				Entries: map[string]string{
					"Built-By":   "ci",
					"Created-By": "Maven",
				},
				WebXML: &WebXMLDisplay{
					DisplayName: "MyApp",
					Servlets:    []string{"FooServlet"},
					Filters:     []string{"LogFilter"},
					Listeners:   []string{"AppListener"},
				},
				AppXML: &AppXMLDisplay{
					DisplayName: "Enterprise App",
					Modules:     []string{"ejb-module.jar"},
				},
				POM: &POMDisplay{
					GroupID:      "com.example",
					ArtifactID:   "myapp",
					Version:      "1.0.0",
					Dependencies: []string{"org.slf4j:slf4j-api:1.7"},
				},
			},
			checks: []string{
				"com.example.App",
				"lib/dep.jar",
				"1.0",
				"Built-By",
				"Maven",
				"MyApp",
				"FooServlet",
				"LogFilter",
				"AppListener",
				"Enterprise App",
				"ejb-module.jar",
				"com.example",
				"myapp",
				"1.0.0",
				"slf4j-api",
			},
		},
		{
			name: "minimal manifest",
			info: &JavaManifestDisplay{
				ManifestVersion: "1.0",
			},
			checks: []string{"MANIFEST.MF", "1.0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				PrintJavaManifest(tc.info)
			})
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}
