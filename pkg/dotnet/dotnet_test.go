package dotnet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseDeps
// ---------------------------------------------------------------------------

func TestParseDeps(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantErr     bool
		errContains string
		check       func(t *testing.T, r *DepsResult)
	}{
		{
			name: "basic deps with runtime target and libraries",
			json: `{
				"runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/win-x64"},
				"libraries": {
					"MyApp/1.0.0": {"type": "project", "serviceable": false},
					"Newtonsoft.Json/13.0.3": {"type": "package", "serviceable": true, "sha512": "abc"}
				},
				"targets": {
					".NETCoreApp,Version=v8.0/win-x64": {
						"MyApp/1.0.0": {"dependencies": {"Newtonsoft.Json": "13.0.3"}},
						"Newtonsoft.Json/13.0.3": {"runtime": {"lib/net8.0/Newtonsoft.Json.dll": {}}}
					}
				}
			}`,
			check: func(t *testing.T, r *DepsResult) {
				if r.TargetFramework != ".NETCoreApp,Version=v8.0" {
					t.Errorf("TargetFramework = %q, want .NETCoreApp,Version=v8.0", r.TargetFramework)
				}
				if r.RuntimeID != "win-x64" {
					t.Errorf("RuntimeID = %q, want win-x64", r.RuntimeID)
				}
				if r.TotalLibraries != 2 {
					t.Errorf("TotalLibraries = %d, want 2", r.TotalLibraries)
				}
				if len(r.ProjectLibs) != 1 {
					t.Fatalf("ProjectLibs len = %d, want 1", len(r.ProjectLibs))
				}
				if r.ProjectLibs[0].Name != "MyApp" {
					t.Errorf("ProjectLibs[0].Name = %q, want MyApp", r.ProjectLibs[0].Name)
				}
				if len(r.PackageLibs) != 1 {
					t.Fatalf("PackageLibs len = %d, want 1", len(r.PackageLibs))
				}
				if r.PackageLibs[0].Name != "Newtonsoft.Json" {
					t.Errorf("PackageLibs[0].Name = %q, want Newtonsoft.Json", r.PackageLibs[0].Name)
				}
				// MyApp should have dependency on Newtonsoft.Json
				if len(r.ProjectLibs[0].Deps) != 1 || r.ProjectLibs[0].Deps[0] != "Newtonsoft.Json" {
					t.Errorf("ProjectLibs[0].Deps = %v, want [Newtonsoft.Json]", r.ProjectLibs[0].Deps)
				}
			},
		},
		{
			name: "runtime target without runtime ID",
			json: `{
				"runtimeTarget": {"name": ".NETCoreApp,Version=v6.0"},
				"libraries": {},
				"targets": {}
			}`,
			check: func(t *testing.T, r *DepsResult) {
				if r.TargetFramework != ".NETCoreApp,Version=v6.0" {
					t.Errorf("TargetFramework = %q", r.TargetFramework)
				}
				if r.RuntimeID != "" {
					t.Errorf("RuntimeID = %q, want empty", r.RuntimeID)
				}
			},
		},
		{
			name: "detects IPC mechanisms",
			json: `{
				"runtimeTarget": {"name": "net8.0"},
				"libraries": {
					"Grpc.Net.Client/2.60.0": {"type": "package"},
					"RabbitMQ.Client/6.8.1": {"type": "package"},
					"Microsoft.AspNetCore.SignalR/1.0.0": {"type": "package"}
				},
				"targets": {}
			}`,
			check: func(t *testing.T, r *DepsResult) {
				ipcSet := make(map[string]bool)
				for _, m := range r.IPCMechanisms {
					ipcSet[m] = true
				}
				for _, want := range []string{"gRPC", "RabbitMQ", "SignalR"} {
					if !ipcSet[want] {
						t.Errorf("missing IPC mechanism %q in %v", want, r.IPCMechanisms)
					}
				}
			},
		},
		{
			name: "detects frameworks",
			json: `{
				"runtimeTarget": {"name": "net8.0"},
				"libraries": {
					"Serilog/3.1.1": {"type": "package"},
					"Microsoft.EntityFrameworkCore/8.0.0": {"type": "package"},
					"Avalonia/11.0.0": {"type": "package"}
				},
				"targets": {}
			}`,
			check: func(t *testing.T, r *DepsResult) {
				fwSet := make(map[string]bool)
				for _, fw := range r.Frameworks {
					fwSet[fw] = true
				}
				for _, want := range []string{"Serilog", "Entity Framework Core", "Avalonia"} {
					if !fwSet[want] {
						t.Errorf("missing framework %q in %v", want, r.Frameworks)
					}
				}
			},
		},
		{
			name: "empty libraries and targets",
			json: `{
				"runtimeTarget": {"name": "net8.0"},
				"libraries": {},
				"targets": {}
			}`,
			check: func(t *testing.T, r *DepsResult) {
				if r.TotalLibraries != 0 {
					t.Errorf("TotalLibraries = %d, want 0", r.TotalLibraries)
				}
				if len(r.ProjectLibs) != 0 || len(r.PackageLibs) != 0 {
					t.Errorf("expected no libs")
				}
			},
		},
		{
			name:        "malformed JSON",
			json:        `{invalid json`,
			wantErr:     true,
			errContains: "parse deps.json",
		},
		{
			name:        "file not found",
			json:        "",
			wantErr:     true,
			errContains: "read deps.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.name == "file not found" {
				path = filepath.Join(t.TempDir(), "nonexistent.deps.json")
			} else {
				path = filepath.Join(t.TempDir(), "app.deps.json")
				if err := os.WriteFile(path, []byte(tt.json), 0644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}

			result, err := ParseDeps(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseRuntimeConfig
// ---------------------------------------------------------------------------

func TestParseRuntimeConfig(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantErr     bool
		errContains string
		check       func(t *testing.T, r *RuntimeConfigResult)
	}{
		{
			name: "singular framework (ASP.NET)",
			json: `{
				"runtimeOptions": {
					"tfm": "net8.0",
					"framework": {
						"name": "Microsoft.AspNetCore.App",
						"version": "8.0.0"
					},
					"configProperties": {
						"System.GC.Server": true
					}
				}
			}`,
			check: func(t *testing.T, r *RuntimeConfigResult) {
				if r.TFM != "net8.0" {
					t.Errorf("TFM = %q, want net8.0", r.TFM)
				}
				if !r.IsASPNET {
					t.Error("IsASPNET should be true")
				}
				if r.IsDesktop {
					t.Error("IsDesktop should be false")
				}
				if len(r.Frameworks) != 1 {
					t.Fatalf("Frameworks len = %d, want 1", len(r.Frameworks))
				}
				if r.Frameworks[0].Name != "Microsoft.AspNetCore.App" {
					t.Errorf("Framework name = %q", r.Frameworks[0].Name)
				}
				if r.Properties == nil {
					t.Fatal("Properties should not be nil")
				}
			},
		},
		{
			name: "plural frameworks (Desktop)",
			json: `{
				"runtimeOptions": {
					"tfm": "net8.0-windows",
					"frameworks": [
						{"name": "Microsoft.NETCore.App", "version": "8.0.0"},
						{"name": "Microsoft.WindowsDesktop.App", "version": "8.0.0"}
					]
				}
			}`,
			check: func(t *testing.T, r *RuntimeConfigResult) {
				if !r.IsDesktop {
					t.Error("IsDesktop should be true")
				}
				if r.IsASPNET {
					t.Error("IsASPNET should be false")
				}
				if len(r.Frameworks) != 2 {
					t.Errorf("Frameworks len = %d, want 2", len(r.Frameworks))
				}
			},
		},
		{
			name: "no frameworks",
			json: `{
				"runtimeOptions": {
					"tfm": "net6.0"
				}
			}`,
			check: func(t *testing.T, r *RuntimeConfigResult) {
				if len(r.Frameworks) != 0 {
					t.Errorf("Frameworks len = %d, want 0", len(r.Frameworks))
				}
				if r.IsASPNET || r.IsDesktop {
					t.Error("should be neither ASP.NET nor Desktop")
				}
			},
		},
		{
			name:        "malformed JSON",
			json:        `not json at all`,
			wantErr:     true,
			errContains: "parse runtimeconfig.json",
		},
		{
			name:        "file not found",
			json:        "",
			wantErr:     true,
			errContains: "read runtimeconfig.json",
		},
		{
			name: "empty runtimeOptions",
			json: `{"runtimeOptions": {}}`,
			check: func(t *testing.T, r *RuntimeConfigResult) {
				if r.TFM != "" {
					t.Errorf("TFM = %q, want empty", r.TFM)
				}
				if len(r.Frameworks) != 0 {
					t.Errorf("Frameworks should be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.name == "file not found" {
				path = filepath.Join(t.TempDir(), "nonexistent.runtimeconfig.json")
			} else {
				path = filepath.Join(t.TempDir(), "app.runtimeconfig.json")
				if err := os.WriteFile(path, []byte(tt.json), 0644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			}

			result, err := ParseRuntimeConfig(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err, tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IsDotNetApp
// ---------------------------------------------------------------------------

func TestIsDotNetApp(t *testing.T) {
	tests := []struct {
		name  string
		files []string // files to create in temp dir
		want  bool
	}{
		{
			name:  "has deps.json",
			files: []string{"MyApp.deps.json"},
			want:  true,
		},
		{
			name:  "has runtimeconfig.json",
			files: []string{"MyApp.runtimeconfig.json"},
			want:  true,
		},
		{
			name:  "has coreclr.dll",
			files: []string{"coreclr.dll"},
			want:  true,
		},
		{
			name:  "has hostfxr.dll",
			files: []string{"hostfxr.dll"},
			want:  true,
		},
		{
			name:  "has libcoreclr.so",
			files: []string{"libcoreclr.so"},
			want:  true,
		},
		{
			name:  "has libhostfxr.dylib",
			files: []string{"libhostfxr.dylib"},
			want:  true,
		},
		{
			name:  "no dotnet markers",
			files: []string{"readme.txt", "app.exe"},
			want:  false,
		},
		{
			name:  "empty directory",
			files: nil,
			want:  false,
		},
		{
			name:  "both deps and runtime config",
			files: []string{"MyApp.deps.json", "MyApp.runtimeconfig.json", "MyApp.dll"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0644); err != nil {
					t.Fatalf("create file %s: %v", f, err)
				}
			}
			got := IsDotNetApp(dir)
			if got != tt.want {
				t.Errorf("IsDotNetApp() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nonexistent directory", func(t *testing.T) {
		got := IsDotNetApp(filepath.Join(t.TempDir(), "nope"))
		if got {
			t.Error("expected false for nonexistent dir")
		}
	})

	t.Run("file instead of directory", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "afile.txt")
		_ = os.WriteFile(f, []byte("hi"), 0644)
		got := IsDotNetApp(f)
		if got {
			t.Error("expected false for file path")
		}
	})
}

// ---------------------------------------------------------------------------
// FindDepsJSON / FindRuntimeConfig
// ---------------------------------------------------------------------------

func TestFindDepsJSON(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  int
	}{
		{
			name:  "finds multiple deps.json",
			files: []string{"App.deps.json", "Lib.deps.json", "readme.txt"},
			want:  2,
		},
		{
			name:  "no matches",
			files: []string{"app.dll", "config.json"},
			want:  0,
		},
		{
			name:  "empty directory",
			files: nil,
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tt.files {
				_ = os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0644)
			}
			got := FindDepsJSON(dir)
			if len(got) != tt.want {
				t.Errorf("FindDepsJSON() returned %d files, want %d", len(got), tt.want)
			}
		})
	}
}

func TestFindRuntimeConfig(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  int
	}{
		{
			name:  "finds runtimeconfig",
			files: []string{"App.runtimeconfig.json", "other.json"},
			want:  1,
		},
		{
			name:  "no matches",
			files: []string{"app.dll"},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tt.files {
				_ = os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0644)
			}
			got := FindRuntimeConfig(dir)
			if len(got) != tt.want {
				t.Errorf("FindRuntimeConfig() returned %d files, want %d", len(got), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ClassifyLibraries
// ---------------------------------------------------------------------------

func TestClassifyLibraries(t *testing.T) {
	tests := []struct {
		name  string
		deps  *DepsResult
		check func(t *testing.T, cl *LibraryClassification)
	}{
		{
			name: "classifies project libs as first party",
			deps: &DepsResult{
				TotalLibraries: 1,
				ProjectLibs: []LibrarySummary{
					{Name: "MyApp", Version: "1.0.0", Type: "project"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.FirstParty) != 1 {
					t.Fatalf("FirstParty len = %d, want 1", len(cl.FirstParty))
				}
				if cl.FirstParty[0].Name != "MyApp" {
					t.Errorf("FirstParty[0].Name = %q", cl.FirstParty[0].Name)
				}
				if cl.TotalLibs != 1 {
					t.Errorf("TotalLibs = %d, want 1", cl.TotalLibs)
				}
			},
		},
		{
			name: "classifies Microsoft and System packages",
			deps: &DepsResult{
				TotalLibraries: 2,
				PackageLibs: []LibrarySummary{
					{Name: "Microsoft.Extensions.Logging", Version: "8.0.0", Type: "package"},
					{Name: "System.Text.Json", Version: "8.0.0", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.Microsoft) != 2 {
					t.Errorf("Microsoft len = %d, want 2", len(cl.Microsoft))
				}
				if len(cl.ThirdParty) != 0 {
					t.Errorf("ThirdParty len = %d, want 0", len(cl.ThirdParty))
				}
			},
		},
		{
			name: "classifies runtime packages",
			deps: &DepsResult{
				TotalLibraries: 1,
				PackageLibs: []LibrarySummary{
					{Name: "runtime.win-x64.Microsoft.NETCore.App", Version: "8.0.0", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.Runtime) != 1 {
					t.Errorf("Runtime len = %d, want 1", len(cl.Runtime))
				}
			},
		},
		{
			name: "classifies third-party packages",
			deps: &DepsResult{
				TotalLibraries: 2,
				PackageLibs: []LibrarySummary{
					{Name: "Newtonsoft.Json", Version: "13.0.3", Type: "package"},
					{Name: "Serilog", Version: "3.1.1", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.ThirdParty) != 2 {
					t.Errorf("ThirdParty len = %d, want 2", len(cl.ThirdParty))
				}
			},
		},
		{
			name: "detects prerelease versions",
			deps: &DepsResult{
				TotalLibraries: 2,
				PackageLibs: []LibrarySummary{
					{Name: "SomeLib", Version: "1.0.0-beta.1", Type: "package"},
					{Name: "StableLib", Version: "2.0.0", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				foundPre := false
				foundStable := false
				for _, lib := range cl.ThirdParty {
					if lib.Name == "SomeLib" && lib.IsPrerelease {
						foundPre = true
					}
					if lib.Name == "StableLib" && !lib.IsPrerelease {
						foundStable = true
					}
				}
				if !foundPre {
					t.Error("SomeLib should be marked as prerelease")
				}
				if !foundStable {
					t.Error("StableLib should not be prerelease")
				}
			},
		},
		{
			name: "detects known vulnerabilities",
			deps: &DepsResult{
				TotalLibraries: 2,
				PackageLibs: []LibrarySummary{
					{Name: "System.Text.Encodings.Web", Version: "4.5.0", Type: "package"},
					{Name: "Newtonsoft.Json", Version: "11.0.2", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.Vulnerable) != 2 {
					t.Fatalf("Vulnerable len = %d, want 2", len(cl.Vulnerable))
				}
				vulnNames := make(map[string]bool)
				for _, v := range cl.Vulnerable {
					vulnNames[v.Name] = true
					if v.Advisory == "" {
						t.Errorf("advisory empty for %s", v.Name)
					}
				}
				if !vulnNames["Newtonsoft.Json"] {
					t.Error("Newtonsoft.Json should be flagged as vulnerable")
				}
				if !vulnNames["System.Text.Encodings.Web"] {
					t.Error("System.Text.Encodings.Web should be flagged as vulnerable")
				}
			},
		},
		{
			name: "non-vulnerable version not flagged",
			deps: &DepsResult{
				TotalLibraries: 1,
				PackageLibs: []LibrarySummary{
					{Name: "System.Text.Encodings.Web", Version: "8.0.0", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.Vulnerable) != 0 {
					t.Errorf("Vulnerable len = %d, want 0", len(cl.Vulnerable))
				}
			},
		},
		{
			name: "categorizes web libraries",
			deps: &DepsResult{
				TotalLibraries: 1,
				PackageLibs: []LibrarySummary{
					{Name: "Swashbuckle.AspNetCore", Version: "6.5.0", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.ThirdParty) != 1 {
					t.Fatalf("ThirdParty len = %d", len(cl.ThirdParty))
				}
				if cl.ThirdParty[0].Category != "web" {
					t.Errorf("Category = %q, want web", cl.ThirdParty[0].Category)
				}
			},
		},
		{
			name: "categorizes data libraries",
			deps: &DepsResult{
				TotalLibraries: 1,
				PackageLibs: []LibrarySummary{
					{Name: "Microsoft.EntityFrameworkCore", Version: "8.0.0", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.Microsoft) != 1 {
					t.Fatalf("Microsoft len = %d", len(cl.Microsoft))
				}
				if cl.Microsoft[0].Category != "data" {
					t.Errorf("Category = %q, want data", cl.Microsoft[0].Category)
				}
			},
		},
		{
			name: "categorizes testing libraries",
			deps: &DepsResult{
				TotalLibraries: 1,
				PackageLibs: []LibrarySummary{
					{Name: "xunit", Version: "2.6.0", Type: "package"},
				},
			},
			check: func(t *testing.T, cl *LibraryClassification) {
				if len(cl.ThirdParty) != 1 {
					t.Fatalf("ThirdParty len = %d", len(cl.ThirdParty))
				}
				if cl.ThirdParty[0].Category != "testing" {
					t.Errorf("Category = %q, want testing", cl.ThirdParty[0].Category)
				}
			},
		},
		{
			name: "empty deps",
			deps: &DepsResult{TotalLibraries: 0},
			check: func(t *testing.T, cl *LibraryClassification) {
				if cl.TotalLibs != 0 {
					t.Errorf("TotalLibs = %d, want 0", cl.TotalLibs)
				}
				if len(cl.FirstParty) != 0 || len(cl.ThirdParty) != 0 || len(cl.Microsoft) != 0 || len(cl.Runtime) != 0 {
					t.Error("all slices should be empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := ClassifyLibraries(tt.deps)
			if tt.check != nil {
				tt.check(t, cl)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterStrings
// ---------------------------------------------------------------------------

func TestFilterStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		check func(t *testing.T, fs *FilteredStrings)
	}{
		{
			name:  "empty input",
			input: nil,
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Total != 0 {
					t.Errorf("Total = %d, want 0", fs.Total)
				}
			},
		},
		{
			name:  "filters short strings as noise",
			input: []string{"ab", "x", "hi"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Filtered != 3 {
					t.Errorf("Filtered = %d, want 3", fs.Filtered)
				}
			},
		},
		{
			name:  "filters hex prefix strings",
			input: []string{"0xFF00FF00"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Filtered != 1 {
					t.Errorf("Filtered = %d, want 1", fs.Filtered)
				}
			},
		},
		{
			name:  "filters long hex blobs",
			input: []string{"aabbccddee11223344556677889900aabbccddee"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Filtered != 1 {
					t.Errorf("Filtered = %d, want 1", fs.Filtered)
				}
			},
		},
		{
			name:  "filters dotnet noise patterns",
			input: []string{"System.Private.CoreLib.Something", "CompilerGenerated stuff here", "<Module> init"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Filtered != 3 {
					t.Errorf("Filtered = %d, want 3", fs.Filtered)
				}
			},
		},
		{
			name:  "filters repeated characters",
			input: []string{"AAAAAAAA", "--------"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Filtered != 2 {
					t.Errorf("Filtered = %d, want 2", fs.Filtered)
				}
			},
		},
		{
			name:  "filters pure numeric strings",
			input: []string{"1234567890"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Filtered != 1 {
					t.Errorf("Filtered = %d, want 1", fs.Filtered)
				}
			},
		},
		{
			name:  "classifies URLs",
			input: []string{"https://api.example.com/v1", "http://localhost:5000"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.URLs) != 2 {
					t.Errorf("URLs len = %d, want 2", len(fs.URLs))
				}
			},
		},
		{
			name:  "classifies namespaces",
			input: []string{"System.Net.Http", "Microsoft.Extensions.DependencyInjection"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.Namespaces) != 2 {
					t.Errorf("Namespaces len = %d, want 2", len(fs.Namespaces))
				}
			},
		},
		{
			name:  "classifies class names",
			input: []string{"HttpClient", "ServiceCollection", "DataContext"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.ClassNames) != 3 {
					t.Errorf("ClassNames len = %d, want 3", len(fs.ClassNames))
				}
			},
		},
		{
			name:  "classifies SQL queries",
			input: []string{"SELECT * FROM users WHERE id = @id", "INSERT INTO logs (msg) VALUES (@msg)"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.SQLQueries) != 2 {
					t.Errorf("SQLQueries len = %d, want 2", len(fs.SQLQueries))
				}
			},
		},
		{
			name:  "classifies file paths",
			input: []string{`C:\Program Files\MyApp\config.json`, "myapp.dll"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.FilePaths) != 2 {
					t.Errorf("FilePaths len = %d, want 2", len(fs.FilePaths))
				}
			},
		},
		{
			name:  "classifies API routes",
			input: []string{"/api/v1/users", "/health"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.APIRoutes) != 2 {
					t.Errorf("APIRoutes len = %d, want 2", len(fs.APIRoutes))
				}
			},
		},
		{
			name:  "classifies config keys",
			input: []string{"ConnectionStrings:DefaultConnection", "MaxRetries=5"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.ConfigKeys) != 2 {
					t.Errorf("ConfigKeys len = %d, want 2", len(fs.ConfigKeys))
				}
			},
		},
		{
			name:  "deduplicates strings",
			input: []string{"https://example.com", "https://example.com", "https://example.com"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.URLs) != 1 {
					t.Errorf("URLs len = %d, want 1 (deduped)", len(fs.URLs))
				}
				if fs.Filtered != 2 {
					t.Errorf("Filtered = %d, want 2 (2 dupes)", fs.Filtered)
				}
			},
		},
		{
			name:  "interesting strings (unclassified)",
			input: []string{"some random meaningful text here"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if len(fs.Interesting) != 1 {
					t.Errorf("Interesting len = %d, want 1", len(fs.Interesting))
				}
			},
		},
		{
			name:  "filters generic type mangling",
			input: []string{"Dictionary`2"},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Filtered != 1 {
					t.Errorf("Filtered = %d, want 1", fs.Filtered)
				}
			},
		},
		{
			name: "mixed input",
			input: []string{
				"https://api.example.com",
				"System.Net.Http",
				"ab",   // noise: too short
				"test", // noise: too short
				"SELECT * FROM users",
				"/api/health",
				`C:\temp\data.dll`,
				"CompilerGenerated stuff",
				"This is an interesting string value",
			},
			check: func(t *testing.T, fs *FilteredStrings) {
				if fs.Total != 9 {
					t.Errorf("Total = %d, want 9", fs.Total)
				}
				if len(fs.URLs) != 1 {
					t.Errorf("URLs = %d", len(fs.URLs))
				}
				if len(fs.Namespaces) != 1 {
					t.Errorf("Namespaces = %d", len(fs.Namespaces))
				}
				if len(fs.SQLQueries) != 1 {
					t.Errorf("SQLQueries = %d", len(fs.SQLQueries))
				}
				if len(fs.APIRoutes) != 1 {
					t.Errorf("APIRoutes = %d", len(fs.APIRoutes))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterStrings(tt.input)
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitLibraryKey (internal but exercised via ParseDeps)
// ---------------------------------------------------------------------------

func TestSplitLibraryKey(t *testing.T) {
	tests := []struct {
		key         string
		wantName    string
		wantVersion string
	}{
		{"MyLib/1.0.0", "MyLib", "1.0.0"},
		{"Namespace.Lib/2.3.4-beta.1", "Namespace.Lib", "2.3.4-beta.1"},
		{"NoSlash", "NoSlash", ""},
		{"Multiple/Slashes/Here", "Multiple/Slashes", "Here"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			name, version := splitLibraryKey(tt.key)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isNoise edge cases
// ---------------------------------------------------------------------------

func TestIsNoise(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"too short (3 chars)", "abc", true},
		{"exactly 4 chars (not noise)", "abcd", false},
		{"long no spaces", strings.Repeat("x", 201), true},
		{"long with spaces", "this is a long string " + strings.Repeat("word ", 40), false},
		{"hex prefix", "0xDEADBEEF", true},
		{"hex blob 32+ chars", strings.Repeat("ab", 16), true},
		{"getter noise", "get_Value returns", true},
		{"setter noise", "set_Property value", true},
		{".ctor noise", ".ctor initialization", true},
		{"display class noise", "<>c__DisplayClass0_0", true},
		{"anonymous type noise", "<>f__AnonymousType0", true},
		{"opcode-like string", "bcdfghjk", true},
		{"repeated chars", "ZZZZZZZZ", true},
		{"IL opcode ldarg", "ldarg.0", true},
		{"normal string", "Hello, World!", false},

		// New assembly instruction patterns
		{"asm mov", "mov eax, [rbx+0x10]", true},
		{"asm push", "push rbp", true},
		{"asm call", "call 0x401000", true},
		{"asm ret", "ret ", true},
		{"asm jmp", "jmp short_label", true},
		{"asm xor", "xor eax, eax", true},
		{"asm lea", "lea rax, [rsp+0x20]", true},
		{"asm nop", "nop padding", true},
		{"asm test", "test eax, eax", true},
		{"asm cmp", "cmp rax, 0x100", true},

		// Repeated pattern noise
		{"repeated 2-char pattern", "ababababababab", true},
		{"repeated 3-char pattern", "xyzxyzxyzxyz", true},

		// No-vowel short strings (binary noise)
		{"no vowels short", "bcdfgh", true},
		{"no vowels medium", "rtypsdfjklz", true},

		// These should NOT be noise
		{"dotted path", "Microsoft.Extensions.Logging", false},
		{"file path", "C:\\Windows\\System32", false},
		{"URL", "https://api.example.com", false},
		{"error message", "Failed to connect to database", false},
		{"config key", "ConnectionTimeout=30", false},
		{"version string", "v2.5.1-beta", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNoise(tt.input)
			if got != tt.want {
				t.Errorf("isNoise(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// categorize
// ---------------------------------------------------------------------------

func TestCategorize(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"Microsoft.AspNetCore.Mvc", "web"},
		{"Microsoft.EntityFrameworkCore.SqlServer", "data"},
		{"Serilog.Sinks.Console", "logging"},
		{"xunit.runner.visualstudio", "testing"},
		{"Grpc.Net.Client", "ipc"},
		{"Microsoft.Maui.Controls", "ui"},
		{"Microsoft.Identity.Web", "security"},
		{"SomeRandomPackage", "other"},
		{"Npgsql", "data"},
		{"Avalonia.Desktop", "ui"},
		{"FluentValidation", "other"}, // not in category patterns
		{"Polly", "other"},            // not in category patterns
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := categorize(tt.name)
			if got != tt.want {
				t.Errorf("categorize(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isPrerelease
// ---------------------------------------------------------------------------

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"1.0.0", false},
		{"1.0.0-beta.1", true},
		{"2.0.0-rc.1", true},
		{"3.0.0-preview.7", true},
		{"8.0.0", false},
		{"1.0.0-alpha", true},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := isPrerelease(tt.version)
			if got != tt.want {
				t.Errorf("isPrerelease(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// classifyDotnetString
// ---------------------------------------------------------------------------

func TestClassifyDotnetString(t *testing.T) {
	tests := []struct {
		input string
		want  dotnetCategory
	}{
		{"https://example.com/api", dotnetCatURL},
		{"http://localhost:5000", dotnetCatURL},
		{"SELECT * FROM table", dotnetCatSQL},
		{"INSERT INTO log VALUES (1)", dotnetCatSQL},
		{"UPDATE users SET name = 'x'", dotnetCatSQL},
		{"DELETE FROM sessions", dotnetCatSQL},
		{"/api/v1/users", dotnetCatAPIRoute},
		{"/health", dotnetCatAPIRoute},
		{`C:\Windows\System32\kernel32.dll`, dotnetCatFilePath},
		{"/usr/local/bin/dotnet", dotnetCatAPIRoute}, // lowercase path matches API route before file path
		{"appsettings.json", dotnetCatFilePath},
		{"ConnectionStrings:Default", dotnetCatConfigKey},
		{"MaxRetries=3", dotnetCatConfigKey},
		{"System.Net.Http", dotnetCatNamespace},
		{"Microsoft.Extensions.DependencyInjection", dotnetCatNamespace},
		{"HttpClient", dotnetCatClassName},
		{"ServiceProvider", dotnetCatClassName},
		{"just some random text", dotnetCatInteresting},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := classifyDotnetString(tt.input)
			if got != tt.want {
				t.Errorf("classifyDotnetString(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// findByPattern with invalid dir
// ---------------------------------------------------------------------------

func TestFindByPatternInvalidDir(t *testing.T) {
	got := FindDepsJSON(filepath.Join(t.TempDir(), "nonexistent"))
	if len(got) != 0 {
		t.Errorf("expected empty result for nonexistent dir, got %d", len(got))
	}
}
