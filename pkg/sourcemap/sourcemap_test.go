package sourcemap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helper to write a source map JSON file and return its path.
func writeMapFile(t *testing.T, dir string, name string, sm SourceMap) string {
	t.Helper()
	data, err := json.Marshal(sm)
	if err != nil {
		t.Fatalf("marshal source map: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestCountMappingSegments(t *testing.T) {
	tests := []struct {
		name     string
		mappings string
		want     int
	}{
		{"empty string", "", 0},
		{"single segment", "AAAA", 1},
		{"two segments comma", "AAAA,BBBB", 2},
		{"two lines", "AAAA;BBBB", 2},
		{"mixed separators", "AAAA,BBBB;CCCC,DDDD", 4},
		{"trailing semicolon", "AAAA;", 1},
		{"leading semicolon", ";AAAA", 1},
		{"only separators", ";;;,,,", 0},
		{"segment between separators", ",AAAA,", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countMappingSegments(tt.mappings)
			if got != tt.want {
				t.Errorf("countMappingSegments(%q) = %d, want %d", tt.mappings, got, tt.want)
			}
		})
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"plain path", "src/app.js", filepath.Join("src", "app.js")},
		{"leading slash", "/src/app.js", filepath.Join("src", "app.js")},
		{"path traversal", "../../../etc/passwd", filepath.Join("etc", "passwd")},
		{"dot segments", "./src/../app.js", filepath.Join("src", "app.js")},
		{"file url", "file:///home/user/src/app.js", filepath.Join("home", "user", "src", "app.js")},
		{"webpack triple slash", "webpack:///src/foo.js", filepath.Join("src", "foo.js")},
		{"webpack double slash", "webpack://src/foo.js", filepath.Join("src", "foo.js")},
		{"webpack single slash", "webpack:/src/foo.js", filepath.Join("src", "foo.js")},
		{"vite fs path", "/@fs/home/user/project/src/app.js", filepath.Join("home", "user", "project", "src", "app.js")},
		{"vite import", "/@vite/client.js", "client.js"},
		{"backslashes", "src\\lib\\app.js", filepath.Join("src", "lib", "app.js")},
		{"empty after clean", "../..", "unknown_source"},
		{"only dots", ".", "unknown_source"},
		{"only slashes", "///", "unknown_source"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizePath(tt.source)
			if got != tt.want {
				t.Errorf("sanitizePath(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		sm          SourceMap
		wantErr     bool
		errContains string
		checkResult func(t *testing.T, r *ParseResult)
	}{
		{
			name: "valid source map with inline content",
			sm: SourceMap{
				Version:        3,
				File:           "bundle.js",
				SourceRoot:     "/src/",
				Sources:        []string{"app.js", "utils.js"},
				SourcesContent: []string{"console.log('a');", "export default {}"},
				Names:          []string{"log", "default"},
				Mappings:       "AAAA,BBBB;CCCC",
			},
			checkResult: func(t *testing.T, r *ParseResult) {
				if r.Version != 3 {
					t.Errorf("version = %d, want 3", r.Version)
				}
				if r.File != "bundle.js" {
					t.Errorf("file = %q, want %q", r.File, "bundle.js")
				}
				if r.SourceRoot != "/src/" {
					t.Errorf("source_root = %q, want %q", r.SourceRoot, "/src/")
				}
				if r.SourceCount != 2 {
					t.Errorf("source_count = %d, want 2", r.SourceCount)
				}
				if r.NameCount != 2 {
					t.Errorf("name_count = %d, want 2", r.NameCount)
				}
				if !r.HasInlineContent {
					t.Error("has_inline_content should be true")
				}
				if r.MappingSegments != 3 {
					t.Errorf("mapping_segments = %d, want 3", r.MappingSegments)
				}
				if len(r.Sources) != 2 {
					t.Fatalf("sources len = %d, want 2", len(r.Sources))
				}
				if !r.Sources[0].HasContent {
					t.Error("sources[0].HasContent should be true")
				}
				if r.Sources[0].Size != len("console.log('a');") {
					t.Errorf("sources[0].Size = %d, want %d", r.Sources[0].Size, len("console.log('a');"))
				}
			},
		},
		{
			name: "no inline content",
			sm: SourceMap{
				Version:  3,
				Sources:  []string{"a.js"},
				Mappings: "AAAA",
			},
			checkResult: func(t *testing.T, r *ParseResult) {
				if r.HasInlineContent {
					t.Error("has_inline_content should be false")
				}
				if r.Sources[0].HasContent {
					t.Error("sources[0].HasContent should be false")
				}
			},
		},
		{
			name: "empty sources and mappings",
			sm: SourceMap{
				Version:  3,
				Sources:  []string{},
				Mappings: "",
			},
			checkResult: func(t *testing.T, r *ParseResult) {
				if r.SourceCount != 0 {
					t.Errorf("source_count = %d, want 0", r.SourceCount)
				}
				if r.MappingSegments != 0 {
					t.Errorf("mapping_segments = %d, want 0", r.MappingSegments)
				}
			},
		},
		{
			name: "wrong version",
			sm: SourceMap{
				Version:  2,
				Sources:  []string{"a.js"},
				Mappings: "AAAA",
			},
			wantErr:     true,
			errContains: "unsupported source map version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeMapFile(t, dir, "test.map", tt.sm)

			result, err := Parse(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

func TestParse_FileErrors(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string
		errContains string
	}{
		{
			name: "nonexistent file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nope.map")
			},
			errContains: "read source map",
		},
		{
			name: "invalid JSON",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				path := filepath.Join(dir, "bad.map")
				_ = os.WriteFile(path, []byte("{not json}"), 0o644)
				return path
			},
			errContains: "parse source map JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			_, err := Parse(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestExtractSources(t *testing.T) {
	tests := []struct {
		name        string
		sm          SourceMap
		wantExtract int
		wantSkip    int
		checkFiles  map[string]string // relative path -> expected content
	}{
		{
			name: "extract inline sources",
			sm: SourceMap{
				Version:        3,
				Sources:        []string{"src/app.js", "src/utils.js"},
				SourcesContent: []string{"console.log('app');", "export default {}"},
				Mappings:       "AAAA",
			},
			wantExtract: 2,
			wantSkip:    0,
			checkFiles: map[string]string{
				filepath.Join("src", "app.js"):   "console.log('app');",
				filepath.Join("src", "utils.js"): "export default {}",
			},
		},
		{
			name: "skip sources without content",
			sm: SourceMap{
				Version:        3,
				Sources:        []string{"a.js", "b.js", "c.js"},
				SourcesContent: []string{"content-a", "", "content-c"},
				Mappings:       "AAAA",
			},
			wantExtract: 2,
			wantSkip:    1,
			checkFiles: map[string]string{
				"a.js": "content-a",
				"c.js": "content-c",
			},
		},
		{
			name: "more sources than sourcesContent",
			sm: SourceMap{
				Version:        3,
				Sources:        []string{"a.js", "b.js", "c.js"},
				SourcesContent: []string{"content-a"},
				Mappings:       "AAAA",
			},
			wantExtract: 1,
			wantSkip:    2,
		},
		{
			name: "no sourcesContent at all",
			sm: SourceMap{
				Version:  3,
				Sources:  []string{"a.js"},
				Mappings: "AAAA",
			},
			wantExtract: 0,
			wantSkip:    1,
		},
		{
			name: "webpack-prefixed paths are sanitized",
			sm: SourceMap{
				Version:        3,
				Sources:        []string{"webpack:///src/main.js"},
				SourcesContent: []string{"// main"},
				Mappings:       "AAAA",
			},
			wantExtract: 1,
			checkFiles: map[string]string{
				filepath.Join("src", "main.js"): "// main",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			mapPath := writeMapFile(t, dir, "test.map", tt.sm)
			outDir := filepath.Join(dir, "output")

			result, err := ExtractSources(mapPath, outDir)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Extracted != tt.wantExtract {
				t.Errorf("extracted = %d, want %d", result.Extracted, tt.wantExtract)
			}
			if result.Skipped != tt.wantSkip {
				t.Errorf("skipped = %d, want %d", result.Skipped, tt.wantSkip)
			}
			if result.TotalSources != len(tt.sm.Sources) {
				t.Errorf("total_sources = %d, want %d", result.TotalSources, len(tt.sm.Sources))
			}

			for relPath, wantContent := range tt.checkFiles {
				fullPath := filepath.Join(outDir, relPath)
				data, err := os.ReadFile(fullPath)
				if err != nil {
					t.Errorf("expected file %s to exist: %v", relPath, err)
					continue
				}
				if string(data) != wantContent {
					t.Errorf("file %s content = %q, want %q", relPath, string(data), wantContent)
				}
			}
		})
	}
}

func TestExtractSources_Errors(t *testing.T) {
	t.Run("nonexistent map file", func(t *testing.T) {
		_, err := ExtractSources("/nonexistent/test.map", t.TempDir())
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid version", func(t *testing.T) {
		dir := t.TempDir()
		path := writeMapFile(t, dir, "bad.map", SourceMap{Version: 1, Sources: []string{"a.js"}, Mappings: "A"})
		_, err := ExtractSources(path, filepath.Join(dir, "out"))
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestDetectBundler(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		wantBundler    BundlerType
		wantConfidence string
		wantIndicators int // minimum number of indicators
	}{
		{
			name:           "webpack require",
			content:        `var x = __webpack_require__(123);`,
			wantBundler:    BundlerWebpack,
			wantConfidence: "high",
		},
		{
			name:           "webpack modules",
			content:        `var __webpack_modules__ = {};`,
			wantBundler:    BundlerWebpack,
			wantConfidence: "high",
		},
		{
			name:           "webpack chunk",
			content:        `self["webpackChunk"] = [];`,
			wantBundler:    BundlerWebpack,
			wantConfidence: "high",
		},
		{
			name:           "webpack with version",
			content:        `__webpack_require__ webpack/runtime/5`,
			wantBundler:    BundlerWebpack,
			wantConfidence: "high",
		},
		{
			name:           "vite path",
			content:        `import "/@vite/client";`,
			wantBundler:    BundlerVite,
			wantConfidence: "high",
		},
		{
			name:           "vite ssr",
			content:        `const __vite_ssr_import__ = {};`,
			wantBundler:    BundlerVite,
			wantConfidence: "high",
		},
		{
			name:           "vite hmr medium",
			content:        `if (import.meta.hot) {}`,
			wantBundler:    BundlerVite,
			wantConfidence: "medium",
		},
		{
			name:           "parcel require",
			content:        `var x = parcelRequire("abc");`,
			wantBundler:    BundlerParcel,
			wantConfidence: "high",
		},
		{
			name:           "parcel package ref",
			content:        `require("@parcel/transformer")`,
			wantBundler:    BundlerParcel,
			wantConfidence: "high",
		},
		{
			name:           "esbuild annotation",
			content:        `// @esbuild generated`,
			wantBundler:    BundlerEsbuild,
			wantConfidence: "high",
		},
		{
			name:           "rollup pure annotation",
			content:        `var x = /*#__PURE__*/React.createElement("div")`,
			wantBundler:    BundlerRollup,
			wantConfidence: "medium",
		},
		{
			name:           "swc helpers",
			content:        `import {_ as _class} from "@swc/helpers";`,
			wantBundler:    BundlerSWC,
			wantConfidence: "high",
		},
		{
			name:           "empty content",
			content:        "",
			wantBundler:    BundlerUnknown,
			wantConfidence: "low",
		},
		{
			name:           "plain js no bundler",
			content:        `function add(a, b) { return a + b; }`,
			wantBundler:    BundlerUnknown,
			wantConfidence: "low",
		},
		{
			name:           "high confidence wins over medium",
			content:        `__webpack_require__ /***/ something`,
			wantBundler:    BundlerWebpack,
			wantConfidence: "high",
			wantIndicators: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectBundler(tt.content)
			if result.Bundler != tt.wantBundler {
				t.Errorf("bundler = %q, want %q", result.Bundler, tt.wantBundler)
			}
			if result.Confidence != tt.wantConfidence {
				t.Errorf("confidence = %q, want %q", result.Confidence, tt.wantConfidence)
			}
			if tt.wantIndicators > 0 && len(result.Indicators) < tt.wantIndicators {
				t.Errorf("indicators count = %d, want >= %d", len(result.Indicators), tt.wantIndicators)
			}
		})
	}
}

func TestDetectBundler_WebpackVersion(t *testing.T) {
	result := DetectBundler("__webpack_require__ webpack/runtime/5")
	if result.Version != "5" {
		t.Errorf("version = %q, want %q", result.Version, "5")
	}
}

func TestDetectBundlerFromMap(t *testing.T) {
	tests := []struct {
		name           string
		sm             *SourceMap
		wantBundler    BundlerType
		wantConfidence string
	}{
		{
			name:           "nil source map",
			sm:             nil,
			wantBundler:    BundlerUnknown,
			wantConfidence: "low",
		},
		{
			name: "webpack source paths",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"webpack/runtime/compat", "src/index.js"},
			},
			wantBundler:    BundlerWebpack,
			wantConfidence: "high",
		},
		{
			name: "vite fs paths",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"/@fs/home/user/project/src/App.vue"},
			},
			wantBundler:    BundlerVite,
			wantConfidence: "high",
		},
		{
			name: "vite module paths",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"src/main.ts", "/@vite/client"},
			},
			wantBundler:    BundlerVite,
			wantConfidence: "high",
		},
		{
			name: "parcel paths",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"@parcel/transformer-js/src/index.js"},
			},
			wantBundler:    BundlerParcel,
			wantConfidence: "high",
		},
		{
			name: "swc paths",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"node_modules/@swc/helpers/src/index.js"},
			},
			wantBundler:    BundlerSWC,
			wantConfidence: "high",
		},
		{
			name: "tsup file name",
			sm: &SourceMap{
				Version: 3,
				File:    "tsup-output.js",
				Sources: []string{"src/index.ts"},
			},
			wantBundler:    BundlerTSUp,
			wantConfidence: "medium",
		},
		{
			name: "esbuild via pnpm paths",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"node_modules/.pnpm/lodash@4.17.21/index.js"},
			},
			wantBundler:    BundlerEsbuild,
			wantConfidence: "medium",
		},
		{
			name: "fallback to inline content detection",
			sm: &SourceMap{
				Version:        3,
				Sources:        []string{"app.js"},
				SourcesContent: []string{"var x = __webpack_require__(1);"},
			},
			wantBundler:    BundlerWebpack,
			wantConfidence: "high",
		},
		{
			name: "rollup heuristic - clean paths no bundler",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"src/main.js", "src/utils.js"},
			},
			wantBundler:    BundlerRollup,
			wantConfidence: "low",
		},
		{
			name: "single source no match",
			sm: &SourceMap{
				Version: 3,
				Sources: []string{"index.js"},
			},
			wantBundler:    BundlerUnknown,
			wantConfidence: "low",
		},
		{
			name: "empty source map",
			sm: &SourceMap{
				Version: 3,
			},
			wantBundler:    BundlerUnknown,
			wantConfidence: "low",
		},
		{
			name: "inline content with empty entries skipped",
			sm: &SourceMap{
				Version:        3,
				Sources:        []string{"a.js", "b.js"},
				SourcesContent: []string{"", "parcelRequire('x')"},
			},
			wantBundler:    BundlerParcel,
			wantConfidence: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectBundlerFromMap(tt.sm)
			if result.Bundler != tt.wantBundler {
				t.Errorf("bundler = %q, want %q", result.Bundler, tt.wantBundler)
			}
			if result.Confidence != tt.wantConfidence {
				t.Errorf("confidence = %q, want %q", result.Confidence, tt.wantConfidence)
			}
		})
	}
}

func TestDetectBundlerFromMap_ContentLimit(t *testing.T) {
	// Ensure only first 5 sourcesContent entries are checked
	sm := &SourceMap{
		Version:        3,
		Sources:        make([]string, 10),
		SourcesContent: make([]string, 10),
	}
	for i := range 10 {
		sm.Sources[i] = "file" + string(rune('a'+i)) + ".js"
		sm.SourcesContent[i] = ""
	}
	// Put a bundler marker in the 7th entry (index 6, beyond limit of 5)
	sm.SourcesContent[6] = "__webpack_require__"

	result := DetectBundlerFromMap(sm)
	if result.Bundler != BundlerRollup {
		// With 10 clean sources, it should fall through to Rollup heuristic, not detect webpack
		t.Errorf("bundler = %q, want %q (content at index 6 should be skipped)", result.Bundler, BundlerRollup)
	}
}

func TestScanDir(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(t *testing.T, dir string)
		wantMaps      int
		wantSources   int
		wantBundlers  map[string]int
		checkMapPaths func(t *testing.T, maps []MapInfo)
	}{
		{
			name: "single valid map",
			setup: func(t *testing.T, dir string) {
				writeMapFile(t, dir, "bundle.js.map", SourceMap{
					Version:  3,
					Sources:  []string{"a.js", "b.js"},
					Mappings: "AAAA",
				})
			},
			wantMaps:    1,
			wantSources: 2,
		},
		{
			name: "multiple maps in subdirectories",
			setup: func(t *testing.T, dir string) {
				writeMapFile(t, dir, "dist/main.js.map", SourceMap{
					Version:  3,
					Sources:  []string{"src/main.js"},
					Mappings: "AAAA",
				})
				writeMapFile(t, dir, "dist/vendor.js.map", SourceMap{
					Version:  3,
					Sources:  []string{"node_modules/lodash/lodash.js", "webpack/bootstrap"},
					Mappings: "BBBB",
				})
			},
			wantMaps:    2,
			wantSources: 3,
			wantBundlers: map[string]int{
				"webpack": 1,
			},
		},
		{
			name: "skips .git directory",
			setup: func(t *testing.T, dir string) {
				writeMapFile(t, dir, "app.js.map", SourceMap{
					Version:  3,
					Sources:  []string{"app.js"},
					Mappings: "A",
				})
				// This should be skipped
				writeMapFile(t, dir, ".git/hooks/pre-commit.map", SourceMap{
					Version:  3,
					Sources:  []string{"hook.js"},
					Mappings: "A",
				})
			},
			wantMaps:    1,
			wantSources: 1,
		},
		{
			name: "skips node_modules directory",
			setup: func(t *testing.T, dir string) {
				writeMapFile(t, dir, "app.js.map", SourceMap{
					Version:  3,
					Sources:  []string{"app.js"},
					Mappings: "A",
				})
				writeMapFile(t, dir, "node_modules/pkg/index.js.map", SourceMap{
					Version:  3,
					Sources:  []string{"index.js"},
					Mappings: "A",
				})
			},
			wantMaps:    1,
			wantSources: 1,
		},
		{
			name: "non-map files ignored",
			setup: func(t *testing.T, dir string) {
				writeMapFile(t, dir, "app.js.map", SourceMap{
					Version:  3,
					Sources:  []string{"a.js"},
					Mappings: "A",
				})
				_ = os.WriteFile(filepath.Join(dir, "app.js"), []byte("// js"), 0o644)
				_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0o644)
			},
			wantMaps:    1,
			wantSources: 1,
		},
		{
			name:     "empty directory",
			setup:    func(t *testing.T, dir string) {},
			wantMaps: 0,
		},
		{
			name: "invalid map file is still listed with zero sources",
			setup: func(t *testing.T, dir string) {
				path := filepath.Join(dir, "bad.map")
				_ = os.WriteFile(path, []byte("{invalid json}"), 0o644)
			},
			wantMaps:    1,
			wantSources: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)

			result, err := ScanDir(dir)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.TotalMaps != tt.wantMaps {
				t.Errorf("total_maps = %d, want %d", result.TotalMaps, tt.wantMaps)
			}
			if result.TotalSources != tt.wantSources {
				t.Errorf("total_sources = %d, want %d", result.TotalSources, tt.wantSources)
			}
			if result.Directory != dir {
				t.Errorf("directory = %q, want %q", result.Directory, dir)
			}
			if tt.wantBundlers != nil {
				for bundler, count := range tt.wantBundlers {
					if result.Bundlers[bundler] != count {
						t.Errorf("bundlers[%s] = %d, want %d", bundler, result.Bundlers[bundler], count)
					}
				}
			}
			if tt.checkMapPaths != nil {
				tt.checkMapPaths(t, result.Maps)
			}
		})
	}
}

func TestScanDir_NonexistentDir(t *testing.T) {
	result, err := ScanDir("/nonexistent/path/that/does/not/exist")
	// filepath.Walk may or may not return an error for nonexistent dirs depending on OS.
	// On Windows it may succeed with zero results. Either outcome is acceptable.
	if err != nil {
		return // error is fine
	}
	if result.TotalMaps != 0 {
		t.Errorf("expected 0 maps for nonexistent dir, got %d", result.TotalMaps)
	}
}

func TestScanDir_CaseInsensitiveExtension(t *testing.T) {
	dir := t.TempDir()
	writeMapFile(t, dir, "Bundle.MAP", SourceMap{
		Version:  3,
		Sources:  []string{"index.js"},
		Mappings: "A",
	})

	result, err := ScanDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalMaps != 1 {
		t.Errorf("expected .MAP to be detected, total_maps = %d", result.TotalMaps)
	}
}

func TestSourceMapTypes(t *testing.T) {
	// Verify bundler type constants are distinct
	types := []BundlerType{
		BundlerWebpack, BundlerVite, BundlerEsbuild,
		BundlerRollup, BundlerParcel, BundlerTSUp,
		BundlerSWC, BundlerUnknown,
	}
	seen := make(map[BundlerType]bool)
	for _, bt := range types {
		if seen[bt] {
			t.Errorf("duplicate BundlerType: %q", bt)
		}
		seen[bt] = true
	}
}
