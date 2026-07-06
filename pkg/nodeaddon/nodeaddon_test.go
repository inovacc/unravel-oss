/*
Copyright (c) 2026 Security Research
*/
package nodeaddon

import (
	"testing"
)

func TestIsNAPISymbol(t *testing.T) {
	tests := []struct {
		name   string
		symbol string
		want   bool
	}{
		{"napi_register_module_v1", "napi_register_module_v1", true},
		{"napi_module_register", "napi_module_register", true},
		{"node_register_module_v1", "node_register_module_v1", true},
		{"node_api_module_get_api_version_v1", "node_api_module_get_api_version_v1", true},
		{"random function", "my_function", false},
		{"partial match", "napi_register", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNAPISymbol(tt.symbol)
			if got != tt.want {
				t.Errorf("isNAPISymbol(%q) = %v, want %v", tt.symbol, got, tt.want)
			}
		})
	}
}

func TestDetectNAPIVersion(t *testing.T) {
	tests := []struct {
		name    string
		exports []ExportedFunc
		want    int
	}{
		{
			"napi v9+",
			[]ExportedFunc{{Name: "node_api_module_get_api_version_v1", IsNAPI: true}},
			9,
		},
		{
			"napi v1",
			[]ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}},
			1,
		},
		{
			"no napi",
			[]ExportedFunc{{Name: "my_func"}},
			0,
		},
		{
			"v9 takes precedence",
			[]ExportedFunc{
				{Name: "napi_register_module_v1", IsNAPI: true},
				{Name: "node_api_module_get_api_version_v1", IsNAPI: true},
			},
			9,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectNAPIVersion(tt.exports)
			if got != tt.want {
				t.Errorf("detectNAPIVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifyLibrary(t *testing.T) {
	tests := []struct {
		name      string
		library   string
		functions []string
		want      string
	}{
		{"windows crypto", "bcrypt.dll", nil, "crypto"},
		{"windows network", "ws2_32.dll", nil, "network"},
		{"windows registry", "advapi32.dll", nil, "registry"},
		{"linux ssl", "libssl.so.3", nil, "crypto"},
		{"linux curl", "libcurl.so.4", nil, "network"},
		{"linux pthread", "libpthread.so.0", nil, "system"},
		{"c runtime", "libc.so.6", nil, "runtime"},
		{"node runtime", "libnode.so", nil, "node"},
		{"unknown", "libcustom.so", nil, "system"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyLibrary(tt.library, tt.functions)
			if got != tt.want {
				t.Errorf("classifyLibrary(%q) = %q, want %q", tt.library, got, tt.want)
			}
		})
	}
}

func TestAssessRisk(t *testing.T) {
	tests := []struct {
		name       string
		imports    []ImportedLib
		exports    []ExportedFunc
		wantMin    int
		wantMax    int
		wantFactor string
	}{
		{
			"no risk",
			[]ImportedLib{{Library: "libc.so", Category: "runtime"}},
			[]ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}},
			0, 5, "",
		},
		{
			"process injection",
			[]ImportedLib{{Library: "kernel32.dll", Category: "system", Functions: []string{"CreateRemoteThread"}}},
			[]ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}},
			30, 100, "Process Injection",
		},
		{
			"missing napi exports",
			[]ImportedLib{{Library: "libc.so", Category: "runtime"}},
			[]ExportedFunc{{Name: "my_func"}},
			20, 100, "Missing N-API Exports",
		},
		{
			"network + crypto combo",
			[]ImportedLib{
				{Library: "ws2_32.dll", Category: "network"},
				{Library: "bcrypt.dll", Category: "crypto"},
			},
			[]ExportedFunc{{Name: "napi_register_module_v1", IsNAPI: true}},
			10, 100, "Network + Crypto",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, factors := assessRisk(tt.imports, tt.exports)
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("assessRisk() score = %d, want [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
			if tt.wantFactor != "" {
				found := false
				for _, f := range factors {
					if f.Name == tt.wantFactor {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("assessRisk() missing expected factor %q, got %v", tt.wantFactor, factors)
				}
			}
		})
	}
}

func TestCategorizeString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/api", "URL"},
		{"http://localhost:3000", "URL"},
		{"C:\\Program Files\\app", "FILE_PATH"},
		{"/usr/local/lib/node", "FILE_PATH"},
		{"error: failed to load", "ERROR_MESSAGE"},
		{"AES-256-CBC cipher", "CRYPTO"},
		{"socket connection bind", "NETWORK"},
		{"HKEY_LOCAL_MACHINE", "REGISTRY"},
		{"hello world", "GENERAL"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := categorizeString(tt.input)
			if got != tt.want {
				t.Errorf("categorizeString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name  string
		input string
		low   float64
		high  float64
	}{
		{"empty", "", 0, 0},
		{"single char", "aaaa", 0, 0.1},
		{"alphabet", "abcdefghijklmnopqrstuvwxyz", 4.5, 5.0},
		{"binary-like", "0101010101", 0.9, 1.1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.low || got > tt.high {
				t.Errorf("shannonEntropy(%q) = %f, want [%f, %f]", tt.input, got, tt.low, tt.high)
			}
		})
	}
}
