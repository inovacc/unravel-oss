package archive

import (
	"os"
	"testing"
)

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantMain  string
		wantVer   string
		wantTitle string
		wantCP    []string
		wantErr   bool
	}{
		{
			name: "basic manifest",
			input: `Manifest-Version: 1.0
Main-Class: com.example.Main
Implementation-Version: 1.2.3
Implementation-Title: Example App
Class-Path: lib/a.jar lib/b.jar
`,
			wantMain:  "com.example.Main",
			wantVer:   "1.2.3",
			wantTitle: "Example App",
			wantCP:    []string{"lib/a.jar", "lib/b.jar"},
		},
		{
			name: "continuation lines",
			input: "Manifest-Version: 1.0\n" +
				"Class-Path: lib/a.jar lib/b.jar \n" +
				" lib/c.jar lib/d.jar\n" +
				"Main-Class: com.example.VeryLongClassName\n" +
				" ThatContinues\n",
			wantMain: "com.example.VeryLongClassNameThatContinues",
			wantCP:   []string{"lib/a.jar", "lib/b.jar", "lib/c.jar", "lib/d.jar"},
		},
		{
			name:     "empty manifest",
			input:    "",
			wantMain: "",
		},
		{
			name: "section separator",
			input: `Manifest-Version: 1.0
Main-Class: com.example.Main

Name: com/example/
Sealed: true
`,
			wantMain: "com.example.Main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseManifest([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseManifest() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if info.MainClass != tt.wantMain {
				t.Errorf("MainClass = %q, want %q", info.MainClass, tt.wantMain)
			}

			if info.ImplementationVersion != tt.wantVer {
				t.Errorf("ImplementationVersion = %q, want %q", info.ImplementationVersion, tt.wantVer)
			}

			if info.ImplementationTitle != tt.wantTitle {
				t.Errorf("ImplementationTitle = %q, want %q", info.ImplementationTitle, tt.wantTitle)
			}

			if tt.wantCP != nil {
				if len(info.ClassPath) != len(tt.wantCP) {
					t.Errorf("ClassPath length = %d, want %d", len(info.ClassPath), len(tt.wantCP))
				} else {
					for i := range tt.wantCP {
						if info.ClassPath[i] != tt.wantCP[i] {
							t.Errorf("ClassPath[%d] = %q, want %q", i, info.ClassPath[i], tt.wantCP[i])
						}
					}
				}
			}
		})
	}
}

func TestParseManifestFromFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/manifests/basic.mf")
	if err != nil {
		t.Skipf("test fixture not available: %v", err)
	}

	info, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("ParseManifest() error: %v", err)
	}

	if info.MainClass != "com.example.Main" {
		t.Errorf("MainClass = %q, want %q", info.MainClass, "com.example.Main")
	}

	if info.ImplementationVersion != "1.2.3" {
		t.Errorf("ImplementationVersion = %q, want %q", info.ImplementationVersion, "1.2.3")
	}

	if len(info.ClassPath) != 2 {
		t.Errorf("ClassPath length = %d, want 2", len(info.ClassPath))
	}
}
