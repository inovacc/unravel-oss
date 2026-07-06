package archive

import (
	"os"
	"testing"
)

func TestParsePOM(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantGroup string
		wantArt   string
		wantVer   string
		wantPkg   string
		wantDeps  int
		wantErr   bool
	}{
		{
			name: "basic pom",
			input: `<?xml version="1.0"?>
<project>
    <groupId>com.example</groupId>
    <artifactId>my-app</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.0.0</version>
        </dependency>
    </dependencies>
</project>`,
			wantGroup: "com.example",
			wantArt:   "my-app",
			wantVer:   "1.0.0",
			wantPkg:   "jar",
			wantDeps:  1,
		},
		{
			name: "with parent inheritance",
			input: `<?xml version="1.0"?>
<project>
    <parent>
        <groupId>com.example.parent</groupId>
        <artifactId>parent-pom</artifactId>
        <version>2.0.0</version>
    </parent>
    <artifactId>child-app</artifactId>
</project>`,
			wantGroup: "com.example.parent",
			wantArt:   "child-app",
			wantVer:   "2.0.0",
		},
		{
			name: "with properties",
			input: `<?xml version="1.0"?>
<project>
    <groupId>com.example</groupId>
    <artifactId>props-app</artifactId>
    <version>1.0.0</version>
    <properties>
        <java.version>17</java.version>
        <spring.version>6.1.0</spring.version>
    </properties>
</project>`,
			wantGroup: "com.example",
			wantArt:   "props-app",
			wantVer:   "1.0.0",
		},
		{
			name: "with plugins",
			input: `<?xml version="1.0"?>
<project>
    <groupId>com.example</groupId>
    <artifactId>plugin-app</artifactId>
    <version>1.0.0</version>
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
        </plugins>
    </build>
</project>`,
			wantGroup: "com.example",
			wantArt:   "plugin-app",
			wantVer:   "1.0.0",
		},
		{
			name:    "invalid xml",
			input:   "not xml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParsePOM([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePOM() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if info.GroupID != tt.wantGroup {
				t.Errorf("GroupID = %q, want %q", info.GroupID, tt.wantGroup)
			}

			if info.ArtifactID != tt.wantArt {
				t.Errorf("ArtifactID = %q, want %q", info.ArtifactID, tt.wantArt)
			}

			if info.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", info.Version, tt.wantVer)
			}

			if tt.wantPkg != "" && info.Packaging != tt.wantPkg {
				t.Errorf("Packaging = %q, want %q", info.Packaging, tt.wantPkg)
			}

			if tt.wantDeps > 0 && len(info.Dependencies) != tt.wantDeps {
				t.Errorf("Dependencies = %d, want %d", len(info.Dependencies), tt.wantDeps)
			}
		})
	}
}

func TestParsePOMProperties(t *testing.T) {
	input := `<?xml version="1.0"?>
<project>
    <groupId>com.example</groupId>
    <artifactId>props</artifactId>
    <version>1.0.0</version>
    <properties>
        <java.version>17</java.version>
        <spring.version>6.1.0</spring.version>
    </properties>
</project>`

	info, err := ParsePOM([]byte(input))
	if err != nil {
		t.Fatalf("ParsePOM() error: %v", err)
	}

	if info.Properties["java.version"] != "17" {
		t.Errorf("Properties[java.version] = %q, want %q", info.Properties["java.version"], "17")
	}

	if info.Properties["spring.version"] != "6.1.0" {
		t.Errorf("Properties[spring.version] = %q, want %q", info.Properties["spring.version"], "6.1.0")
	}
}

func TestParsePOMFromFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/pomxml/basic.xml")
	if err != nil {
		t.Skipf("test fixture not available: %v", err)
	}

	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM() error: %v", err)
	}

	if info.GroupID != "com.example" {
		t.Errorf("GroupID = %q, want %q", info.GroupID, "com.example")
	}

	if info.ArtifactID != "webapp" {
		t.Errorf("ArtifactID = %q, want %q", info.ArtifactID, "webapp")
	}

	if info.Packaging != "war" {
		t.Errorf("Packaging = %q, want %q", info.Packaging, "war")
	}

	if len(info.Dependencies) != 3 {
		t.Errorf("Dependencies = %d, want 3", len(info.Dependencies))
	}

	if len(info.Plugins) != 1 {
		t.Errorf("Plugins = %d, want 1", len(info.Plugins))
	}
}
