package archive

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test: ParseSpringProperties — basic key=value
// ---------------------------------------------------------------------------

func TestParseSpringProperties_Basic(t *testing.T) {
	data := []byte(`server.port=8080
spring.datasource.url=jdbc:postgresql://localhost:5432/mydb
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.username=admin
spring.profiles.active=prod,staging
`)
	config, err := ParseSpringProperties(data)
	if err != nil {
		t.Fatalf("ParseSpringProperties error: %v", err)
	}
	if config.ServerPort != "8080" {
		t.Errorf("ServerPort = %q, want %q", config.ServerPort, "8080")
	}
	if config.Datasource == nil {
		t.Fatal("Datasource should not be nil")
	}
	if config.Datasource.URL != "jdbc:postgresql://localhost:5432/mydb" {
		t.Errorf("Datasource.URL = %q", config.Datasource.URL)
	}
	if config.Datasource.Driver != "org.postgresql.Driver" {
		t.Errorf("Datasource.Driver = %q", config.Datasource.Driver)
	}
	if config.Datasource.Username != "admin" {
		t.Errorf("Datasource.Username = %q, want admin", config.Datasource.Username)
	}
	if len(config.Profiles) != 2 {
		t.Fatalf("Profiles length = %d, want 2", len(config.Profiles))
	}
	if config.Profiles[0] != "prod" || config.Profiles[1] != "staging" {
		t.Errorf("Profiles = %v, want [prod staging]", config.Profiles)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringProperties — colon delimiter
// ---------------------------------------------------------------------------

func TestParseSpringProperties_ColonDelimiter(t *testing.T) {
	data := []byte(`server.port: 9090
`)
	config, err := ParseSpringProperties(data)
	if err != nil {
		t.Fatalf("ParseSpringProperties error: %v", err)
	}
	if config.ServerPort != "9090" {
		t.Errorf("ServerPort = %q, want %q", config.ServerPort, "9090")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringProperties — comments and blank lines skipped
// ---------------------------------------------------------------------------

func TestParseSpringProperties_CommentsSkipped(t *testing.T) {
	data := []byte(`# This is a comment
! Another comment style
server.port=3000

# Another comment
app.name=MyApp
`)
	config, err := ParseSpringProperties(data)
	if err != nil {
		t.Fatalf("ParseSpringProperties error: %v", err)
	}
	if config.ServerPort != "3000" {
		t.Errorf("ServerPort = %q, want %q", config.ServerPort, "3000")
	}
	if config.Properties["app.name"] != "MyApp" {
		t.Errorf("Properties[app.name] = %q, want MyApp", config.Properties["app.name"])
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringProperties — no key (no delimiter) lines are skipped
// ---------------------------------------------------------------------------

func TestParseSpringProperties_NoDelimiterSkipped(t *testing.T) {
	data := []byte(`justakeynodelimiter
server.port=4000
`)
	config, err := ParseSpringProperties(data)
	if err != nil {
		t.Fatalf("ParseSpringProperties error: %v", err)
	}
	if config.Properties["justakeynodelimiter"] != "" {
		t.Errorf("expected line without delimiter to be skipped")
	}
	if config.ServerPort != "4000" {
		t.Errorf("ServerPort = %q, want 4000", config.ServerPort)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringProperties — empty input
// ---------------------------------------------------------------------------

func TestParseSpringProperties_Empty(t *testing.T) {
	config, err := ParseSpringProperties([]byte{})
	if err != nil {
		t.Fatalf("ParseSpringProperties error: %v", err)
	}
	if len(config.Properties) != 0 {
		t.Errorf("Properties = %d, want 0", len(config.Properties))
	}
	if config.Datasource != nil {
		t.Error("Datasource should be nil for empty input")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringProperties — datasource username alone creates struct
// ---------------------------------------------------------------------------

func TestParseSpringProperties_DatasourceUsername(t *testing.T) {
	data := []byte(`spring.datasource.username=sa
`)
	config, err := ParseSpringProperties(data)
	if err != nil {
		t.Fatalf("ParseSpringProperties error: %v", err)
	}
	if config.Datasource == nil {
		t.Fatal("Datasource should not be nil")
	}
	if config.Datasource.Username != "sa" {
		t.Errorf("Datasource.Username = %q, want sa", config.Datasource.Username)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringYAML — basic hierarchy
// ---------------------------------------------------------------------------

func TestParseSpringYAML_Basic(t *testing.T) {
	data := []byte(`server:
  port: 8080
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
  profiles:
    active: test,dev
`)
	config, err := ParseSpringYAML(data)
	if err != nil {
		t.Fatalf("ParseSpringYAML error: %v", err)
	}
	if config.ServerPort != "8080" {
		t.Errorf("ServerPort = %q, want 8080", config.ServerPort)
	}
	if config.Datasource == nil {
		t.Fatal("Datasource should not be nil")
	}
	if config.Datasource.URL != "jdbc:h2:mem:testdb" {
		t.Errorf("Datasource.URL = %q", config.Datasource.URL)
	}
	if config.Datasource.Driver != "org.h2.Driver" {
		t.Errorf("Datasource.Driver = %q", config.Datasource.Driver)
	}
	if config.Datasource.Username != "sa" {
		t.Errorf("Datasource.Username = %q, want sa", config.Datasource.Username)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringYAML — comments and blank lines skipped
// ---------------------------------------------------------------------------

func TestParseSpringYAML_CommentsSkipped(t *testing.T) {
	data := []byte(`# Spring config
server:
  port: 9000
# end
`)
	config, err := ParseSpringYAML(data)
	if err != nil {
		t.Fatalf("ParseSpringYAML error: %v", err)
	}
	if config.ServerPort != "9000" {
		t.Errorf("ServerPort = %q, want 9000", config.ServerPort)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringYAML — flat key-value (no nesting)
// ---------------------------------------------------------------------------

func TestParseSpringYAML_FlatKeyValue(t *testing.T) {
	data := []byte(`app.name: MyService
app.version: 1.0
`)
	config, err := ParseSpringYAML(data)
	if err != nil {
		t.Fatalf("ParseSpringYAML error: %v", err)
	}
	if config.Properties["app.name"] != "MyService" {
		t.Errorf("Properties[app.name] = %q, want MyService", config.Properties["app.name"])
	}
	if config.Properties["app.version"] != "1.0" {
		t.Errorf("Properties[app.version] = %q, want 1.0", config.Properties["app.version"])
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringYAML — empty input
// ---------------------------------------------------------------------------

func TestParseSpringYAML_Empty(t *testing.T) {
	config, err := ParseSpringYAML([]byte{})
	if err != nil {
		t.Fatalf("ParseSpringYAML error: %v", err)
	}
	if len(config.Properties) != 0 {
		t.Errorf("Properties = %d, want 0", len(config.Properties))
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSpringYAML — line without colon is skipped
// ---------------------------------------------------------------------------

func TestParseSpringYAML_NoColonSkipped(t *testing.T) {
	data := []byte(`nokeyvalue
server:
  port: 7070
`)
	config, err := ParseSpringYAML(data)
	if err != nil {
		t.Fatalf("ParseSpringYAML error: %v", err)
	}
	// "nokeyvalue" has no colon and should be skipped
	if _, ok := config.Properties["nokeyvalue"]; ok {
		t.Error("expected line without colon to be skipped")
	}
	if config.ServerPort != "7070" {
		t.Errorf("ServerPort = %q, want 7070", config.ServerPort)
	}
}

// ---------------------------------------------------------------------------
// Test: buildKeyPath — direct unit tests
// ---------------------------------------------------------------------------

func TestBuildKeyPath(t *testing.T) {
	tests := []struct {
		name  string
		stack []stackEntry
		key   string
		want  string
	}{
		{
			name:  "empty stack",
			stack: nil,
			key:   "port",
			want:  "port",
		},
		{
			name:  "one level",
			stack: []stackEntry{{key: "server", indent: 0}},
			key:   "port",
			want:  "server.port",
		},
		{
			name: "two levels",
			stack: []stackEntry{
				{key: "spring", indent: 0},
				{key: "datasource", indent: 2},
			},
			key:  "url",
			want: "spring.datasource.url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildKeyPath(tt.stack, tt.key)
			if got != tt.want {
				t.Errorf("buildKeyPath = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: applySpringProperty — all known keys
// ---------------------------------------------------------------------------

func TestApplySpringProperty_AllKeys(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		check    func(*SpringConfig) bool
		wantDesc string
	}{
		{
			key:      "server.port",
			value:    "8443",
			check:    func(c *SpringConfig) bool { return c.ServerPort == "8443" },
			wantDesc: "ServerPort=8443",
		},
		{
			key:   "spring.datasource.url",
			value: "jdbc:mysql://localhost/db",
			check: func(c *SpringConfig) bool {
				return c.Datasource != nil && c.Datasource.URL == "jdbc:mysql://localhost/db"
			},
			wantDesc: "Datasource.URL",
		},
		{
			key:      "spring.datasource.driver-class-name",
			value:    "com.mysql.Driver",
			check:    func(c *SpringConfig) bool { return c.Datasource != nil && c.Datasource.Driver == "com.mysql.Driver" },
			wantDesc: "Datasource.Driver",
		},
		{
			key:      "spring.datasource.username",
			value:    "root",
			check:    func(c *SpringConfig) bool { return c.Datasource != nil && c.Datasource.Username == "root" },
			wantDesc: "Datasource.Username",
		},
		{
			key:   "spring.profiles.active",
			value: "dev, test",
			check: func(c *SpringConfig) bool {
				return len(c.Profiles) == 2 && c.Profiles[0] == "dev" && c.Profiles[1] == "test"
			},
			wantDesc: "Profiles=[dev test]",
		},
		{
			key:      "unknown.key",
			value:    "value",
			check:    func(c *SpringConfig) bool { return c.ServerPort == "" && c.Datasource == nil },
			wantDesc: "unknown key is ignored",
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantDesc, func(t *testing.T) {
			cfg := &SpringConfig{Properties: make(map[string]string)}
			applySpringProperty(cfg, tt.key, tt.value)
			if !tt.check(cfg) {
				t.Errorf("applySpringProperty(%q, %q) failed check: %s", tt.key, tt.value, tt.wantDesc)
			}
		})
	}
}
