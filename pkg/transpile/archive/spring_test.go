package archive

import (
	"testing"
)

func TestParseSpringProperties(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPort  string
		wantDSURL string
		wantProps int
		wantErr   bool
	}{
		{
			name: "basic properties",
			input: `server.port=8080
spring.datasource.url=jdbc:postgresql://localhost:5432/mydb
spring.datasource.username=user
spring.datasource.driver-class-name=org.postgresql.Driver
spring.profiles.active=dev,local
app.name=MyApp
`,
			wantPort:  "8080",
			wantDSURL: "jdbc:postgresql://localhost:5432/mydb",
			wantProps: 6,
		},
		{
			name: "with comments",
			input: `# Server configuration
server.port=9090
# Database
! This is also a comment
spring.datasource.url=jdbc:mysql://localhost/db
`,
			wantPort:  "9090",
			wantDSURL: "jdbc:mysql://localhost/db",
			wantProps: 2,
		},
		{
			name: "colon delimiter",
			input: `server.port:8443
app.name:test
`,
			wantPort:  "8443",
			wantProps: 2,
		},
		{
			name:      "empty",
			input:     "",
			wantProps: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseSpringProperties([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSpringProperties() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if config.ServerPort != tt.wantPort {
				t.Errorf("ServerPort = %q, want %q", config.ServerPort, tt.wantPort)
			}

			if tt.wantDSURL != "" {
				if config.Datasource == nil {
					t.Error("expected Datasource to be set")
				} else if config.Datasource.URL != tt.wantDSURL {
					t.Errorf("Datasource.URL = %q, want %q", config.Datasource.URL, tt.wantDSURL)
				}
			}

			if len(config.Properties) != tt.wantProps {
				t.Errorf("Properties count = %d, want %d", len(config.Properties), tt.wantProps)
			}
		})
	}
}

func TestParseSpringProfiles(t *testing.T) {
	input := `spring.profiles.active=dev,staging,prod`

	config, err := ParseSpringProperties([]byte(input))
	if err != nil {
		t.Fatalf("ParseSpringProperties() error: %v", err)
	}

	if len(config.Profiles) != 3 {
		t.Fatalf("Profiles count = %d, want 3", len(config.Profiles))
	}

	expected := []string{"dev", "staging", "prod"}
	for i, want := range expected {
		if config.Profiles[i] != want {
			t.Errorf("Profiles[%d] = %q, want %q", i, config.Profiles[i], want)
		}
	}
}

func TestParseSpringYAML(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPort  string
		wantDSURL string
		wantProps int
	}{
		{
			name: "basic yaml",
			input: `server:
  port: 8080
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/mydb
    username: user
`,
			wantPort:  "8080",
			wantDSURL: "jdbc:postgresql://localhost:5432/mydb",
			wantProps: 3,
		},
		{
			name: "with comments",
			input: `# Server config
server:
  port: 9090
`,
			wantPort:  "9090",
			wantProps: 1,
		},
		{
			name:      "empty",
			input:     "",
			wantProps: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseSpringYAML([]byte(tt.input))
			if err != nil {
				t.Fatalf("ParseSpringYAML() error: %v", err)
			}

			if config.ServerPort != tt.wantPort {
				t.Errorf("ServerPort = %q, want %q", config.ServerPort, tt.wantPort)
			}

			if tt.wantDSURL != "" {
				if config.Datasource == nil {
					t.Error("expected Datasource to be set")
				} else if config.Datasource.URL != tt.wantDSURL {
					t.Errorf("Datasource.URL = %q, want %q", config.Datasource.URL, tt.wantDSURL)
				}
			}

			if len(config.Properties) != tt.wantProps {
				t.Errorf("Properties count = %d, want %d", len(config.Properties), tt.wantProps)
			}
		})
	}
}
