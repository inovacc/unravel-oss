package archive

import (
	"os"
	"testing"
)

func TestParseWebXML(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantServlets  int
		wantFilters   int
		wantListeners int
		wantMappings  int
		wantErr       bool
	}{
		{
			name: "basic web.xml",
			input: `<?xml version="1.0"?>
<web-app>
    <servlet>
        <servlet-name>Hello</servlet-name>
        <servlet-class>com.example.HelloServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>Hello</servlet-name>
        <url-pattern>/hello</url-pattern>
    </servlet-mapping>
    <filter>
        <filter-name>Auth</filter-name>
        <filter-class>com.example.AuthFilter</filter-class>
    </filter>
    <listener>
        <listener-class>com.example.AppListener</listener-class>
    </listener>
</web-app>`,
			wantServlets:  1,
			wantFilters:   1,
			wantListeners: 1,
			wantMappings:  1,
		},
		{
			name: "with init params",
			input: `<?xml version="1.0"?>
<web-app>
    <servlet>
        <servlet-name>Config</servlet-name>
        <servlet-class>com.example.ConfigServlet</servlet-class>
        <init-param>
            <param-name>key1</param-name>
            <param-value>value1</param-value>
        </init-param>
        <init-param>
            <param-name>key2</param-name>
            <param-value>value2</param-value>
        </init-param>
    </servlet>
</web-app>`,
			wantServlets: 1,
		},
		{
			name:    "invalid xml",
			input:   "not xml at all",
			wantErr: true,
		},
		{
			name:  "empty web-app",
			input: `<?xml version="1.0"?><web-app></web-app>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseWebXML([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseWebXML() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if len(info.Servlets) != tt.wantServlets {
				t.Errorf("Servlets = %d, want %d", len(info.Servlets), tt.wantServlets)
			}

			if len(info.Filters) != tt.wantFilters {
				t.Errorf("Filters = %d, want %d", len(info.Filters), tt.wantFilters)
			}

			if len(info.Listeners) != tt.wantListeners {
				t.Errorf("Listeners = %d, want %d", len(info.Listeners), tt.wantListeners)
			}

			if len(info.ServletMappings) != tt.wantMappings {
				t.Errorf("ServletMappings = %d, want %d", len(info.ServletMappings), tt.wantMappings)
			}
		})
	}
}

func TestParseWebXMLInitParams(t *testing.T) {
	input := `<?xml version="1.0"?>
<web-app>
    <servlet>
        <servlet-name>Config</servlet-name>
        <servlet-class>com.example.ConfigServlet</servlet-class>
        <init-param>
            <param-name>configPath</param-name>
            <param-value>/WEB-INF/config.xml</param-value>
        </init-param>
    </servlet>
</web-app>`

	info, err := ParseWebXML([]byte(input))
	if err != nil {
		t.Fatalf("ParseWebXML() error: %v", err)
	}

	if len(info.Servlets) != 1 {
		t.Fatalf("expected 1 servlet, got %d", len(info.Servlets))
	}

	servlet := info.Servlets[0]
	if servlet.Name != "Config" {
		t.Errorf("Name = %q, want %q", servlet.Name, "Config")
	}

	if servlet.Class != "com.example.ConfigServlet" {
		t.Errorf("Class = %q, want %q", servlet.Class, "com.example.ConfigServlet")
	}

	if servlet.InitParams["configPath"] != "/WEB-INF/config.xml" {
		t.Errorf("InitParams[configPath] = %q, want %q", servlet.InitParams["configPath"], "/WEB-INF/config.xml")
	}
}

func TestParseWebXMLFromFile(t *testing.T) {
	data, err := os.ReadFile("../../testdata/webxml/basic.xml")
	if err != nil {
		t.Skipf("test fixture not available: %v", err)
	}

	info, err := ParseWebXML(data)
	if err != nil {
		t.Fatalf("ParseWebXML() error: %v", err)
	}

	if len(info.Servlets) != 2 {
		t.Errorf("Servlets = %d, want 2", len(info.Servlets))
	}

	if len(info.Filters) != 1 {
		t.Errorf("Filters = %d, want 1", len(info.Filters))
	}

	if len(info.Listeners) != 1 {
		t.Errorf("Listeners = %d, want 1", len(info.Listeners))
	}

	if len(info.WelcomeFiles) != 2 {
		t.Errorf("WelcomeFiles = %d, want 2", len(info.WelcomeFiles))
	}

	if len(info.ErrorPages) != 2 {
		t.Errorf("ErrorPages = %d, want 2", len(info.ErrorPages))
	}

	if len(info.SecurityConstraints) != 1 {
		t.Errorf("SecurityConstraints = %d, want 1", len(info.SecurityConstraints))
	}

	if info.ContextParams["env"] != "production" {
		t.Errorf("ContextParams[env] = %q, want %q", info.ContextParams["env"], "production")
	}
}
