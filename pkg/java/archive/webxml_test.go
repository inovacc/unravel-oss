package archive

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test: ParseWebXML — full document
// ---------------------------------------------------------------------------

func TestParseWebXML_Full(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<web-app>
  <servlet>
    <servlet-name>HelloServlet</servlet-name>
    <servlet-class>com.example.HelloServlet</servlet-class>
    <init-param>
      <param-name>greeting</param-name>
      <param-value>Hello World</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>HelloServlet</servlet-name>
    <url-pattern>/hello</url-pattern>
  </servlet-mapping>
  <filter>
    <filter-name>AuthFilter</filter-name>
    <filter-class>com.example.AuthFilter</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>AuthFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <listener>
    <listener-class>com.example.AppListener</listener-class>
  </listener>
  <context-param>
    <param-name>env</param-name>
    <param-value>production</param-value>
  </context-param>
  <error-page>
    <error-code>404</error-code>
    <location>/notfound.html</location>
  </error-page>
  <error-page>
    <exception-type>java.lang.Exception</exception-type>
    <location>/error.html</location>
  </error-page>
  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>Protected</web-resource-name>
      <url-pattern>/admin/*</url-pattern>
      <http-method>GET</http-method>
      <http-method>POST</http-method>
    </web-resource-collection>
    <auth-constraint>
      <role-name>admin</role-name>
    </auth-constraint>
  </security-constraint>
</web-app>`)

	info, err := ParseWebXML(data)
	if err != nil {
		t.Fatalf("ParseWebXML error: %v", err)
	}

	// Servlets
	if len(info.Servlets) != 1 {
		t.Fatalf("Servlets length = %d, want 1", len(info.Servlets))
	}
	s := info.Servlets[0]
	if s.Name != "HelloServlet" {
		t.Errorf("servlet.Name = %q, want %q", s.Name, "HelloServlet")
	}
	if s.Class != "com.example.HelloServlet" {
		t.Errorf("servlet.Class = %q, want %q", s.Class, "com.example.HelloServlet")
	}
	if s.LoadOnStartup != 1 {
		t.Errorf("servlet.LoadOnStartup = %d, want 1", s.LoadOnStartup)
	}
	if s.InitParams["greeting"] != "Hello World" {
		t.Errorf("servlet.InitParams[greeting] = %q, want %q", s.InitParams["greeting"], "Hello World")
	}

	// Servlet mappings
	if len(info.ServletMappings) != 1 {
		t.Fatalf("ServletMappings length = %d, want 1", len(info.ServletMappings))
	}
	if info.ServletMappings[0].URLPattern != "/hello" {
		t.Errorf("ServletMapping.URLPattern = %q, want %q", info.ServletMappings[0].URLPattern, "/hello")
	}

	// Filters
	if len(info.Filters) != 1 {
		t.Fatalf("Filters length = %d, want 1", len(info.Filters))
	}
	if info.Filters[0].Name != "AuthFilter" {
		t.Errorf("filter.Name = %q, want %q", info.Filters[0].Name, "AuthFilter")
	}

	// Filter mappings
	if len(info.FilterMappings) != 1 {
		t.Fatalf("FilterMappings length = %d, want 1", len(info.FilterMappings))
	}
	if info.FilterMappings[0].URLPattern != "/*" {
		t.Errorf("FilterMapping.URLPattern = %q, want %q", info.FilterMappings[0].URLPattern, "/*")
	}

	// Listeners
	if len(info.Listeners) != 1 {
		t.Fatalf("Listeners length = %d, want 1", len(info.Listeners))
	}
	if info.Listeners[0].Class != "com.example.AppListener" {
		t.Errorf("listener.Class = %q, want %q", info.Listeners[0].Class, "com.example.AppListener")
	}

	// Context params
	if info.ContextParams["env"] != "production" {
		t.Errorf("ContextParams[env] = %q, want %q", info.ContextParams["env"], "production")
	}

	// Error pages
	if len(info.ErrorPages) != 2 {
		t.Fatalf("ErrorPages length = %d, want 2", len(info.ErrorPages))
	}
	ep0 := info.ErrorPages[0]
	if ep0.ErrorCode != 404 {
		t.Errorf("error-page[0].ErrorCode = %d, want 404", ep0.ErrorCode)
	}
	if ep0.Location != "/notfound.html" {
		t.Errorf("error-page[0].Location = %q, want %q", ep0.Location, "/notfound.html")
	}
	ep1 := info.ErrorPages[1]
	if ep1.ExceptionType != "java.lang.Exception" {
		t.Errorf("error-page[1].ExceptionType = %q, want %q", ep1.ExceptionType, "java.lang.Exception")
	}

	// Welcome files
	if len(info.WelcomeFiles) != 2 {
		t.Fatalf("WelcomeFiles length = %d, want 2", len(info.WelcomeFiles))
	}

	// Security constraints
	if len(info.SecurityConstraints) != 1 {
		t.Fatalf("SecurityConstraints length = %d, want 1", len(info.SecurityConstraints))
	}
	sc := info.SecurityConstraints[0]
	if sc.WebResourceName != "Protected" {
		t.Errorf("sc.WebResourceName = %q, want %q", sc.WebResourceName, "Protected")
	}
	if len(sc.URLPatterns) != 1 || sc.URLPatterns[0] != "/admin/*" {
		t.Errorf("sc.URLPatterns = %v, want [/admin/*]", sc.URLPatterns)
	}
	if len(sc.HTTPMethods) != 2 {
		t.Errorf("sc.HTTPMethods = %v, want [GET POST]", sc.HTTPMethods)
	}
	if len(sc.AuthRoles) != 1 || sc.AuthRoles[0] != "admin" {
		t.Errorf("sc.AuthRoles = %v, want [admin]", sc.AuthRoles)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseWebXML — empty document
// ---------------------------------------------------------------------------

func TestParseWebXML_Empty(t *testing.T) {
	data := []byte(`<web-app/>`)
	info, err := ParseWebXML(data)
	if err != nil {
		t.Fatalf("ParseWebXML error: %v", err)
	}
	if len(info.Servlets) != 0 {
		t.Errorf("Servlets length = %d, want 0", len(info.Servlets))
	}
	if info.ContextParams == nil {
		t.Error("ContextParams map should not be nil")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseWebXML — invalid XML
// ---------------------------------------------------------------------------

func TestParseWebXML_InvalidXML(t *testing.T) {
	_, err := ParseWebXML([]byte(`<web-app><unclosed>`))
	if err == nil {
		t.Error("ParseWebXML: expected error for invalid XML, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseWebXML — servlet with multiple init params
// ---------------------------------------------------------------------------

func TestParseWebXML_MultipleInitParams(t *testing.T) {
	data := []byte(`<web-app>
  <servlet>
    <servlet-name>MyServlet</servlet-name>
    <servlet-class>com.example.MyServlet</servlet-class>
    <init-param>
      <param-name>key1</param-name>
      <param-value>val1</param-value>
    </init-param>
    <init-param>
      <param-name>key2</param-name>
      <param-value>val2</param-value>
    </init-param>
  </servlet>
</web-app>`)
	info, err := ParseWebXML(data)
	if err != nil {
		t.Fatalf("ParseWebXML error: %v", err)
	}
	if len(info.Servlets) != 1 {
		t.Fatalf("Servlets = %d, want 1", len(info.Servlets))
	}
	s := info.Servlets[0]
	if len(s.InitParams) != 2 {
		t.Fatalf("InitParams length = %d, want 2", len(s.InitParams))
	}
	if s.InitParams["key1"] != "val1" {
		t.Errorf("InitParams[key1] = %q, want val1", s.InitParams["key1"])
	}
	if s.InitParams["key2"] != "val2" {
		t.Errorf("InitParams[key2] = %q, want val2", s.InitParams["key2"])
	}
}
