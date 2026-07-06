package archive

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test: ParseAppXML — all module types
// ---------------------------------------------------------------------------

func TestParseAppXML_AllModuleTypes(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<application>
  <module>
    <web>
      <web-uri>webapp.war</web-uri>
      <context-root>/app</context-root>
    </web>
  </module>
  <module>
    <ejb>ejb-module.jar</ejb>
  </module>
  <module>
    <java>util.jar</java>
  </module>
  <module>
    <connector>adapter.rar</connector>
  </module>
  <security-role>
    <role-name>admin</role-name>
    <description>Administrator role</description>
  </security-role>
  <security-role>
    <role-name>user</role-name>
  </security-role>
</application>`)

	info, err := ParseAppXML(data)
	if err != nil {
		t.Fatalf("ParseAppXML error: %v", err)
	}

	if len(info.Modules) != 4 {
		t.Fatalf("Modules length = %d, want 4", len(info.Modules))
	}

	// Web module
	web := info.Modules[0]
	if web.Type != "web" {
		t.Errorf("module[0].Type = %q, want %q", web.Type, "web")
	}
	if web.URI != "webapp.war" {
		t.Errorf("module[0].URI = %q, want %q", web.URI, "webapp.war")
	}
	if web.ContextRoot != "/app" {
		t.Errorf("module[0].ContextRoot = %q, want %q", web.ContextRoot, "/app")
	}

	// EJB module
	ejb := info.Modules[1]
	if ejb.Type != "ejb" {
		t.Errorf("module[1].Type = %q, want %q", ejb.Type, "ejb")
	}
	if ejb.URI != "ejb-module.jar" {
		t.Errorf("module[1].URI = %q, want %q", ejb.URI, "ejb-module.jar")
	}

	// Java module
	jm := info.Modules[2]
	if jm.Type != "java" {
		t.Errorf("module[2].Type = %q, want %q", jm.Type, "java")
	}
	if jm.URI != "util.jar" {
		t.Errorf("module[2].URI = %q, want %q", jm.URI, "util.jar")
	}

	// Connector module
	conn := info.Modules[3]
	if conn.Type != "connector" {
		t.Errorf("module[3].Type = %q, want %q", conn.Type, "connector")
	}
	if conn.URI != "adapter.rar" {
		t.Errorf("module[3].URI = %q, want %q", conn.URI, "adapter.rar")
	}

	// Security roles
	if len(info.SecurityRoles) != 2 {
		t.Fatalf("SecurityRoles length = %d, want 2", len(info.SecurityRoles))
	}
	if info.SecurityRoles[0].Name != "admin" {
		t.Errorf("role[0].Name = %q, want %q", info.SecurityRoles[0].Name, "admin")
	}
	if info.SecurityRoles[0].Description != "Administrator role" {
		t.Errorf("role[0].Description = %q, want %q", info.SecurityRoles[0].Description, "Administrator role")
	}
	if info.SecurityRoles[1].Name != "user" {
		t.Errorf("role[1].Name = %q, want %q", info.SecurityRoles[1].Name, "user")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseAppXML — empty document
// ---------------------------------------------------------------------------

func TestParseAppXML_Empty(t *testing.T) {
	data := []byte(`<application/>`)
	info, err := ParseAppXML(data)
	if err != nil {
		t.Fatalf("ParseAppXML error: %v", err)
	}
	if len(info.Modules) != 0 {
		t.Errorf("Modules length = %d, want 0", len(info.Modules))
	}
	if len(info.SecurityRoles) != 0 {
		t.Errorf("SecurityRoles length = %d, want 0", len(info.SecurityRoles))
	}
}

// ---------------------------------------------------------------------------
// Test: ParseAppXML — invalid XML
// ---------------------------------------------------------------------------

func TestParseAppXML_InvalidXML(t *testing.T) {
	_, err := ParseAppXML([]byte(`<application><unclosed>`))
	if err == nil {
		t.Error("ParseAppXML: expected error for invalid XML, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: ParseAppXML — web module only
// ---------------------------------------------------------------------------

func TestParseAppXML_WebModuleOnly(t *testing.T) {
	data := []byte(`<application>
  <module>
    <web>
      <web-uri>myapp.war</web-uri>
      <context-root>/myapp</context-root>
    </web>
  </module>
</application>`)
	info, err := ParseAppXML(data)
	if err != nil {
		t.Fatalf("ParseAppXML error: %v", err)
	}
	if len(info.Modules) != 1 {
		t.Fatalf("Modules = %d, want 1", len(info.Modules))
	}
	m := info.Modules[0]
	if m.Type != "web" || m.URI != "myapp.war" || m.ContextRoot != "/myapp" {
		t.Errorf("module = %+v, want type=web uri=myapp.war contextRoot=/myapp", m)
	}
}
