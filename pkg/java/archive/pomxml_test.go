package archive

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Test: ParsePOM — basic happy path
// ---------------------------------------------------------------------------

func TestParsePOM_Basic(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.2.3</version>
  <packaging>jar</packaging>
</project>`)

	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM error: %v", err)
	}
	if info.GroupID != "com.example" {
		t.Errorf("GroupID = %q, want %q", info.GroupID, "com.example")
	}
	if info.ArtifactID != "myapp" {
		t.Errorf("ArtifactID = %q, want %q", info.ArtifactID, "myapp")
	}
	if info.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", info.Version, "1.2.3")
	}
	if info.Packaging != "jar" {
		t.Errorf("Packaging = %q, want %q", info.Packaging, "jar")
	}
}

// ---------------------------------------------------------------------------
// Test: ParsePOM — dependencies
// ---------------------------------------------------------------------------

func TestParsePOM_Dependencies(t *testing.T) {
	data := []byte(`<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
      <scope>compile</scope>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`)

	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM error: %v", err)
	}
	if len(info.Dependencies) != 2 {
		t.Fatalf("Dependencies length = %d, want 2", len(info.Dependencies))
	}
	dep := info.Dependencies[0]
	if dep.GroupID != "org.springframework" {
		t.Errorf("dep[0].GroupID = %q, want %q", dep.GroupID, "org.springframework")
	}
	if dep.ArtifactID != "spring-core" {
		t.Errorf("dep[0].ArtifactID = %q, want %q", dep.ArtifactID, "spring-core")
	}
	if dep.Version != "5.3.0" {
		t.Errorf("dep[0].Version = %q, want %q", dep.Version, "5.3.0")
	}
	if dep.Scope != "compile" {
		t.Errorf("dep[0].Scope = %q, want %q", dep.Scope, "compile")
	}
}

// ---------------------------------------------------------------------------
// Test: ParsePOM — plugins
// ---------------------------------------------------------------------------

func TestParsePOM_Plugins(t *testing.T) {
	data := []byte(`<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0</version>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.8.1</version>
      </plugin>
    </plugins>
  </build>
</project>`)

	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM error: %v", err)
	}
	if len(info.Plugins) != 1 {
		t.Fatalf("Plugins length = %d, want 1", len(info.Plugins))
	}
	p := info.Plugins[0]
	if p.GroupID != "org.apache.maven.plugins" {
		t.Errorf("plugin.GroupID = %q, want %q", p.GroupID, "org.apache.maven.plugins")
	}
	if p.ArtifactID != "maven-compiler-plugin" {
		t.Errorf("plugin.ArtifactID = %q, want %q", p.ArtifactID, "maven-compiler-plugin")
	}
}

// ---------------------------------------------------------------------------
// Test: ParsePOM — properties
// ---------------------------------------------------------------------------

func TestParsePOM_Properties(t *testing.T) {
	data := []byte(`<project>
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0</version>
  <properties>
    <java.version>11</java.version>
    <spring.version>5.3.0</spring.version>
  </properties>
</project>`)

	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM error: %v", err)
	}
	if info.Properties["java.version"] != "11" {
		t.Errorf("Properties[java.version] = %q, want %q", info.Properties["java.version"], "11")
	}
	if info.Properties["spring.version"] != "5.3.0" {
		t.Errorf("Properties[spring.version] = %q, want %q", info.Properties["spring.version"], "5.3.0")
	}
}

// ---------------------------------------------------------------------------
// Test: ParsePOM — parent inheritance (groupId from parent)
// ---------------------------------------------------------------------------

func TestParsePOM_ParentInheritance(t *testing.T) {
	data := []byte(`<project>
  <parent>
    <groupId>com.parent</groupId>
    <artifactId>parent-pom</artifactId>
    <version>2.0.0</version>
  </parent>
  <artifactId>child-module</artifactId>
</project>`)

	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM error: %v", err)
	}
	// groupId should be inherited from parent
	if info.GroupID != "com.parent" {
		t.Errorf("GroupID (inherited) = %q, want %q", info.GroupID, "com.parent")
	}
	// version should be inherited from parent
	if info.Version != "2.0.0" {
		t.Errorf("Version (inherited) = %q, want %q", info.Version, "2.0.0")
	}
}

// ---------------------------------------------------------------------------
// Test: ParsePOM — own values take precedence over parent
// ---------------------------------------------------------------------------

func TestParsePOM_OwnOverridesParent(t *testing.T) {
	data := []byte(`<project>
  <parent>
    <groupId>com.parent</groupId>
    <artifactId>parent-pom</artifactId>
    <version>2.0.0</version>
  </parent>
  <groupId>com.child</groupId>
  <artifactId>child-module</artifactId>
  <version>3.0.0</version>
</project>`)

	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM error: %v", err)
	}
	if info.GroupID != "com.child" {
		t.Errorf("GroupID = %q, want %q (own should override parent)", info.GroupID, "com.child")
	}
	if info.Version != "3.0.0" {
		t.Errorf("Version = %q, want %q (own should override parent)", info.Version, "3.0.0")
	}
}

// ---------------------------------------------------------------------------
// Test: ParsePOM — invalid XML
// ---------------------------------------------------------------------------

func TestParsePOM_InvalidXML(t *testing.T) {
	_, err := ParsePOM([]byte(`<project><unclosed>`))
	if err == nil {
		t.Error("ParsePOM: expected error for invalid XML, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: ParsePOM — empty project
// ---------------------------------------------------------------------------

func TestParsePOM_Empty(t *testing.T) {
	data := []byte(`<project></project>`)
	info, err := ParsePOM(data)
	if err != nil {
		t.Fatalf("ParsePOM error: %v", err)
	}
	if info.GroupID != "" {
		t.Errorf("GroupID = %q, want empty", info.GroupID)
	}
	if len(info.Dependencies) != 0 {
		t.Errorf("Dependencies = %d, want 0", len(info.Dependencies))
	}
	if info.Properties == nil {
		t.Error("Properties map should not be nil")
	}
}
