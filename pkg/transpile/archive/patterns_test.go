package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectPatterns(t *testing.T) {
	dir := t.TempDir()

	// Create a servlet Java file
	servletDir := filepath.Join(dir, "com", "example")
	if err := os.MkdirAll(servletDir, 0o755); err != nil {
		t.Fatal(err)
	}

	servletCode := `package com.example;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        resp.getWriter().println("Hello");
    }
}
`
	if err := os.WriteFile(filepath.Join(servletDir, "MyServlet.java"), []byte(servletCode), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create an EJB Java file
	ejbCode := `package com.example;
import javax.ejb.Stateless;
import javax.ejb.EJB;

@Stateless
public class MyService {
    @EJB
    private AnotherService other;

    public String doWork() {
        return "result";
    }
}
`
	if err := os.WriteFile(filepath.Join(servletDir, "MyService.java"), []byte(ejbCode), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a JNDI Java file
	jndiCode := `package com.example;
import javax.naming.InitialContext;
import javax.naming.Context;

public class JndiLookup {
    public Object getResource() throws Exception {
        Context ctx = new InitialContext();
        return ctx.lookup("java:comp/env/jdbc/MyDB");
    }
}
`
	if err := os.WriteFile(filepath.Join(servletDir, "JndiLookup.java"), []byte(jndiCode), 0o644); err != nil {
		t.Fatal(err)
	}

	info := &ArchiveInfo{
		ExtractDir: dir,
		JavaFiles: []string{
			"com/example/MyServlet.java",
			"com/example/MyService.java",
			"com/example/JndiLookup.java",
		},
	}

	report := DetectPatterns(info)

	if !report.HasServlets {
		t.Error("expected HasServlets = true")
	}

	if !report.HasEJB {
		t.Error("expected HasEJB = true")
	}

	if !report.HasJNDI {
		t.Error("expected HasJNDI = true")
	}

	if len(report.EJBTypes) == 0 {
		t.Error("expected EJB types to be detected")
	}

	if len(report.JNDILookups) == 0 {
		t.Error("expected JNDI lookups to be detected")
	}
}

func TestDetectPatternsServletFromWebXML(t *testing.T) {
	dir := t.TempDir()

	info := &ArchiveInfo{
		ExtractDir: dir,
		WebXML: &WebXMLInfo{
			Servlets: []*ServletInfo{
				{Name: "Hello", Class: "com.example.HelloServlet"},
			},
		},
	}

	report := DetectPatterns(info)

	if !report.HasServlets {
		t.Error("expected HasServlets = true from web.xml")
	}
}

func TestDetectPatternsEmpty(t *testing.T) {
	dir := t.TempDir()

	info := &ArchiveInfo{
		ExtractDir: dir,
	}

	report := DetectPatterns(info)

	if report.HasServlets {
		t.Error("expected HasServlets = false")
	}

	if report.HasEJB {
		t.Error("expected HasEJB = false")
	}

	if report.HasJNDI {
		t.Error("expected HasJNDI = false")
	}
}
