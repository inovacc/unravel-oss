package archive

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeJavaFile writes content to a .java file inside dir/rel and returns the relative path.
func writeJavaFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write java file: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — servlet detection
// ---------------------------------------------------------------------------

func TestDetectPatterns_Servlets(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantHit bool
	}{
		{
			name:    "extends HttpServlet",
			source:  `public class MyServlet extends HttpServlet { }`,
			wantHit: true,
		},
		{
			name:    "implements Filter",
			source:  `public class MyFilter implements Filter { }`,
			wantHit: true,
		},
		{
			name:    "implements ServletContextListener",
			source:  `public class App implements ServletContextListener { }`,
			wantHit: true,
		},
		{
			name:    "implements HttpSessionListener",
			source:  `public class Sess implements HttpSessionListener { }`,
			wantHit: true,
		},
		{
			name:    "@WebServlet annotation",
			source:  `@WebServlet("/api") public class Api { }`,
			wantHit: true,
		},
		{
			name:    "@WebFilter annotation",
			source:  `@WebFilter("/*") public class F { }`,
			wantHit: true,
		},
		{
			name:    "@WebListener annotation",
			source:  `@WebListener public class L { }`,
			wantHit: true,
		},
		{
			name:    "no servlet indicators",
			source:  `public class Plain { void hello() {} }`,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			rel := "com/example/Test.java"
			writeJavaFile(t, dir, rel, tt.source)

			info := &ArchiveInfo{
				ExtractDir: dir,
				JavaFiles:  []string{rel},
			}
			report := DetectPatterns(info)
			if report.HasServlets != tt.wantHit {
				t.Errorf("HasServlets = %v, want %v (source: %q)", report.HasServlets, tt.wantHit, tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — EJB detection
// ---------------------------------------------------------------------------

func TestDetectPatterns_EJB(t *testing.T) {
	dir := t.TempDir()
	source := `
@Stateless
public class OrderService {
    @Stateful
    private SessionBean bean;
    @Singleton
    public static void init() {}
    @MessageDriven
    public void onMessage(Message m) {}
    @Schedule(second="0", minute="0", hour="6")
    public void morning() {}
    @EJB
    private RemoteService remote;
}
`
	writeJavaFile(t, dir, "OrderService.java", source)

	info := &ArchiveInfo{
		ExtractDir: dir,
		JavaFiles:  []string{"OrderService.java"},
	}
	report := DetectPatterns(info)

	if !report.HasEJB {
		t.Error("HasEJB should be true")
	}
	wantTypes := map[string]bool{
		"@Stateless":     true,
		"@Stateful":      true,
		"@Singleton":     true,
		"@MessageDriven": true,
		"@Schedule":      true,
		"@EJB":           true,
	}
	for _, et := range report.EJBTypes {
		if !wantTypes[et] {
			t.Errorf("unexpected EJBType %q", et)
		}
		delete(wantTypes, et)
	}
	for remaining := range wantTypes {
		t.Errorf("missing EJBType %q", remaining)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — EJB deduplication
// ---------------------------------------------------------------------------

func TestDetectPatterns_EJB_Dedup(t *testing.T) {
	dir := t.TempDir()
	source := `
@Stateless
public class A {}
`
	writeJavaFile(t, dir, "A.java", source)
	writeJavaFile(t, dir, "B.java", source) // same annotation in another file

	info := &ArchiveInfo{
		ExtractDir: dir,
		JavaFiles:  []string{"A.java", "B.java"},
	}
	report := DetectPatterns(info)

	count := 0
	for _, et := range report.EJBTypes {
		if et == "@Stateless" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("@Stateless appears %d times in EJBTypes, want 1 (dedup)", count)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — JNDI detection
// ---------------------------------------------------------------------------

func TestDetectPatterns_JNDI(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantHit bool
		lookups []string
	}{
		{
			name:    "InitialContext usage",
			source:  `Context ctx = new InitialContext(); Object obj = ctx.lookup("java:comp/env/jdbc/myDS");`,
			wantHit: true,
			lookups: []string{"java:comp/env/jdbc/myDS"},
		},
		{
			name:    "@Resource annotation",
			source:  `@Resource private DataSource ds;`,
			wantHit: true,
			lookups: nil,
		},
		{
			name:    "Context.lookup",
			source:  `obj = Context.lookup("java:global/myBean");`,
			wantHit: true,
			lookups: []string{"java:global/myBean"},
		},
		{
			name:    "no JNDI",
			source:  `public class Plain { }`,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeJavaFile(t, dir, "Test.java", tt.source)

			info := &ArchiveInfo{
				ExtractDir: dir,
				JavaFiles:  []string{"Test.java"},
			}
			report := DetectPatterns(info)

			if report.HasJNDI != tt.wantHit {
				t.Errorf("HasJNDI = %v, want %v", report.HasJNDI, tt.wantHit)
			}
			for _, wl := range tt.lookups {
				found := slices.Contains(report.JNDILookups, wl)
				if !found {
					t.Errorf("JNDI lookup %q not found in %v", wl, report.JNDILookups)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — JNDI lookup deduplication
// ---------------------------------------------------------------------------

func TestDetectPatterns_JNDI_DedupLookups(t *testing.T) {
	dir := t.TempDir()
	// Same lookup expression appears twice in the file
	source := `
Context ctx = new InitialContext();
Object a = ctx.lookup("java:comp/env/ds");
Object b = ctx.lookup("java:comp/env/ds");
`
	writeJavaFile(t, dir, "Dup.java", source)

	info := &ArchiveInfo{
		ExtractDir: dir,
		JavaFiles:  []string{"Dup.java"},
	}
	report := DetectPatterns(info)

	count := 0
	for _, l := range report.JNDILookups {
		if l == "java:comp/env/ds" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("lookup appears %d times, want 1 (dedup)", count)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — ClassLoader detection
// ---------------------------------------------------------------------------

func TestDetectPatterns_ClassLoading(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantHit bool
	}{
		{
			name:    "ClassLoader",
			source:  `ClassLoader cl = getClass().getClassLoader();`,
			wantHit: true,
		},
		{
			name:    "Class.forName",
			source:  `Class<?> c = Class.forName("com.example.Plugin");`,
			wantHit: true,
		},
		{
			name:    "getClassLoader",
			source:  `Thread.currentThread().getContextClassLoader().getClassLoader();`,
			wantHit: true,
		},
		{
			name:    "loadClass",
			source:  `cl.loadClass("com.example.Foo");`,
			wantHit: true,
		},
		{
			name:    "URLClassLoader",
			source:  `URLClassLoader ucl = new URLClassLoader(urls);`,
			wantHit: true,
		},
		{
			name:    "ServiceLoader",
			source:  `ServiceLoader<Spi> loader = ServiceLoader.load(Spi.class);`,
			wantHit: true,
		},
		{
			name:    "none",
			source:  `public class Plain {}`,
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeJavaFile(t, dir, "Test.java", tt.source)

			info := &ArchiveInfo{
				ExtractDir: dir,
				JavaFiles:  []string{"Test.java"},
			}
			report := DetectPatterns(info)

			if report.HasClassLoading != tt.wantHit {
				t.Errorf("HasClassLoading = %v, want %v", report.HasClassLoading, tt.wantHit)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — javax/jakarta annotations
// ---------------------------------------------------------------------------

func TestDetectPatterns_Annotations(t *testing.T) {
	dir := t.TempDir()
	source := `
import javax.persistence.Entity;
import jakarta.inject.Inject;
@javax.persistence.Entity
public class MyEntity {
    @jakarta.inject.Inject
    private Service svc;
}
`
	writeJavaFile(t, dir, "MyEntity.java", source)

	info := &ArchiveInfo{
		ExtractDir: dir,
		JavaFiles:  []string{"MyEntity.java"},
	}
	report := DetectPatterns(info)

	if len(report.Annotations) == 0 {
		t.Error("expected Annotations to be non-empty")
	}
	found := map[string]bool{}
	for _, ann := range report.Annotations {
		found[ann] = true
	}
	if !found["@javax.persistence.Entity"] {
		t.Errorf("expected @javax.persistence.Entity in annotations, got %v", report.Annotations)
	}
	if !found["@jakarta.inject.Inject"] {
		t.Errorf("expected @jakarta.inject.Inject in annotations, got %v", report.Annotations)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — annotation deduplication across files
// ---------------------------------------------------------------------------

func TestDetectPatterns_Annotations_Dedup(t *testing.T) {
	dir := t.TempDir()
	source := `@javax.persistence.Entity public class A {}`
	writeJavaFile(t, dir, "A.java", source)
	writeJavaFile(t, dir, "B.java", source)

	info := &ArchiveInfo{
		ExtractDir: dir,
		JavaFiles:  []string{"A.java", "B.java"},
	}
	report := DetectPatterns(info)

	count := 0
	for _, ann := range report.Annotations {
		if ann == "@javax.persistence.Entity" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("@javax.persistence.Entity appears %d times, want 1 (dedup)", count)
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — web.xml servlet path
// ---------------------------------------------------------------------------

func TestDetectPatterns_WebXMLServlets(t *testing.T) {
	// No Java files, but WebXML has servlets — HasServlets should be true
	info := &ArchiveInfo{
		ExtractDir: t.TempDir(),
		JavaFiles:  nil,
		WebXML: &WebXMLInfo{
			Servlets: []*ServletInfo{
				{Name: "S", Class: "com.S"},
			},
		},
	}
	report := DetectPatterns(info)
	if !report.HasServlets {
		t.Error("HasServlets should be true when WebXML has servlets")
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — web.xml filters path
// ---------------------------------------------------------------------------

func TestDetectPatterns_WebXMLFilters(t *testing.T) {
	info := &ArchiveInfo{
		ExtractDir: t.TempDir(),
		JavaFiles:  nil,
		WebXML: &WebXMLInfo{
			Filters: []*FilterInfo{
				{Name: "F", Class: "com.F"},
			},
		},
	}
	report := DetectPatterns(info)
	if !report.HasServlets {
		t.Error("HasServlets should be true when WebXML has filters")
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — unreadable Java file is skipped gracefully
// ---------------------------------------------------------------------------

func TestDetectPatterns_SkipsUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	// A non-existent file in JavaFiles list — should not panic or error
	info := &ArchiveInfo{
		ExtractDir: dir,
		JavaFiles:  []string{"nonexistent/Missing.java"},
	}
	// Should not panic
	report := DetectPatterns(info)
	if report == nil {
		t.Error("DetectPatterns returned nil")
	}
}

// ---------------------------------------------------------------------------
// Test: DetectPatterns — empty ArchiveInfo
// ---------------------------------------------------------------------------

func TestDetectPatterns_Empty(t *testing.T) {
	info := &ArchiveInfo{
		ExtractDir: t.TempDir(),
	}
	report := DetectPatterns(info)
	if report.HasServlets || report.HasEJB || report.HasJNDI || report.HasClassLoading {
		t.Error("all flags should be false for empty ArchiveInfo")
	}
}

// ---------------------------------------------------------------------------
// Test: dedup — helper function
// ---------------------------------------------------------------------------

func TestDedup(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "no duplicates",
			input: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "with duplicates",
			input: []string{"a", "b", "a", "c", "b"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "all same",
			input: []string{"x", "x", "x"},
			want:  []string{"x"},
		},
		{
			name:  "empty",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "whitespace trimming",
			input: []string{" hello ", "hello", "world "},
			want:  []string{"hello", "world"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedup(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("dedup(%v) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("dedup[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
