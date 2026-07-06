package archive

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PatternReport describes enterprise Java patterns detected in the source.
type PatternReport struct {
	HasServlets     bool     `json:"has_servlets"`
	HasEJB          bool     `json:"has_ejb"`
	HasJNDI         bool     `json:"has_jndi"`
	HasClassLoading bool     `json:"has_class_loading"`
	EJBTypes        []string `json:"ejb_types,omitempty"`
	JNDILookups     []string `json:"jndi_lookups,omitempty"`
	Annotations     []string `json:"annotations,omitempty"`
}

// Pattern detection regexes.
var (
	servletRe     = regexp.MustCompile(`(?:extends\s+HttpServlet|implements\s+(?:Filter|ServletContextListener|HttpSessionListener)|@WebServlet|@WebFilter|@WebListener)`)
	ejbRe         = regexp.MustCompile(`@(Stateless|Stateful|Singleton|MessageDriven|Schedule|EJB)`)
	jndiRe        = regexp.MustCompile(`(?:InitialContext|@Resource|Context\.lookup|new\s+InitialContext)`)
	jndiLookupRe  = regexp.MustCompile(`\.lookup\(\s*"([^"]+)"\s*\)`)
	classLoaderRe = regexp.MustCompile(`(?:ClassLoader|Class\.forName|getClassLoader|loadClass|URLClassLoader|ServiceLoader)`)
	annotationRe  = regexp.MustCompile(`@(javax|jakarta)\.\w+[\w.]*`)
)

// DetectPatterns scans Java source files for enterprise patterns.
func DetectPatterns(info *ArchiveInfo) *PatternReport {
	report := &PatternReport{}

	seenEJB := make(map[string]struct{})
	seenAnnotations := make(map[string]struct{})

	for _, javaRel := range info.JavaFiles {
		javaPath := filepath.Join(info.ExtractDir, filepath.FromSlash(javaRel))

		data, err := os.ReadFile(javaPath)
		if err != nil {
			continue
		}

		source := string(data)

		// Servlet detection
		if servletRe.MatchString(source) {
			report.HasServlets = true
		}

		// EJB detection
		for _, match := range ejbRe.FindAllStringSubmatch(source, -1) {
			report.HasEJB = true

			if _, ok := seenEJB[match[1]]; !ok {
				seenEJB[match[1]] = struct{}{}
				report.EJBTypes = append(report.EJBTypes, "@"+match[1])
			}
		}

		// JNDI detection
		if jndiRe.MatchString(source) {
			report.HasJNDI = true
			for _, match := range jndiLookupRe.FindAllStringSubmatch(source, -1) {
				report.JNDILookups = append(report.JNDILookups, match[1])
			}
		}

		// ClassLoader detection
		if classLoaderRe.MatchString(source) {
			report.HasClassLoading = true
		}

		// Java EE annotation detection
		for _, match := range annotationRe.FindAllStringSubmatch(source, -1) {
			ann := match[0]
			if _, ok := seenAnnotations[ann]; !ok {
				seenAnnotations[ann] = struct{}{}
				report.Annotations = append(report.Annotations, ann)
			}
		}
	}

	// Also check web.xml for servlet indicators
	if info.WebXML != nil {
		if len(info.WebXML.Servlets) > 0 || len(info.WebXML.Filters) > 0 {
			report.HasServlets = true
		}
	}

	// Deduplicate JNDI lookups
	if len(report.JNDILookups) > 0 {
		report.JNDILookups = dedup(report.JNDILookups)
	}

	return report
}

// dedup removes duplicates from a string slice, preserving order.
func dedup(items []string) []string {
	seen := make(map[string]struct{}, len(items))

	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
