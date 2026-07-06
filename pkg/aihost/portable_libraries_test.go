package aihost

import (
	"strings"
	"testing"
)

func TestPortableLibrarySkills_ShapeAndFrontmatter(t *testing.T) {
	libs := PortableLibrarySkills()
	if len(libs) != 2 {
		t.Fatalf("got %d libraries, want 2 (command + agent)", len(libs))
	}
	for _, lib := range libs {
		if lib.Kind != KindSkill {
			t.Errorf("%s Kind = %v, want KindSkill", lib.Path, lib.Kind)
		}
		if !strings.HasSuffix(lib.Path, "/SKILL.md") {
			t.Errorf("%s path is not a SKILL.md", lib.Path)
		}
		// Frontmatter MUST end with a newline (Render appends ---/created after it).
		if !strings.HasSuffix(lib.Frontmatter, "\n") {
			t.Errorf("%s frontmatter does not end with newline", lib.Path)
		}
		if !strings.Contains(lib.Frontmatter, "name:") || !strings.Contains(lib.Frontmatter, "description:") {
			t.Errorf("%s frontmatter missing name/description", lib.Path)
		}
		if !strings.Contains(lib.Body, "## Index") {
			t.Errorf("%s body missing Index section", lib.Path)
		}
	}
}
