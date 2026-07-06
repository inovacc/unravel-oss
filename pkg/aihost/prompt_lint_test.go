/*
Copyright (c) 2026 Security Research
*/

package aihost_test

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/all" // register all domain assets
)

// forbiddenSecretTokens must never appear in any rendered asset.
var forbiddenSecretTokens = []string{"sk-ant-", "ANTHROPIC_API_KEY", "anthropic_api_key"}

func TestRegisteredPromptAssetsLint(t *testing.T) {
	td := aihost.TemplateData{
		Name:        "unravel",
		Version:     "dev",
		Description: "unravel plugin",
		McpCommand:  "unravel",
		Created:     "2026-07-04",
	}

	assets := append(aihost.AllAssets(), aihost.PortableLibrarySkills()...)
	if len(assets) == 0 {
		t.Fatal("no assets registered — is the assets/all barrel imported?")
	}

	for _, asset := range assets {
		rendered, err := asset.Render(td)
		if err != nil {
			t.Errorf("render %s: %v", asset.Path, err)
			continue
		}
		text := string(rendered)

		for _, tok := range forbiddenSecretTokens {
			if strings.Contains(text, tok) {
				t.Errorf("%s leaks secret token %q", asset.Path, tok)
			}
		}

		fm, hasFM := renderedFrontmatter(text)
		installableSkill := asset.Kind == aihost.KindSkill && strings.HasSuffix(asset.Path, "/SKILL.md")
		if installableSkill && !hasFM {
			t.Errorf("%s is a SKILL.md asset without frontmatter", asset.Path)
			continue
		}
		if installableSkill || asset.Kind == aihost.KindCommand || asset.Kind == aihost.KindAgent {
			desc, ok := frontmatterField(fm, "description")
			if !ok {
				t.Errorf("%s frontmatter missing description", asset.Path)
				continue
			}
			if strings.TrimSpace(strings.Trim(desc, `"'`)) == "" {
				t.Errorf("%s frontmatter has blank description", asset.Path)
			}
		}
	}
}

func renderedFrontmatter(text string) (string, bool) {
	if !strings.HasPrefix(text, "---\n") {
		return "", false
	}
	rest := strings.TrimPrefix(text, "---\n")
	before, _, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return "", false
	}
	return before, true
}

func frontmatterField(fm, name string) (string, bool) {
	prefix := name + ":"
	for _, line := range strings.Split(fm, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(after), true
		}
	}
	return "", false
}
