/*
Copyright (c) 2026 Security Research

Rules package manages conversion rules for the transpiler.
Zero-dependency operation: rules are baked into the binary as Go assets.
*/
package rules

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/transpile" // trigger registration
)

const rulesPrefix = "skills/transpile/rules/"

// Get returns the content of a rule file for a given language and rule name.
func Get(language, name string) (string, error) {
	path := rulesPrefix + language + "/" + name + ".md"
	asset, ok := aihost.AssetByPath(aihost.KindSkill, path)
	if !ok {
		return "", aihost.ErrAssetNotFound
	}
	return asset.Body, nil
}

// List returns all rule names for a given language.
func List(language string) ([]string, error) {
	prefix := rulesPrefix + language + "/"
	assets := aihost.AssetsByKind(aihost.KindSkill)

	var names []string
	for _, a := range assets {
		if strings.HasPrefix(a.Path, prefix) && !strings.Contains(strings.TrimPrefix(a.Path, prefix), "/") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(a.Path, prefix), ".md"))
		}
	}
	return names, nil
}

// GetStrategy returns the content of a strategy file.
// Path is relative to the strategies/ directory (e.g., "concurrency/channels.md").
func GetStrategy(path string) (string, error) {
	fullPath := rulesPrefix + "strategies/" + path
	asset, ok := aihost.AssetByPath(aihost.KindSkill, fullPath)
	if !ok {
		return "", aihost.ErrAssetNotFound
	}
	return asset.Body, nil
}

// ListStrategies returns all strategy file paths relative to strategies/.
func ListStrategies() ([]string, error) {
	prefix := rulesPrefix + "strategies/"
	assets := aihost.AssetsByKind(aihost.KindSkill)

	var paths []string
	for _, a := range assets {
		if after, ok := strings.CutPrefix(a.Path, prefix); ok {
			paths = append(paths, after)
		}
	}
	return paths, nil
}
