// Package registry holds the YAML-defined schema of facts the 'knowledge'
// command tries to answer for every supported app. Each YAML file in this
// directory becomes one Category whose facts the command sequence
//
//	dissect → gaps → fill
//
// will populate. The YAML is embedded at build time so the binary is
// self-contained — analysts can override by passing --registry <dir>.
package registry

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var embedded embed.FS

// Category describes one logical grouping of facts (e.g. "crypto").
// AppliesTo lists the apps the category is meaningful for; an empty list
// means "all apps known to the sweep registry".
type Category struct {
	Category  string   `yaml:"category"`
	AppliesTo []string `yaml:"applies_to"`
	Facts     []Fact   `yaml:"facts"`
}

// Fact is one question worth answering. Key is unique within (Category, App).
// CandidatesQuery is the trigram search expression handed to the fill loop
// to pre-select evidence modules; GapPrompt is what claude actually reads.
type Fact struct {
	Key             string `yaml:"key"`
	ValueFormat     string `yaml:"value_format"`
	CandidatesQuery string `yaml:"candidates_q"`
	GapPrompt       string `yaml:"gap_prompt"`
	// ValueFunction is reserved for future computed facts (derived from
	// other facts). Unused for now.
	ValueFunction string `yaml:"value_function"`
}

// Load reads all YAML files in the embedded registry and, when overrideDir
// is a non-empty, existing directory, merges any YAML files found there over
// the embedded definitions.
//
// Merge semantics (override-wins): each (category, key) pair in overrideDir
// replaces the embedded fact with the same key; new (category, key) pairs and
// entire new categories supplement the registry; untouched embedded facts are
// preserved. An empty or non-existent overrideDir is a clean no-op. Malformed
// override files surface a wrapped error.
func Load(overrideDir string) ([]Category, error) {
	out, err := loadFromEmbedded()
	if err != nil {
		return nil, fmt.Errorf("embedded registry: %w", err)
	}
	overrides, err := loadFromDir(overrideDir)
	if err != nil {
		return nil, fmt.Errorf("override registry: %w", err)
	}
	return mergeOverrides(out, overrides), nil
}

// loadFromDir reads every *.yaml/*.yml file in dir as a Category. A blank dir
// or one that does not exist yields no categories and no error.
func loadFromDir(dir string) ([]Category, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}
	var cats []Category
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(path.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		full := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var c Category
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		if c.Category == "" {
			return nil, fmt.Errorf("%s: missing 'category'", e.Name())
		}
		cats = append(cats, c)
	}
	return cats, nil
}

// mergeOverrides folds overrides into base with override-wins precedence: a
// fact whose (category, key) matches a base fact replaces it in place; new
// keys are appended to the matching category; categories absent from base are
// added. Category-level metadata (AppliesTo) from an override replaces the
// base category's when the override supplies a non-empty list.
func mergeOverrides(base, overrides []Category) []Category {
	idx := make(map[string]int, len(base))
	for i, c := range base {
		idx[c.Category] = i
	}
	for _, oc := range overrides {
		bi, ok := idx[oc.Category]
		if !ok {
			base = append(base, oc)
			idx[oc.Category] = len(base) - 1
			continue
		}
		dst := &base[bi]
		if len(oc.AppliesTo) > 0 {
			dst.AppliesTo = oc.AppliesTo
		}
		factIdx := make(map[string]int, len(dst.Facts))
		for j, f := range dst.Facts {
			factIdx[f.Key] = j
		}
		for _, of := range oc.Facts {
			if fj, found := factIdx[of.Key]; found {
				dst.Facts[fj] = of
			} else {
				dst.Facts = append(dst.Facts, of)
				factIdx[of.Key] = len(dst.Facts) - 1
			}
		}
	}
	sort.Slice(base, func(i, j int) bool { return base[i].Category < base[j].Category })
	return base
}

func loadFromEmbedded() ([]Category, error) {
	entries, err := embedded.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var cats []Category
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(path.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		raw, err := embedded.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var c Category
		if err := yaml.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		if c.Category == "" {
			return nil, fmt.Errorf("%s: missing 'category'", e.Name())
		}
		cats = append(cats, c)
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].Category < cats[j].Category })
	return cats, nil
}

// Materialize expands a registry into one (category, app, key) triple per
// fact for each app in AppliesTo. Apps not in AppliesTo are skipped.
// Returns a flat slice ready for INSERT into app_facts.
type Materialised struct {
	App, Category, Key string
	GapPrompt          string
	CandidatesQ        string
	ValueFormat        string
}

func Materialize(cats []Category, knownApps []string) []Materialised {
	apps := map[string]bool{}
	for _, a := range knownApps {
		apps[a] = true
	}
	var out []Materialised
	for _, c := range cats {
		targets := c.AppliesTo
		if len(targets) == 0 {
			targets = knownApps
		}
		for _, app := range targets {
			if !apps[app] {
				continue
			}
			for _, f := range c.Facts {
				out = append(out, Materialised{
					App:         app,
					Category:    c.Category,
					Key:         f.Key,
					GapPrompt:   f.GapPrompt,
					CandidatesQ: f.CandidatesQuery,
					ValueFormat: f.ValueFormat,
				})
			}
		}
	}
	return out
}
