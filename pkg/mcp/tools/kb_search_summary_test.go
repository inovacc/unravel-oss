package mcptools

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKbSearchItemHasSyntheticName(t *testing.T) {
	b, _ := json.Marshal(kbSearchItem{Name: "teams_module_1", SyntheticName: "Foo"})
	if !strings.Contains(string(b), `"synthetic_name":"Foo"`) {
		t.Fatalf("kbSearchItem missing synthetic_name json: %s", b)
	}
}

func TestKbSearchItemHasTopic(t *testing.T) {
	b, _ := json.Marshal(kbSearchItem{Name: "x", Topic: "messaging"})
	if !strings.Contains(string(b), `"topic":"messaging"`) {
		t.Fatalf("kbSearchItem missing topic json: %s", b)
	}
}

func TestKbSearchItemAdditiveFields(t *testing.T) {
	b, err := json.Marshal(kbSearchItem{
		Name:               "X",
		BodyExcerptSnippet: "code",
		Summary:            "does X",
		Role:               "util",
		Tags:               "a,b",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"body_excerpt_snippet":"code"`, `"summary":"does X"`, `"role":"util"`, `"tags":"a,b"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("kbSearchItem JSON missing %s — got %s", want, s)
		}
	}
}
