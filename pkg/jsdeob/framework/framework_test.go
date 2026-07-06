/*
Copyright (c) 2026 Security Research
*/
package framework

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func mustHave(t *testing.T, infos []FrameworkInfo, name string) FrameworkInfo {
	t.Helper()
	for _, fi := range infos {
		if fi.Name == name {
			return fi
		}
	}
	t.Fatalf("expected framework %q in %v", name, infos)
	return FrameworkInfo{}
}

func TestDetect_React(t *testing.T) {
	got := Detect(loadFixture(t, "react_module.js"))
	fi := mustHave(t, got, "React")
	if fi.Confidence < 0.7 {
		t.Errorf("React confidence too low: %v", fi.Confidence)
	}
	joined := strings.Join(fi.Evidence, " ")
	if !strings.Contains(joined, "_jsx") {
		t.Errorf("React evidence missing _jsx marker: %v", fi.Evidence)
	}
}

func TestDetect_Preact(t *testing.T) {
	got := Detect(loadFixture(t, "preact_module.js"))
	mustHave(t, got, "Preact")
}

func TestDetect_Vue(t *testing.T) {
	got := Detect(loadFixture(t, "vue_module.js"))
	mustHave(t, got, "Vue")
}

func TestDetect_Angular(t *testing.T) {
	got := Detect(loadFixture(t, "angular_module.js"))
	mustHave(t, got, "Angular")
}

func TestDetect_Svelte(t *testing.T) {
	got := Detect(loadFixture(t, "svelte_module.js"))
	mustHave(t, got, "Svelte")
}

func TestDetect_Solid(t *testing.T) {
	got := Detect(loadFixture(t, "solid_module.js"))
	mustHave(t, got, "Solid")
}

func TestDetect_Nextjs(t *testing.T) {
	got := Detect(loadFixture(t, "nextjs_module.js"))
	if len(got) < 1 {
		t.Fatalf("expected at least one framework match, got %v", got)
	}
	if got[0].Name != "Next.js" {
		t.Errorf("expected Next.js first (specificity rule), got %v", got)
	}
	mustHave(t, got, "React")
	r := mustHave(t, got, "React")
	n := mustHave(t, got, "Next.js")
	if specificityFor(n.Name) <= specificityFor(r.Name) {
		t.Errorf("Next.js specificity should outrank React")
	}
}

func TestDetect_Nuxt(t *testing.T) {
	got := Detect(loadFixture(t, "nuxt_module.js"))
	mustHave(t, got, "Nuxt")
}

func TestDetect_Remix(t *testing.T) {
	got := Detect(loadFixture(t, "remix_module.js"))
	mustHave(t, got, "Remix")
}

func TestDetect_None(t *testing.T) {
	got := Detect([]byte("var x = 1; console.log(x);"))
	if got == nil {
		t.Fatalf("Detect must return non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

func TestDetect_Multiple(t *testing.T) {
	src := []byte(`
self.__NEXT_DATA__ = {};
import { _jsx } from "react/jsx-runtime";
const x = _jsx("div");
`)
	got := Detect(src)
	if len(got) < 2 {
		t.Fatalf("expected >=2 frameworks, got %v", got)
	}
	if got[0].Name != "Next.js" {
		t.Errorf("expected Next.js first via specificity, got %s", got[0].Name)
	}
	mustHave(t, got, "React")
}

func TestDetect_VersionExtraction(t *testing.T) {
	src := []byte(`var meta = "react@18.2.0"; var jsx = _jsx(0);`)
	got := Detect(src)
	fi := mustHave(t, got, "React")
	if fi.Version != "18.2.0" {
		t.Errorf("expected version 18.2.0, got %q", fi.Version)
	}
}

func TestDetect_FrameworkInfoShape(t *testing.T) {
	// Mirror Phase 4: Name string, Version string, Confidence float64,
	// Evidence []string. Verified via reflection so future drift is loud.
	rt := reflect.TypeFor[FrameworkInfo]()
	want := map[string]reflect.Kind{
		"Name":       reflect.String,
		"Version":    reflect.String,
		"Confidence": reflect.Float64,
		"Evidence":   reflect.Slice,
	}
	if rt.NumField() != len(want) {
		t.Fatalf("FrameworkInfo field count = %d, want %d", rt.NumField(), len(want))
	}
	for name, kind := range want {
		f, ok := rt.FieldByName(name)
		if !ok {
			t.Errorf("FrameworkInfo missing field %q", name)
			continue
		}
		if f.Type.Kind() != kind {
			t.Errorf("FrameworkInfo.%s kind = %v, want %v", name, f.Type.Kind(), kind)
		}
	}
}

func TestDetect_LargeInputBounded(t *testing.T) {
	// 5 MB of `a` interspersed with one React fingerprint near the end.
	big := bytes.Repeat([]byte("a"), 5*1024*1024)
	big = append(big, []byte("_jsx(")...)
	deadline := time.Now().Add(2 * time.Second)
	done := make(chan []FrameworkInfo, 1)
	go func() { done <- Detect(big) }()
	select {
	case got := <-done:
		mustHave(t, got, "React")
	case <-time.After(time.Until(deadline)):
		t.Fatal("Detect exceeded 2s on 5 MB input")
	}
}

func TestDetect_AllFixturesGoldenMatch(t *testing.T) {
	// Parameterised loop validating each golden fixture is recognised by
	// exactly its expected matcher.
	cases := []struct {
		file string
		want string
	}{
		{"react_module.js", "React"},
		{"preact_module.js", "Preact"},
		{"vue_module.js", "Vue"},
		{"angular_module.js", "Angular"},
		{"svelte_module.js", "Svelte"},
		{"solid_module.js", "Solid"},
		{"nextjs_module.js", "Next.js"},
		{"nuxt_module.js", "Nuxt"},
		{"remix_module.js", "Remix"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			got := Detect(loadFixture(t, tc.file))
			mustHave(t, got, tc.want)
		})
	}
}

func TestDetectPrimary(t *testing.T) {
	fi, ok := DetectPrimary(loadFixture(t, "vue_module.js"))
	if !ok {
		t.Fatal("expected primary framework")
	}
	if fi.Name != "Vue" {
		t.Errorf("primary name = %q, want Vue", fi.Name)
	}
	_, ok = DetectPrimary([]byte("nothing here"))
	if ok {
		t.Error("expected no primary on plain input")
	}
}
