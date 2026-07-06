package mcptools

import (
	"context"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResolvedInfoText_RedactsAndDescribes(t *testing.T) {
	info := ResolvedInfo{
		Database: "unravel", User: "unravel_app", Host: "10.0.0.5", Port: 5432,
		Source:  "UNRAVEL_KB_DB",
		Catalog: CatalogSummary{Apps: 0, Sources: 0, MigrationVersion: 11, Dirty: false},
	}
	got := info.Text()
	for _, want := range []string{"unravel_app@10.0.0.5:5432/unravel", "source=UNRAVEL_KB_DB", "kb_apps=0", "knowledge_sources=0", "migration=11"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Text() missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "password") || strings.Contains(got, "secret") {
		t.Fatalf("Text() leaked credential-ish token:\n%s", got)
	}

	t.Run("SummaryErr appears in Text", func(t *testing.T) {
		info2 := ResolvedInfo{
			Database: "unravel", User: "u", Host: "localhost", Port: 5432,
			Source:  "tool-arg",
			Catalog: CatalogSummary{SummaryErr: "relation does not exist"},
		}
		got2 := info2.Text()
		if !strings.Contains(got2, "summary_error=relation does not exist") {
			t.Fatalf("Text() missing summary_error in:\n%s", got2)
		}
	})
}

func TestResolveSource_Precedence(t *testing.T) {
	// An explicit per-call tool-arg wins over config.yaml.
	if s := resolveSource("postgres://x"); s != "tool-arg" {
		t.Fatalf("override → want tool-arg, got %s", s)
	}
	// With no per-call arg, the DSN comes from config.yaml — the single source
	// of truth. The removed UNRAVEL_KB_DSN / UNRAVEL_KB_DB env fallbacks must no
	// longer influence the source.
	t.Setenv("UNRAVEL_KB_DSN", "postgres://should-not-win")
	t.Setenv("UNRAVEL_KB_DB", "postgres://should-not-win")
	if s := resolveSource(""); s != "config.yaml" {
		t.Fatalf("no tool-arg → want config.yaml, got %s", s)
	}
}

func TestEmptyResultDiagnostic_NamesDBAndCounts(t *testing.T) {
	info := ResolvedInfo{Database: "unravel", User: "u", Host: "h", Port: 5432,
		Source: "config.yaml", Catalog: CatalogSummary{Apps: 0, Sources: 0, MigrationVersion: 11}}
	text, structured := emptyResultDiagnostic(info, "modules")
	if !strings.Contains(text, "no modules matched") || !strings.Contains(text, "knowledge_sources=0") {
		t.Fatalf("diagnostic text not actionable:\n%s", text)
	}
	if structured["resolved_db"] == nil || structured["catalog"] == nil {
		t.Fatalf("structured diagnostic missing keys: %#v", structured)
	}
	if !strings.Contains(text, "catalog has zero knowledge_sources") {
		t.Fatalf("hint missing when Sources==0 and SummaryErr==%q:\n%s", "", text)
	}
}

func TestOpenKBInfo_DelegatesAndKeepsSignature(t *testing.T) {
	_, info, err := openKBInfo(context.Background(), "postgres://bad:bad@127.0.0.1:1/none?sslmode=disable")
	if err == nil {
		t.Skip("unexpected reachable DB in test env")
	}
	if info.Source != "tool-arg" {
		t.Fatalf("error path lost Source: %+v", info)
	}
}

func TestKBPoolInfo_DefaultsWhenUnset(t *testing.T) {
	kbPoolInfoVal = atomic.Value{} // reset to unpopulated
	if got := kbPoolInfoOr("modules"); got == "" {
		t.Fatal("kbPoolInfoOr must always yield a non-empty diagnostic string")
	}
}

func TestDBJSONSchema_NoSqliteClaim(t *testing.T) {
	for _, t0 := range []reflect.Type{
		reflect.TypeOf(kbStatsInput{}), reflect.TypeOf(kbDumpInput{}), reflect.TypeOf(kbFactsInput{}),
	} {
		f, ok := t0.FieldByName("DB")
		if !ok {
			continue
		}
		if js := f.Tag.Get("jsonschema"); strings.Contains(js, "sqlite") {
			t.Fatalf("%s.DB jsonschema still claims sqlite: %q", t0.Name(), js)
		}
	}
}

func TestKBDoctorInput_Shape(t *testing.T) {
	f, ok := reflect.TypeOf(kbDoctorInput{}).FieldByName("DB")
	if !ok {
		t.Fatal("kbDoctorInput must have a DB field")
	}
	if got := f.Tag.Get("json"); got != "db,omitempty" {
		t.Fatalf("kbDoctorInput.DB json tag = %q, want \"db,omitempty\"", got)
	}
	// B3: DB is now supervisor-routed and the field is retained as a
	// DEPRECATED no-op for wire-shape compatibility. SQLite must still
	// never be claimed.
	js := f.Tag.Get("jsonschema")
	if strings.Contains(js, "sqlite") {
		t.Fatalf("kbDoctorInput.DB jsonschema = %q (must not claim sqlite)", js)
	}
	if !strings.Contains(js, "DEPRECATED") {
		t.Fatalf("kbDoctorInput.DB jsonschema = %q (want DEPRECATED marker)", js)
	}
}
