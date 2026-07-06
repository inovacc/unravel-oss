package analysis

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

func TestResultSet_Add(t *testing.T) {
	rs := &ResultSet{}
	r := Wrap("test", detect.TypeAPK, "MyApp", "1.0", "test summary", 50, map[string]string{"key": "val"})
	rs.Add(r)
	if rs.Count() != 1 {
		t.Errorf("Count() = %d, want 1", rs.Count())
	}
}

func TestResultSet_FindByAnalyzer(t *testing.T) {
	rs := &ResultSet{}
	rs.Add(Wrap("android", detect.TypeAPK, "MyApp", "1.0", "", 50, nil))
	rs.Add(Wrap("npm", detect.TypeNPMPackage, "lodash", "4.17", "", 10, nil))

	r := rs.FindByAnalyzer("npm")
	if r == nil {
		t.Fatal("expected to find npm result")
	}
	if r.AppName() != "lodash" {
		t.Errorf("AppName() = %q, want %q", r.AppName(), "lodash")
	}

	if rs.FindByAnalyzer("nonexistent") != nil {
		t.Error("expected nil for nonexistent analyzer")
	}
}

func TestResultSet_FindByType(t *testing.T) {
	rs := &ResultSet{}
	rs.Add(Wrap("android", detect.TypeAPK, "App1", "1.0", "", 50, nil))
	rs.Add(Wrap("android", detect.TypeAPK, "App2", "2.0", "", 30, nil))
	rs.Add(Wrap("npm", detect.TypeNPMPackage, "pkg", "1.0", "", 10, nil))

	apks := rs.FindByType(detect.TypeAPK)
	if len(apks) != 2 {
		t.Errorf("FindByType(APK) = %d results, want 2", len(apks))
	}
}

func TestResultSet_Names(t *testing.T) {
	rs := &ResultSet{}
	rs.Add(Wrap("android", detect.TypeAPK, "", "", "", 0, nil))
	rs.Add(Wrap("npm", detect.TypeNPMPackage, "", "", "", 0, nil))

	names := rs.Names()
	if len(names) != 2 || names[0] != "android" || names[1] != "npm" {
		t.Errorf("Names() = %v, want [android npm]", names)
	}
}

func TestWrap(t *testing.T) {
	raw := map[string]int{"score": 42}
	r := Wrap("test", detect.TypePE, "app.exe", "3.1", "PE binary", 25, raw)

	if r.FormatType() != detect.TypePE {
		t.Errorf("FormatType() = %v", r.FormatType())
	}
	if r.AnalyzerName() != "test" {
		t.Errorf("AnalyzerName() = %q", r.AnalyzerName())
	}
	if r.AppName() != "app.exe" {
		t.Errorf("AppName() = %q", r.AppName())
	}
	if r.RiskScore() != 25 {
		t.Errorf("RiskScore() = %d", r.RiskScore())
	}

	data, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON() returned empty")
	}

	if r.Raw() == nil {
		t.Error("Raw() returned nil")
	}
}
