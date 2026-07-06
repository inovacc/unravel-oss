package dex

import "testing"

// TestParseResult_StripHeavyTables pins the `dex --json` default behavior: the
// per-DEX string/type/class/method/field tables (which reached ~184 MB on real
// apps and buried the findings) are cleared, while the DexFile metadata, summary
// totals, risk findings, and high-entropy strings are preserved.
func TestParseResult_StripHeavyTables(t *testing.T) {
	r := &ParseResult{
		DexFiles: []DexFile{{
			Name:    "classes.dex",
			Version: "039",
			Strings: []string{"a", "b"},
			Types:   []string{"La;"},
			Classes: []ClassDef{{}},
			Methods: []MethodRef{{}},
			Fields:  []FieldRef{{}},
		}},
		TotalClasses:       1,
		TotalMethods:       1,
		TotalStrings:       2,
		RiskFindings:       []RiskFinding{{Category: "crypto", API: "javax.crypto.Cipher", Severity: "medium"}},
		HighEntropyStrings: []HighEntropyString{{Value: "AKIAEXAMPLE", Entropy: 4.9}},
	}

	r.StripHeavyTables()

	df := r.DexFiles[0]
	if df.Strings != nil || df.Types != nil || df.Classes != nil || df.Methods != nil || df.Fields != nil {
		t.Errorf("heavy per-DEX tables not stripped: strings=%d types=%d classes=%d methods=%d fields=%d",
			len(df.Strings), len(df.Types), len(df.Classes), len(df.Methods), len(df.Fields))
	}
	if df.Name != "classes.dex" || df.Version != "039" {
		t.Error("DexFile metadata (name/version) was lost")
	}
	if r.TotalClasses != 1 || r.TotalStrings != 2 {
		t.Error("summary totals were lost")
	}
	if len(r.RiskFindings) != 1 || len(r.HighEntropyStrings) != 1 {
		t.Error("risk findings / high-entropy strings were lost")
	}
}
