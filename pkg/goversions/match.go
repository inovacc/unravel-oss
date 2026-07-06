package goversions

// Posture computes which vulns the given Go version is exposed to.
// A version V is exposed via a range when introduced<=V and (fixed=="" or V<fixed).
func Posture(version string, vulns []Vuln) CVEPosture {
	p := CVEPosture{Version: version}
	for _, v := range vulns {
		for _, r := range v.Affected {
			afterIntro := r.Introduced == "" || r.Introduced == "0" || Compare(r.Introduced, version) <= 0
			beforeFix := r.Fixed == "" || Compare(version, r.Fixed) < 0
			if afterIntro && beforeFix {
				p.Exposed = append(p.Exposed, ExposedVuln{ID: v.ID, FixedIn: r.Fixed, Summary: v.Summary})
				break // one exposing range per vuln is enough
			}
		}
	}
	return p
}
