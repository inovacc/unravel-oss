package goversions

import "testing"

func vuln(id, intro, fixed string) Vuln {
	return Vuln{ID: id, Summary: id, Affected: []AffectedRange{{Component: "stdlib", Introduced: intro, Fixed: fixed}}}
}

func TestPosture(t *testing.T) {
	vs := []Vuln{
		vuln("GO-A", "0", "1.20.6"),      // fixed in 1.20.6
		vuln("GO-B", "1.21.0", ""),       // unfixed, from 1.21.0
		vuln("GO-C", "1.19.0", "1.19.4"), // narrow window
	}
	// go1.20.3: exposed to A (not yet fixed), not B (before 1.21), not C (>1.19.4)
	p := Posture("go1.20.3", vs)
	if len(p.Exposed) != 1 || p.Exposed[0].ID != "GO-A" || p.Exposed[0].FixedIn != "1.20.6" {
		t.Fatalf("go1.20.3 posture = %+v", p.Exposed)
	}
	// go1.20.6: A fixed -> not exposed
	if len(Posture("go1.20.6", vs).Exposed) != 0 {
		t.Errorf("go1.20.6 should be clean of GO-A")
	}
	// go1.22.0: exposed to B (unfixed, >=1.21)
	p2 := Posture("go1.22.0", vs)
	if len(p2.Exposed) != 1 || p2.Exposed[0].ID != "GO-B" {
		t.Errorf("go1.22.0 posture = %+v", p2.Exposed)
	}
}
