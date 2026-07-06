package goversions

import (
	"go/version"
	"strings"
)

func canonical(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return ""
	}
	if !strings.HasPrefix(v, "go") {
		v = "go" + v
	}
	return v
}

// Compare orders two Go release versions: <0 if a<b, 0 if equal, >0 if a>b.
func Compare(a, b string) int {
	return version.Compare(canonical(a), canonical(b))
}
