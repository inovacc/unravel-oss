/*
Copyright (c) 2026 Security Research
*/
package clr

import "testing"

func TestIsFrameworkAssembly(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Framework / runtime / common-vendored → true.
		{"System.Private.CoreLib", true},
		{"System.Collections", true},
		{"Microsoft.Win32.Primitives", true},
		{"Microsoft.Extensions.Logging", true},
		{"Windows.Foundation", true},
		{"WinRT.Runtime", true},
		{"CommunityToolkit.Mvvm", true},
		{"protobuf-net", true},
		{"protobuf-net.Core", true},
		{"netstandard", true},
		{"mscorlib", true},
		// LinkedIn first-party / app code → false.
		{"LinkedIn", false},
		{"TrackingLib", false},
		{"ShareLib", false},
		{"WindowsLix", false},
		{"Lego", false},
	}
	for _, c := range cases {
		if got := isFrameworkAssembly(c.name); got != c.want {
			t.Errorf("isFrameworkAssembly(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
