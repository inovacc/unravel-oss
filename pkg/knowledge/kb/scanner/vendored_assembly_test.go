package scanner

import "testing"

func TestIsVendoredAssembly(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"System.Text.Json", true},
		{"System", true},
		{"Microsoft.Extensions.Logging", true},
		{"WinRT.Runtime", true},
		{"CommunityToolkit.Mvvm", true},
		{"protobuf-net.Core", true},
		{"protobuf-net", true},
		{"LinkedIn.TrackingLib", false},
		{"ShareLib", false},
		{"WindowsLix", false},
		{"Lego", false},
		{"", false},
		{"SystemicRisk", false}, // must not greedy-prefix on "System"
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVendoredAssembly(tt.name); got != tt.want {
				t.Fatalf("IsVendoredAssembly(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
