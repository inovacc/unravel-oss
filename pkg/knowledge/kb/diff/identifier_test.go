/*
Copyright (c) 2026 Security Research
*/

package diff

import (
	"strings"
	"testing"
)

func TestIdentifier_AllCategories(t *testing.T) {
	tests := []struct {
		name     string
		category string
		payload  any
		want     string
	}{
		{"dep", CategoryDep, DepDiff{Name: "Google.Protobuf"}, "Google.Protobuf"},
		{"capability empty namespace", CategoryCapability, CapabilityDiff{Name: "internetClient"}, ":internetClient"},
		{"capability with namespace", CategoryCapability, CapabilityDiff{Name: "runFullTrust", Namespace: "rescap"}, "rescap:runFullTrust"},
		{"url", CategoryURL, URLDiff{Host: "g.whatsapp.net"}, "g.whatsapp.net"},
		{"risk", CategoryRisk, RiskDiff{}, "risk-score"},
		{"cert truncates new", CategoryCert, CertDiff{FingerprintNew: "abcdef0123456789aaaaaaaa"}, "abcdef0123456789"},
		{"cert falls back to old", CategoryCert, CertDiff{FingerprintOld: "0011223344556677ffffffff"}, "0011223344556677"},
		{"fact preformatted", CategoryFact, FactDiff{Key: "crypto/db_cipher"}, "crypto/db_cipher"},
		{"module truncates", CategoryModule, ModuleDiff{BodySHA256: "0123456789abcdef00112233"}, "0123456789abcdef"},
		{"component", CategoryComponent, ComponentDiff{ModuleID: "42"}, "42"},
		{"file truncates", CategoryFile, FileDiff{FileSHA256: "deadbeefcafebabe11223344"}, "deadbeefcafebabe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Identifier(tt.category, tt.payload)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Identifier(%s, %T) = %q, want %q", tt.category, tt.payload, got, tt.want)
			}
		})
	}
}

func TestIdentifier_UnknownCategory(t *testing.T) {
	_, err := Identifier("bogus", DepDiff{Name: "x"})
	if err == nil {
		t.Fatal("expected error for unknown category, got nil")
	}
	if !strings.Contains(err.Error(), "unknown diff category") {
		t.Fatalf("expected unknown-category error, got %v", err)
	}
}

func TestIdentifier_TypeMismatch(t *testing.T) {
	_, err := Identifier(CategoryDep, URLDiff{Host: "x"})
	if err == nil {
		t.Fatal("expected error for payload/category mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "DepDiff") {
		t.Fatalf("expected mismatch error referencing DepDiff, got %v", err)
	}
}

func TestIdentifier_ShortFingerprintNotTruncated(t *testing.T) {
	got, err := Identifier(CategoryCert, CertDiff{FingerprintNew: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Fatalf("expected short fp passthrough, got %q", got)
	}
}
