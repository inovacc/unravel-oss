/*
Copyright (c) 2026 Security Research
*/
package dotnet

import (
	"sort"
	"strings"
)

// LibraryClassification provides detailed classification of .NET dependencies.
type LibraryClassification struct {
	FirstParty []ClassifiedLib `json:"first_party"`
	ThirdParty []ClassifiedLib `json:"third_party"`
	Microsoft  []ClassifiedLib `json:"microsoft"`
	Runtime    []ClassifiedLib `json:"runtime"`
	Vulnerable []VulnerableLib `json:"vulnerable,omitempty"`
	TotalLibs  int             `json:"total"`
}

// ClassifiedLib is a library with category and prerelease metadata.
type ClassifiedLib struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Category     string `json:"category"` // "web", "data", "security", "logging", "testing", "ui", "ipc", "other"
	IsPrerelease bool   `json:"is_prerelease,omitempty"`
}

// VulnerableLib describes a library with a known vulnerability.
type VulnerableLib struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Advisory string `json:"advisory"`
}

// categoryPatterns maps lowercase package name prefixes/substrings to categories.
var categoryPatterns = []struct {
	pattern  string
	category string
}{
	// web
	{"microsoft.aspnetcore", "web"},
	{"swashbuckle", "web"},
	{"nswag", "web"},
	{"refit", "web"},
	{"hotchocolate", "web"},
	{"strawberryshake", "web"},
	{"microsoft.aspnetcore.odata", "web"},
	{"yarp", "web"},
	{"ocelot", "web"},

	// data
	{"microsoft.entityframeworkcore", "data"},
	{"npgsql", "data"},
	{"dapper", "data"},
	{"mongodb", "data"},
	{"stackexchange.redis", "data"},
	{"microsoft.data.sqlclient", "data"},
	{"mysql.data", "data"},
	{"microsoft.data.sqlite", "data"},

	// security
	{"microsoft.identity", "security"},
	{"identityserver", "security"},
	{"duende.identityserver", "security"},
	{"system.identitymodel.tokens.jwt", "security"},
	{"microsoft.aspnetcore.authentication.jwtbearer", "security"},

	// logging
	{"serilog", "logging"},
	{"nlog", "logging"},
	{"microsoft.extensions.logging", "logging"},

	// ipc
	{"microsoft.aspnetcore.signalr", "ipc"},
	{"grpc.net", "ipc"},
	{"grpc.core", "ipc"},
	{"grpc.aspnetcore", "ipc"},
	{"masstransit", "ipc"},
	{"rabbitmq.client", "ipc"},
	{"confluent.kafka", "ipc"},
	{"nservicebus", "ipc"},
	{"rebus", "ipc"},
	{"zeromq", "ipc"},
	{"netmq", "ipc"},
	{"messagepack", "ipc"},
	{"google.protobuf", "ipc"},

	// ui
	{"microsoft.maui", "ui"},
	{"avalonia", "ui"},
	{"microsoft.windowsdesktop", "ui"},
	{"uno.ui", "ui"},

	// testing
	{"xunit", "testing"},
	{"nunit", "testing"},
	{"mstest", "testing"},
	{"moq", "testing"},
	{"nsubstitute", "testing"},
	{"fluentassertions", "testing"},
	{"coverlet", "testing"},
	{"microsoft.net.test", "testing"},
}

// knownVulnerabilities maps lowercase "name/version-prefix" to advisory descriptions.
// These represent well-known vulnerable NuGet packages.
var knownVulnerabilities = []struct {
	name     string
	maxVer   string // vulnerable if version <= this (prefix match)
	advisory string
}{
	{"system.text.encodings.web", "4.5.0", "CVE-2021-26701: RCE via malformed input"},
	{"system.text.regularexpressions", "4.3.0", "CVE-2019-0820: ReDoS in Regex"},
	{"microsoft.aspnetcore.server.kestrel.core", "2.1.0", "CVE-2019-0548: DoS via malformed request"},
	{"newtonsoft.json", "11.0.2", "CVE-2024-21907: stack overflow via deeply nested JSON"},
	{"microsoft.data.odata", "5.8.3", "CVE-2018-8269: XXE in OData deserialization"},
	{"system.net.http", "4.3.1", "CVE-2018-8292: credential leak on redirect"},
	{"microsoft.identitymodel.tokens", "5.1.5", "CVE-2024-21643: improper token validation"},
	{"system.drawing.common", "6.0.0", "CVE-2023-21808: RCE in System.Drawing on Linux"},
	{"microsoft.aspnetcore.http.connections", "1.0.3", "CVE-2019-0982: DoS in SignalR connections"},
	{"log4net", "2.0.14", "CVE-2018-1285: XXE via SerializedLayout"},
}

// ClassifyLibraries takes a DepsResult and provides detailed classification.
func ClassifyLibraries(deps *DepsResult) *LibraryClassification {
	cl := &LibraryClassification{
		TotalLibs: deps.TotalLibraries,
	}

	// Classify project libraries as first-party.
	for _, lib := range deps.ProjectLibs {
		cat := categorize(lib.Name)
		cl.FirstParty = append(cl.FirstParty, ClassifiedLib{
			Name:         lib.Name,
			Version:      lib.Version,
			Category:     cat,
			IsPrerelease: isPrerelease(lib.Version),
		})
	}

	// Classify package libraries.
	for _, lib := range deps.PackageLibs {
		lower := strings.ToLower(lib.Name)
		cat := categorize(lib.Name)
		prerelease := isPrerelease(lib.Version)

		classified := ClassifiedLib{
			Name:         lib.Name,
			Version:      lib.Version,
			Category:     cat,
			IsPrerelease: prerelease,
		}

		switch {
		case strings.HasPrefix(lower, "runtime."):
			cl.Runtime = append(cl.Runtime, classified)
		case strings.HasPrefix(lower, "microsoft.") || strings.HasPrefix(lower, "system."):
			cl.Microsoft = append(cl.Microsoft, classified)
		default:
			cl.ThirdParty = append(cl.ThirdParty, classified)
		}

		// Check for known vulnerabilities.
		checkVulnerability(cl, lib.Name, lib.Version)
	}

	// Sort all slices by name.
	sortClassified := func(s []ClassifiedLib) {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
	sortClassified(cl.FirstParty)
	sortClassified(cl.ThirdParty)
	sortClassified(cl.Microsoft)
	sortClassified(cl.Runtime)

	sort.Slice(cl.Vulnerable, func(i, j int) bool { return cl.Vulnerable[i].Name < cl.Vulnerable[j].Name })

	return cl
}

// categorize returns the best-matching category for a library name.
func categorize(name string) string {
	lower := strings.ToLower(name)
	for _, cp := range categoryPatterns {
		if strings.HasPrefix(lower, cp.pattern) || strings.Contains(lower, cp.pattern) {
			return cp.category
		}
	}

	return "other"
}

// isPrerelease returns true if the version contains a prerelease marker ("-").
func isPrerelease(version string) bool {
	return strings.Contains(version, "-")
}

// checkVulnerability checks if a package matches any known vulnerability entry.
func checkVulnerability(cl *LibraryClassification, name, version string) {
	lower := strings.ToLower(name)
	for _, vuln := range knownVulnerabilities {
		if lower == vuln.name && version <= vuln.maxVer {
			cl.Vulnerable = append(cl.Vulnerable, VulnerableLib{
				Name:     name,
				Version:  version,
				Advisory: vuln.advisory,
			})
		}
	}
}
