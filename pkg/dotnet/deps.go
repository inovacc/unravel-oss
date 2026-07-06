package dotnet

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// DepsJSON represents the parsed .deps.json file structure.
type DepsJSON struct {
	RuntimeTarget RuntimeTarget                    `json:"runtimeTarget"`
	Libraries     map[string]LibraryInfo           `json:"libraries"`
	Targets       map[string]map[string]TargetInfo `json:"targets"`
}

// RuntimeTarget holds the target framework moniker and optional runtime identifier.
type RuntimeTarget struct {
	Name string `json:"name"`
}

// LibraryInfo describes a single library entry in the deps manifest.
type LibraryInfo struct {
	Type        string `json:"type"` // "project" or "package"
	Serviceable bool   `json:"serviceable"`
	SHA512      string `json:"sha512"`
	Path        string `json:"path"`
	HashPath    string `json:"hashPath"`
}

// TargetInfo describes a library's dependencies and runtime assets for a specific target.
type TargetInfo struct {
	Dependencies map[string]string `json:"dependencies"`
	Runtime      map[string]any    `json:"runtime"`
}

// DepsResult is the high-level analysis result from parsing a .deps.json file.
type DepsResult struct {
	TargetFramework string           `json:"target_framework"`
	RuntimeID       string           `json:"runtime_id,omitempty"`
	ProjectLibs     []LibrarySummary `json:"project_libraries"`
	PackageLibs     []LibrarySummary `json:"package_libraries"`
	TotalLibraries  int              `json:"total_libraries"`
	IPCMechanisms   []string         `json:"ipc_mechanisms,omitempty"`
	Frameworks      []string         `json:"frameworks,omitempty"`
}

// LibrarySummary is a simplified view of a library with its resolved dependencies.
type LibrarySummary struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Type    string   `json:"type"`
	Deps    []string `json:"dependencies,omitempty"`
}

// ipcPatterns maps known NuGet package prefixes to IPC mechanism names.
var ipcPatterns = map[string]string{
	"microsoft.aspnetcore.signalr": "SignalR",
	"grpc.net.client":              "gRPC",
	"grpc.net.server":              "gRPC",
	"grpc.core":                    "gRPC",
	"grpc.aspnetcore":              "gRPC",
	"google.protobuf":              "Protobuf",
	"system.io.pipes":              "Named Pipes",
	"messagepack":                  "MessagePack",
	"rabbitmq.client":              "RabbitMQ",
	"confluent.kafka":              "Kafka",
	"masstransit":                  "MassTransit",
	"nservicebus":                  "NServiceBus",
	"rebus":                        "Rebus",
	"mediator":                     "Mediator",
	"zeromq":                       "ZeroMQ",
	"netmq":                        "ZeroMQ",
}

// frameworkPatterns maps known NuGet package prefixes to framework names.
var frameworkPatterns = map[string]string{
	"microsoft.aspnetcore":             "ASP.NET Core",
	"microsoft.maui":                   "MAUI",
	"microsoft.extensions.hosting":     "Generic Host",
	"microsoft.entityframeworkcore":    "Entity Framework Core",
	"avalonia":                         "Avalonia",
	"uno.ui":                           "Uno Platform",
	"blazor":                           "Blazor",
	"microsoft.aspnetcore.components":  "Blazor",
	"microsoft.windowsdesktop":         "WPF/WinForms",
	"microsoft.winui":                  "WinUI 3",
	"microsoft.windowsappsdk":          "WindowsAppSDK",
	"microsoft.windowsappruntime":      "WindowsAppRuntime",
	"swashbuckle":                      "Swagger",
	"nswag":                            "NSwag",
	"serilog":                          "Serilog",
	"nlog":                             "NLog",
	"hangfire":                         "Hangfire",
	"quartz":                           "Quartz.NET",
	"identityserver":                   "IdentityServer",
	"duende.identityserver":            "Duende IdentityServer",
	"microsoft.identity.web":           "Microsoft Identity",
	"ocelot":                           "Ocelot Gateway",
	"yarp":                             "YARP Proxy",
	"microsoft.aspnetcore.odata":       "OData",
	"hotchocolate":                     "HotChocolate GraphQL",
	"strawberryshake":                  "StrawberryShake GraphQL",
	"dapper":                           "Dapper",
	"automapper":                       "AutoMapper",
	"fluentvalidation":                 "FluentValidation",
	"polly":                            "Polly",
	"refit":                            "Refit",
	"microsoft.orleans":                "Orleans",
	"microsoft.azure.functions.worker": "Azure Functions",
	"amazon.lambda.aspnetcoreserver":   "AWS Lambda",
}

// ParseDeps reads a .deps.json file and returns a structured analysis result.
func ParseDeps(path string) (*DepsResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read deps.json: %w", err)
	}

	var deps DepsJSON
	if err := json.Unmarshal(data, &deps); err != nil {
		return nil, fmt.Errorf("parse deps.json: %w", err)
	}

	result := &DepsResult{}

	// Parse target framework and runtime ID from runtimeTarget.name.
	// Format: ".NETCoreApp,Version=v8.0/win-x64" or ".NETCoreApp,Version=v8.0"
	rtName := deps.RuntimeTarget.Name
	if before, after, ok := strings.Cut(rtName, "/"); ok {
		result.TargetFramework = before
		result.RuntimeID = after
	} else {
		result.TargetFramework = rtName
	}

	// Find the target entry that matches (use first available if exact match fails).
	var targetLibs map[string]TargetInfo
	for tKey, tVal := range deps.Targets {
		targetLibs = tVal
		// Prefer the target that matches the runtime target name.
		if tKey == rtName {
			break
		}
	}

	// Classify libraries into project vs package.
	ipcSeen := make(map[string]bool)
	fwSeen := make(map[string]bool)

	for key, lib := range deps.Libraries {
		name, version := splitLibraryKey(key)
		summary := LibrarySummary{
			Name:    name,
			Version: version,
			Type:    lib.Type,
		}

		// Attach dependencies from the target info.
		if targetLibs != nil {
			if ti, ok := targetLibs[key]; ok {
				for dep := range ti.Dependencies {
					summary.Deps = append(summary.Deps, dep)
				}
				sort.Strings(summary.Deps)
			}
		}

		switch lib.Type {
		case "project":
			result.ProjectLibs = append(result.ProjectLibs, summary)
		default:
			result.PackageLibs = append(result.PackageLibs, summary)
		}

		// Detect IPC mechanisms.
		lower := strings.ToLower(name)
		for prefix, mechanism := range ipcPatterns {
			if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
				if !ipcSeen[mechanism] {
					ipcSeen[mechanism] = true
					result.IPCMechanisms = append(result.IPCMechanisms, mechanism)
				}
			}
		}

		// Detect frameworks.
		for prefix, fw := range frameworkPatterns {
			if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
				if !fwSeen[fw] {
					fwSeen[fw] = true
					result.Frameworks = append(result.Frameworks, fw)
				}
			}
		}
	}

	sort.Slice(result.ProjectLibs, func(i, j int) bool {
		return result.ProjectLibs[i].Name < result.ProjectLibs[j].Name
	})
	sort.Slice(result.PackageLibs, func(i, j int) bool {
		return result.PackageLibs[i].Name < result.PackageLibs[j].Name
	})
	sort.Strings(result.IPCMechanisms)
	sort.Strings(result.Frameworks)

	result.TotalLibraries = len(deps.Libraries)

	return result, nil
}

// splitLibraryKey splits "Name/Version" into its parts.
func splitLibraryKey(key string) (name, version string) {
	if idx := strings.LastIndex(key, "/"); idx >= 0 {
		return key[:idx], key[idx+1:]
	}
	return key, ""
}
