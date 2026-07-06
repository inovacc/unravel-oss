/*
Copyright (c) 2026 Security Research
*/
package protobuf

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

const (
	maxProtoFiles   = 100
	maxServices     = 50
	maxMessageTypes = 200
)

// DetectProtobuf analyzes DEX parse results for protobuf and gRPC usage.
func DetectProtobuf(dexResult *dex.ParseResult) *ScanResult {
	result := &ScanResult{}

	if dexResult == nil {
		return result
	}

	// Collect all class names (strip L-prefix and convert / to .)
	var classNames []string
	for _, df := range dexResult.DexFiles {
		for _, c := range df.Classes {
			name := stripLPrefix(c.ClassName)
			classNames = append(classNames, name)
		}
	}

	// Detect protobuf — count classes with protobuf-related packages
	protoClassCount := 0
	for _, name := range classNames {
		if strings.Contains(name, "com/google/protobuf/") || strings.Contains(name, "com.google.protobuf.") {
			result.HasProtobuf = true
			protoClassCount++
		} else if strings.Contains(name, "protobuf") || strings.Contains(name, "Protobuf") {
			protoClassCount++
		}
	}

	if protoClassCount > 0 {
		result.HasProtobuf = true
		result.TotalProtoRefs = protoClassCount
	}

	// Detect gRPC and framework
	for _, name := range classNames {
		if strings.Contains(name, "io/grpc/") || strings.Contains(name, "io.grpc.") {
			result.HasGRPC = true

			// Detect framework variant
			if strings.Contains(name, "io/grpc/kotlin/") || strings.Contains(name, "io.grpc.kotlin.") {
				result.GRPCFramework = "grpc-kotlin"
			} else if strings.Contains(name, "io/grpc/okhttp/") || strings.Contains(name, "io.grpc.okhttp.") {
				if result.GRPCFramework == "" {
					result.GRPCFramework = "grpc-okhttp"
				}
			}
		}
	}

	if result.HasGRPC && result.GRPCFramework == "" {
		result.GRPCFramework = "grpc-java"
	}

	// Find gRPC service stubs
	for _, name := range classNames {
		if strings.Contains(name, "Grpc$") && strings.HasSuffix(name, "Stub") {
			if len(result.GRPCServices) >= maxServices {
				break
			}

			serviceName := extractServiceName(name)
			pkgName := extractPackageName(name)

			result.GRPCServices = append(result.GRPCServices, GRPCService{
				ServiceName: serviceName,
				PackageName: pkgName,
				ClassName:   name,
				IsStub:      true,
				Framework:   result.GRPCFramework,
			})
		}
	}

	// Find generated proto message classes (OuterClass pattern)
	for _, name := range classNames {
		if strings.HasSuffix(name, "OuterClass") {
			if len(result.MessageTypes) >= maxMessageTypes {
				break
			}

			// Extract message type name from "com/example/MyMessageOuterClass"
			parts := strings.Split(name, "/")
			if len(parts) == 0 {
				parts = strings.Split(name, ".")
			}

			last := parts[len(parts)-1]
			msgType := strings.TrimSuffix(last, "OuterClass")

			if msgType != "" {
				result.MessageTypes = append(result.MessageTypes, msgType)
			}
		}
	}

	// Find .proto file references in DEX strings
	for _, df := range dexResult.DexFiles {
		for _, s := range df.Strings {
			if strings.HasSuffix(s, ".proto") && !strings.Contains(s, " ") && len(s) < 200 {
				if len(result.ProtoFiles) >= maxProtoFiles {
					break
				}

				result.ProtoFiles = append(result.ProtoFiles, ProtoFileRef{
					Name:   s,
					Source: "dex_strings",
				})
			}
		}
	}

	result.TotalProtoRefs += len(result.ProtoFiles) + len(result.GRPCServices) + len(result.MessageTypes)

	return result
}

// stripLPrefix removes the "L" prefix and trailing ";" from DEX class names.
func stripLPrefix(name string) string {
	if strings.HasPrefix(name, "L") {
		name = name[1:]
	}

	name = strings.TrimSuffix(name, ";")

	return name
}

// extractServiceName extracts the service name from a gRPC stub class name.
// e.g., "com/example/MyServiceGrpc$MyServiceStub" -> "MyService"
func extractServiceName(className string) string {
	// Find the part before "Grpc$"
	before, _, ok := strings.Cut(className, "Grpc$")
	if !ok {
		return className
	}

	prefix := before

	// Get last segment
	parts := strings.Split(prefix, "/")
	if len(parts) == 0 {
		parts = strings.Split(prefix, ".")
	}

	return parts[len(parts)-1]
}

// extractPackageName extracts the package from a class name.
func extractPackageName(className string) string {
	sep := "/"
	if !strings.Contains(className, "/") {
		sep = "."
	}

	idx := strings.LastIndex(className, sep)
	if idx < 0 {
		return ""
	}

	return strings.ReplaceAll(className[:idx], "/", ".")
}
