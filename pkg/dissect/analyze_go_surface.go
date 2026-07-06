/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strings"
)

// GoSurface is the externally-observable communication surface recovered from a
// Go binary's embedded strings: backend hosts, gRPC/proto service+RPC names, and
// referenced config paths. Stripped Go binaries (no DWARF/symtab) still carry
// these as plain strings, so this is the primary RE signal for standalone Go
// apps where the Electron/APK/.NET analyzers find nothing.
type GoSurface struct {
	Hosts       []string `json:"hosts,omitempty"`        // scheme+host, e.g. https://cloudcode-pa.googleapis.com
	RPCServices []string `json:"rpc_services,omitempty"` // fq proto/gRPC names + /vN:method RPC paths
	ConfigPaths []string `json:"config_paths,omitempty"` // referenced config files / dirs (~/.x, *.json)
}

// Empty reports whether nothing was recovered.
func (s *GoSurface) Empty() bool {
	return s == nil || (len(s.Hosts) == 0 && len(s.RPCServices) == 0 && len(s.ConfigPaths) == 0)
}

const (
	goSurfaceMinRun     = 6   // shortest printable run worth scanning
	goSurfaceMaxHosts   = 200 // caps keep a 350k-string binary from flooding the KB
	goSurfaceMaxRPCs    = 400
	goSurfaceMaxConfigs = 150
)

var (
	// scheme + host(:port) only — paths are dropped so endpoints dedupe by host.
	goHostRe = regexp.MustCompile(`https?://[A-Za-z0-9.-]+(?::[0-9]+)?`)
	// fully-qualified proto/gRPC name: lower.dotted.package + UpperCamel leaf.
	goProtoRe = regexp.MustCompile(`[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+\.[A-Z][A-Za-z0-9_]+`)
	// REST-transcoded RPC path, e.g. /v1internal:retrieveUserQuotaSummary.
	goRPCPathRe = regexp.MustCompile(`/v[0-9]+(?:internal|beta[0-9]*|alpha[0-9]*)?:[A-Za-z][A-Za-z0-9]+`)
	// referenced config: ~/.dir/... or a *.json/*.yaml/*.toml leaf.
	goConfigRe = regexp.MustCompile(`~[\\/]\.[A-Za-z0-9_./\\-]+|[A-Za-z0-9_.-]+\.(?:json|ya?ml|toml)`)
)

// goProtoNoise are vendored/runtime proto prefixes that are not app surface.
var goProtoNoise = []string{
	"google.protobuf.", "google.rpc.", "google.api.", "grpc.reflection.",
	"grpc.health.", "grpc.lb.", "grpc.channelz.", "grpc.binarylog.",
	"google.longrunning.", "go.opentelemetry.", "opencensus.proto.",
}

// scanGoSurface streams the binary and recovers its communication surface. It
// reads the file directly (not r.GarbleStrings) so it works regardless of the
// maxStringsFileSize gate — Go agent binaries routinely exceed it. Memory is
// bounded: one printable run plus the (capped) frequency tables.
func scanGoSurface(path string) (*GoSurface, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	hosts := map[string]int{}
	rpcs := map[string]int{}
	cfgs := map[string]int{}

	br := bufio.NewReaderSize(f, 1<<20)
	var run []byte
	flush := func() {
		if len(run) >= goSurfaceMinRun {
			s := string(run)
			for _, m := range goHostRe.FindAllString(s, -1) {
				hosts[strings.ToLower(m)]++
			}
			for _, m := range goProtoRe.FindAllString(s, -1) {
				if !protoIsNoise(m) {
					rpcs[m]++
				}
			}
			for _, m := range goRPCPathRe.FindAllString(s, -1) {
				rpcs[m]++
			}
			for _, m := range goConfigRe.FindAllString(s, -1) {
				cfgs[m]++
			}
		}
		run = run[:0]
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		if b >= 0x20 && b < 0x7f {
			run = append(run, b)
			continue
		}
		flush()
	}
	flush()

	s := &GoSurface{
		Hosts:       topN(hosts, goSurfaceMaxHosts),
		RPCServices: topN(rpcs, goSurfaceMaxRPCs),
		ConfigPaths: topN(cfgs, goSurfaceMaxConfigs),
	}
	return s, nil
}

func protoIsNoise(s string) bool {
	for _, p := range goProtoNoise {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// topN returns the n most frequent keys, frequency desc then lexicographic so
// the output is deterministic.
func topN(counts map[string]int, n int) []string {
	if len(counts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}
