/*
Copyright (c) 2026 Security Research

Package manifest summarises a parsed *msix.AppxManifest into the
denormalised pkg/uwp.ManifestSummary view consumed by the scoring layer.
*/
package manifest

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"unicode/utf16"

	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/uwp"
)

// Summarize flattens an *msix.AppxManifest into a *uwp.ManifestSummary,
// preserving manifest-order capabilities (D-04) and computing the Microsoft
// Package Family Name (PFN).
//
// Returns nil when m is nil so callers can compose with fallible parses.
func Summarize(m *msix.AppxManifest) *uwp.ManifestSummary {
	if m == nil {
		return nil
	}

	id := uwp.IdentityInfo{
		Name:          m.Identity.Name,
		Publisher:     m.Identity.Publisher,
		Version:       m.Identity.Version,
		ProcessorArch: m.Identity.ProcessorArchitecture,
	}

	out := &uwp.ManifestSummary{
		Identity: id,
		PFN:      ComputePFN(id.Name, id.Publisher),
	}

	for _, dep := range m.Dependencies.TargetDeviceFamily {
		out.TargetFamilies = append(out.TargetFamilies, dep.Name)
	}

	for _, app := range m.Applications.Application {
		out.EntryPoints = append(out.EntryPoints, uwp.EntryPoint{
			Id:         app.ID,
			Executable: app.Executable,
			EntryPoint: app.EntryPoint,
		})
	}

	out.Capabilities = flattenCapabilities(&m.Capabilities)
	return out
}

// flattenCapabilities converts msix.CapabilitiesBlock.OrderedRefs into
// []uwp.CapabilityRef. When OrderedRefs is empty (older fixtures parsed by
// stdlib path), falls back to flattening the typed slices in declaration
// order — degraded path documented in code.
func flattenCapabilities(c *msix.CapabilitiesBlock) []uwp.CapabilityRef {
	if len(c.OrderedRefs) > 0 {
		out := make([]uwp.CapabilityRef, 0, len(c.OrderedRefs))
		for _, r := range c.OrderedRefs {
			out = append(out, uwp.CapabilityRef{
				Name:      r.Name,
				Namespace: r.Namespace,
				Index:     r.Index,
			})
		}
		return out
	}

	// Degraded fallback: ordered refs not populated (e.g. caller stitched
	// CapabilitiesBlock manually). Flatten typed slices in declaration order.
	idx := 0
	add := func(out []uwp.CapabilityRef, ns string, caps []msix.NamedCap) []uwp.CapabilityRef {
		for _, n := range caps {
			out = append(out, uwp.CapabilityRef{Name: n.Name, Namespace: ns, Index: idx})
			idx++
		}
		return out
	}

	var out []uwp.CapabilityRef
	out = add(out, "", c.Capability)
	out = add(out, "uap", c.UAPCapability)
	out = add(out, "uap2", c.UAP2Capability)
	out = add(out, "uap3", c.UAP3Capability)
	out = add(out, "uap4", c.UAP4Capability)
	out = add(out, "uap6", c.UAP6Capability)
	out = add(out, "uap8", c.UAP8Capability)
	out = add(out, "uap10", c.UAP10Capability)
	out = add(out, "uap13", c.UAP13Capability)
	out = add(out, "uap15", c.UAP15Capability)
	out = add(out, "rescap", c.RestrictedCapability)
	for _, dc := range c.DeviceCapability {
		out = append(out, uwp.CapabilityRef{Name: dc.Name, Namespace: "device", Index: idx})
		idx++
	}
	out = add(out, "custom", c.CustomCapability)
	out = add(out, "unknown", c.UnknownCapability)
	return out
}

// ComputePFN computes the Microsoft Package Family Name (PFN) from the
// Identity Name and Publisher. The format is:
//
//	<Name>_<PublisherIdHash>
//
// PublisherIdHash is a 13-char Crockford-style base32-encoded representation
// of the first 8 bytes of SHA-256(UTF-16LE(Publisher)).
//
// Reference: learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-identity
func ComputePFN(name, publisher string) string {
	if name == "" {
		return ""
	}
	hash := PublisherIdHash(publisher)
	if hash == "" {
		return name
	}
	return name + "_" + hash
}

// PublisherIdHash returns the 13-character Microsoft Publisher ID computed
// from a CN=... publisher string.
//
// Steps (per Microsoft spec):
//  1. Encode publisher as UTF-16LE.
//  2. SHA-256(bytes).
//  3. Take first 8 bytes (64 bits).
//  4. Base32-encode using Microsoft's custom alphabet
//     "0123456789abcdefghjkmnpqrstvwxyz" (Crockford, lowercase).
//  5. Pad with trailing zero bit and emit 13 chars (no padding).
func PublisherIdHash(publisher string) string {
	if publisher == "" {
		return ""
	}
	utf16le := encodeUTF16LE(publisher)
	digest := sha256.Sum256(utf16le)
	first8 := digest[:8]
	return crockfordBase32(first8)
}

func encodeUTF16LE(s string) []byte {
	codeUnits := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(codeUnits)*2)
	for _, u := range codeUnits {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// crockfordBase32 encodes 8 bytes (64 bits) into the 13-char lowercase
// Microsoft PFN base32 alphabet.
//
// Microsoft pads the 64-bit hash with one zero bit (so it spans 65 bits ==
// 13 base32 digits) and emits using the alphabet
// "0123456789abcdefghjkmnpqrstvwxyz" (i, l, o, u removed).
func crockfordBase32(b []byte) string {
	const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	if len(b) != 8 {
		return ""
	}

	// Pack 8 bytes into a uint64, append a zero bit, treat as 65-bit integer
	// most-significant-first; emit 13 base-32 digits.
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])

	out := make([]byte, 13)
	// Process the 65-bit value 5 bits at a time, MSB first.
	// We hold the value in two parts (top bit + 64-bit value).
	for i := range 13 {
		shift := uint(60 - i*5)
		var idx uint64
		if i == 0 {
			// top 4 bits of hi + 0-pad bit (placed below) => we want the top 5
			// bits of the (hi << 1) | 0 representation.
			idx = (hi >> 59) & 0x1F
		} else {
			// subsequent 5-bit chunks come from (hi << 1) at position
			// (60 - i*5). Since the appended bit is zero we can compute via:
			idx = ((hi << 1) >> shift) & 0x1F
		}
		out[i] = alphabet[idx]
	}
	// Drop unused fallback to avoid lint.
	_ = base32.NewEncoding
	_ = strings.ToLower
	return string(out)
}
