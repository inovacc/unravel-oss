package reconstruct

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// NewProvenance creates a Provenance record from reconstruction results.
func NewProvenance(original, reconstructed string, verified bool, failures []string, opts Options) *Provenance {
	hash := sha256.Sum256([]byte(original))
	return &Provenance{
		Source:         "mcp-reconstruct",
		OriginalHash:   fmt.Sprintf("%x", hash),
		Confidence:     computeConfidence(verified, failures),
		PromptVersion:  opts.PromptVersion,
		Timestamp:      time.Now(),
		Verified:       verified,
		VerifyFailures: failures,
		StageDurations: make(map[string]time.Duration),
	}
}

// Header returns a language-appropriate comment block containing provenance
// metadata, suitable for embedding at the top of reconstructed files.
func (p *Provenance) Header(lang Language) string {
	prefix := "//"
	if lang == LangPython {
		prefix = "#"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s [AI-RECONSTRUCTED]\n", prefix)
	fmt.Fprintf(&b, "%s original_hash: %s\n", prefix, p.OriginalHash)
	fmt.Fprintf(&b, "%s confidence: %.2f\n", prefix, p.Confidence)
	if p.Model != "" {
		fmt.Fprintf(&b, "%s model: %s\n", prefix, p.Model)
	}
	fmt.Fprintf(&b, "%s prompt_version: %s\n", prefix, p.PromptVersion)
	fmt.Fprintf(&b, "%s verified: %v\n", prefix, p.Verified)
	fmt.Fprintf(&b, "%s timestamp: %s\n", prefix, p.Timestamp.UTC().Format(time.RFC3339))
	if len(p.VerifyFailures) > 0 {
		fmt.Fprintf(&b, "%s verify_failures: %s\n", prefix, strings.Join(p.VerifyFailures, "; "))
	}

	return b.String()
}

// computeConfidence returns a confidence score based on verification results.
func computeConfidence(verified bool, failures []string) float64 {
	if verified && len(failures) == 0 {
		return 1.0
	}
	if len(failures) == 0 {
		return 0.8
	}
	// Decrease confidence per failure, minimum 0.1.
	conf := 0.8 - float64(len(failures))*0.15
	if conf < 0.1 {
		conf = 0.1
	}
	return conf
}
