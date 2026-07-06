/*
Copyright (c) 2026 Security Research

kb_export_internal_test.go — white-box unit test for kbExportOutput struct
(Task 3 / kb-export-fidelity: additive manifest_path field seam).
*/
package mcptools

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKbExportOutputHasManifestPath(t *testing.T) {
	b, _ := json.Marshal(kbExportOutput{ManifestPath: "x/manifest.json"})
	if !strings.Contains(string(b), `"manifest_path":"x/manifest.json"`) {
		t.Fatalf("kbExportOutput missing manifest_path: %s", b)
	}
}
