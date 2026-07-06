/*
Copyright (c) 2026 Security Research
*/
package schema

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// GenerateSchemaPrompt builds a system prompt for AI-powered schema extraction.
// The prompt instructs the AI to produce a structured JSON ApplicationSchema
// that can be consumed by another AI to replicate the app in a different framework.
func GenerateSchemaPrompt(s *ApplicationSchema, r *dissect.DissectResult) string {
	var sb strings.Builder

	sb.WriteString("# Application Schema Extraction — AI System Prompt\n\n")
	sb.WriteString("You are extracting a **machine-readable application schema** from a security analysis.\n")
	sb.WriteString("Your output must be a single JSON object matching the ApplicationSchema type below.\n")
	sb.WriteString("Another AI will read this schema to replicate the application in a different framework\n")
	sb.WriteString("(e.g., Electron → Tauri, PWA → Electron, Android → cross-platform).\n\n")

	sb.WriteString("## Target Application\n\n")
	sb.WriteString(fmt.Sprintf("- **Name:** %s\n", s.AppName))
	sb.WriteString(fmt.Sprintf("- **Framework:** %s\n", s.Framework))
	if s.Version != "" {
		sb.WriteString(fmt.Sprintf("- **Version:** %s\n", s.Version))
	}
	sb.WriteString(fmt.Sprintf("- **Source:** %s\n", s.SourcePath))
	sb.WriteString("\n")

	// Show what static analysis already found
	sb.WriteString("## Static Analysis Summary\n\n")

	if len(s.Communication.Endpoints) > 0 {
		sb.WriteString(fmt.Sprintf("- **Endpoints found:** %d\n", len(s.Communication.Endpoints)))
		for _, ep := range s.Communication.Endpoints {
			sb.WriteString(fmt.Sprintf("  - `%s` (%s)\n", ep.URL, ep.Purpose))
		}
	}

	if len(s.IPC.Channels) > 0 {
		sb.WriteString(fmt.Sprintf("- **IPC channels:** %d\n", len(s.IPC.Channels)))
	}

	if len(s.Telemetry.Services) > 0 {
		sb.WriteString(fmt.Sprintf("- **Telemetry services:** %d\n", len(s.Telemetry.Services)))
	}

	if s.Security.RiskScore > 0 {
		sb.WriteString(fmt.Sprintf("- **Risk score:** %d/100\n", s.Security.RiskScore))
	}

	sb.WriteString("\n")

	// Instructions
	sb.WriteString("## Instructions\n\n")
	sb.WriteString("Analyze the provided data and enrich the schema with:\n\n")
	sb.WriteString("1. **Communication patterns** — classify every endpoint by purpose (api, auth, telemetry, cdn, websocket).\n")
	sb.WriteString("   Identify HTTP methods, data formats, and authentication requirements per endpoint.\n")
	sb.WriteString("2. **Authentication methods** — determine token types (bearer, api_key, oauth2), storage location,\n")
	sb.WriteString("   refresh mechanisms, and implementation library.\n")
	sb.WriteString("3. **Storage mechanisms** — identify all databases, local storage, caches, and encryption methods.\n")
	sb.WriteString("4. **IPC channels** — for Electron/Tauri apps, map all IPC channels with direction and message types.\n")
	sb.WriteString("   For Android, identify exported components and intent filters.\n")
	sb.WriteString("5. **Stealth features** — detect screen capture blocking, process hiding, anti-debugging,\n")
	sb.WriteString("   anti-instrumentation (Frida detection), and obfuscation.\n")
	sb.WriteString("6. **Telemetry** — identify analytics SDKs, crash reporting, event tracking, and consent mechanisms.\n")
	sb.WriteString("7. **Security posture** — permissions, sandbox status, CSP headers, dangerous permissions.\n\n")

	sb.WriteString("## Output Format\n\n")
	sb.WriteString("Return a single JSON object with this exact structure:\n\n")
	sb.WriteString("```json\n")
	sb.WriteString(`{
  "app_name": "string",
  "framework": "string",
  "version": "string",
  "communication": {
    "endpoints": [{"url": "", "methods": [], "purpose": "", "auth_type": "", "data_format": ""}],
    "protocols": [],
    "data_formats": [],
    "certificate_pinning": false,
    "cleartext_allowed": false
  },
  "auth": {
    "methods": [{"type": "", "header_name": "", "implementation": ""}],
    "token_storage": "",
    "mfa": false
  },
  "storage": {
    "databases": [{"type": "", "purpose": "", "tables": [], "encrypted": false}],
    "local_storage": [{"type": "", "location": "", "sensitive_data": false}],
    "encrypted": false,
    "key_management": ""
  },
  "ipc": {
    "channels": [{"name": "", "direction": "", "message_types": [], "privileged": false}],
    "protocols": []
  },
  "stealth": {
    "screen_capture_block": false,
    "screen_share_hide": false,
    "process_hiding": false,
    "anti_debugging": [],
    "anti_instrumentation": [],
    "code_obfuscation": ""
  },
  "telemetry": {
    "services": [{"name": "", "endpoint": "", "data_types": []}],
    "event_tracking": false,
    "crash_reporting": false,
    "consent_required": false
  },
  "security": {
    "debuggable": false,
    "sandbox_enabled": false,
    "content_protection": false,
    "csp": "",
    "permissions": [],
    "dangerous_permissions": [],
    "risk_score": 0
  },
  "confidence": 0.0
}
`)
	sb.WriteString("```\n\n")

	sb.WriteString("Be precise. Only include data you can verify from the analysis. Set confidence to\n")
	sb.WriteString("the fraction (0.0–1.0) of schema sections that have meaningful data.\n")

	return sb.String()
}
