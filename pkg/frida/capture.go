/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"fmt"
	"strings"
)

// GenerateCapture creates traffic capture configuration templates for common
// interception tools. When domains are provided, templates include filtering
// rules scoped to those domains.
func GenerateCapture(packageName string, domains []string) *CaptureResult {
	result := &CaptureResult{
		PackageName: packageName,
		Domains:     domains,
	}

	result.Templates = []CaptureTemplate{
		mitmproxyTemplate(packageName, domains),
		pcapdroidTemplate(packageName, domains),
		burpTemplate(packageName, domains),
		charlesTemplate(packageName, domains),
	}

	return result
}

// GenerateCaptureFromAnalysis creates capture templates using domains extracted
// from the analysis input's network data.
func GenerateCaptureFromAnalysis(input AnalysisInput) *CaptureResult {
	return GenerateCapture(input.PackageName, input.Domains)
}

func mitmproxyTemplate(packageName string, domains []string) CaptureTemplate {
	var domainFilter string
	if len(domains) > 0 {
		quoted := make([]string, len(domains))
		for i, d := range domains {
			quoted[i] = fmt.Sprintf("    %q,", d)
		}

		domainFilter = fmt.Sprintf(`
TARGET_DOMAINS = [
%s
]

def domain_match(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in TARGET_DOMAINS)
`, strings.Join(quoted, "\n"))
	} else {
		domainFilter = `
TARGET_DOMAINS = []

def domain_match(host: str) -> bool:
    return True  # no domain filter, capture all traffic
`
	}

	content := fmt.Sprintf(`"""
mitmproxy capture script for %s
Usage: mitmproxy -s capture_mitmproxy.py
"""
import datetime
import os
import re
from mitmproxy import http

OUTPUT_DIR = "captures"
SENSITIVE_HEADERS = re.compile(
    r"(authorization|x-api-key|x-auth-token|cookie|x-csrf-token)",
    re.IGNORECASE,
)
%s
def request(flow: http.HTTPFlow) -> None:
    if not domain_match(flow.request.pretty_host):
        return

    ts = datetime.datetime.now().strftime("%%Y%%m%%d_%%H%%M%%S_%%f")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    path = os.path.join(OUTPUT_DIR, f"req_{ts}.txt")
    with open(path, "w") as f:
        f.write(f"{flow.request.method} {flow.request.pretty_url}\n")
        for k, v in flow.request.headers.items():
            marker = " <<<" if SENSITIVE_HEADERS.search(k) else ""
            f.write(f"{k}: {v}{marker}\n")
        if flow.request.content:
            f.write(f"\n{flow.request.content.decode('utf-8', errors='replace')}\n")


def response(flow: http.HTTPFlow) -> None:
    if not domain_match(flow.request.pretty_host):
        return

    ts = datetime.datetime.now().strftime("%%Y%%m%%d_%%H%%M%%S_%%f")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    path = os.path.join(OUTPUT_DIR, f"resp_{ts}.txt")
    with open(path, "w") as f:
        f.write(f"{flow.response.status_code} {flow.request.pretty_url}\n")
        for k, v in flow.response.headers.items():
            f.write(f"{k}: {v}\n")
        if flow.response.content:
            f.write(f"\n{flow.response.content.decode('utf-8', errors='replace')}\n")
`, packageName, domainFilter)

	return CaptureTemplate{
		Name:        "capture_mitmproxy",
		Tool:        "mitmproxy",
		Description: "mitmproxy addon script with domain filtering and sensitive header detection",
		Content:     content,
		Format:      "py",
	}
}

func pcapdroidTemplate(packageName string, domains []string) CaptureTemplate {
	domainJSON := "[]"
	if len(domains) > 0 {
		quoted := make([]string, len(domains))
		for i, d := range domains {
			quoted[i] = fmt.Sprintf("    %q", d)
		}

		domainJSON = fmt.Sprintf("[\n%s\n  ]", strings.Join(quoted, ",\n"))
	}

	content := fmt.Sprintf(`{
  "app_filter": %q,
  "capture_domains": %s,
  "tls_decryption": true,
  "pcap_dump_mode": "pcap_file",
  "snaplen": 65535,
  "block_quic": true,
  "auto_start": true
}
`, packageName, domainJSON)

	return CaptureTemplate{
		Name:        "pcapdroid_config",
		Tool:        "pcapdroid",
		Description: "PCAPdroid configuration targeting the app package with TLS decryption",
		Content:     content,
		Format:      "json",
	}
}

func burpTemplate(packageName string, domains []string) CaptureTemplate {
	scopeRules := ""
	sslPassthrough := ""

	if len(domains) > 0 {
		var rules []string
		var passRules []string

		for _, d := range domains {
			escaped := strings.ReplaceAll(d, ".", "\\\\.")
			rules = append(rules, fmt.Sprintf(`        {
          "enabled": true,
          "prefix": "https",
          "host": "^%s$"
        }`, escaped))
			passRules = append(passRules, fmt.Sprintf(`        {
          "enabled": true,
          "host": %q,
          "port": ""
        }`, d))
		}

		scopeRules = strings.Join(rules, ",\n")
		sslPassthrough = strings.Join(passRules, ",\n")
	} else {
		scopeRules = `        {
          "enabled": true,
          "prefix": "https",
          "host": ".*"
        }`
		sslPassthrough = ""
	}

	var sslSection string
	if sslPassthrough != "" {
		sslSection = fmt.Sprintf(`
    "ssl_pass_through": {
      "rules": [
%s
      ]
    },`, sslPassthrough)
	}

	content := fmt.Sprintf(`{
  "project_options": {
    "target": {
      "scope": {
        "advanced_mode": true,
        "include": [
%s
        ]
      }
    },%s
    "http": {
      "redirections": {
        "follow_redirections": "in_scope_only"
      }
    }
  },
  "comment": "Burp Suite project config for %s"
}
`, scopeRules, sslSection, packageName)

	return CaptureTemplate{
		Name:        "burp_project",
		Tool:        "burp",
		Description: "Burp Suite project configuration with scope and SSL pass-through rules",
		Content:     content,
		Format:      "json",
	}
}

func charlesTemplate(packageName string, domains []string) CaptureTemplate {
	var sslLocations string
	var mapLocalRules string

	if len(domains) > 0 {
		var sslEntries []string
		var mapEntries []string

		for _, d := range domains {
			sslEntries = append(sslEntries, fmt.Sprintf(`      <locationPatterns>
        <locationMatch>
          <location host="%s" port="443" protocol="https"/>
        </locationMatch>
      </locationPatterns>`, d))
			mapEntries = append(mapEntries, fmt.Sprintf(`      <mapLocalRule>
        <location host="%s" protocol="https"/>
        <localPath>/path/to/local/files</localPath>
        <enabled>false</enabled>
      </mapLocalRule>`, d))
		}

		sslLocations = strings.Join(sslEntries, "\n")
		mapLocalRules = strings.Join(mapEntries, "\n")
	}

	content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<charles-session>
  <comment>Charles Proxy session for %s</comment>
  <sslProxying>
    <enabled>true</enabled>
    <locations>
%s
    </locations>
  </sslProxying>
  <mapLocal>
    <enabled>true</enabled>
    <rules>
%s
    </rules>
  </mapLocal>
  <rewrite>
    <enabled>true</enabled>
    <rules>
      <rewriteRule>
        <name>Remove Cache Headers</name>
        <enabled>false</enabled>
        <matchHeader>Cache-Control</matchHeader>
        <matchValue>.*</matchValue>
        <replaceValue>no-cache</replaceValue>
        <type>response-header</type>
      </rewriteRule>
    </rules>
  </rewrite>
</charles-session>
`, packageName, sslLocations, mapLocalRules)

	return CaptureTemplate{
		Name:        "charles_session",
		Tool:        "charles",
		Description: "Charles Proxy session with SSL proxying, map local, and rewrite rules",
		Content:     content,
		Format:      "xml",
	}
}
