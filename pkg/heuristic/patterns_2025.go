package heuristic

// Patterns2025 returns detection patterns for 2024-2026 attack techniques,
// based on real-world supply chain attacks (Shai-Hulud, event-stream, node-ipc),
// CVE exploitation patterns, and modern evasion techniques.
func Patterns2025() []Pattern {
	return []Pattern{
		// ========================
		// SUPPLY CHAIN — 2025 Campaigns
		// ========================
		{
			ID: "supply-ci-fingerprint", Name: "CI/CD Environment Fingerprinting",
			Description: "Checks for CI-specific env vars — activates only in automated pipelines (Shai-Hulud pattern)",
			Category:    CategorySupplyChain, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`process\.env\.(?:GITHUB_ACTIONS|CI|GITLAB_CI|JENKINS_URL|TRAVIS|CIRCLECI|BUILD_ID|SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)`,
			},
		},
		{
			ID: "supply-remote-dynamic-dep", Name: "Remote Dynamic Dependency",
			Description: "Package fetches real payload at runtime from URL — defeats static analysis of published artifact",
			Category:    CategorySupplyChain, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`require\s*\(\s*(?:await\s+)?fetch\s*\(`,
				`import\s*\(\s*["']https?://`,
				`eval\s*\(\s*(?:await\s+)?(?:fetch|axios|request)\s*\(`,
			},
		},
		{
			ID: "supply-npm-token-theft", Name: "NPM/Package Token Theft",
			Description: "Access to package registry auth tokens — worm propagation vector (Shai-Hulud self-replication)",
			Category:    CategorySupplyChain, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`(?:npm|NPM)_TOKEN|_authToken|npmAuthToken`,
				`npm\s+publish`,
				`\.npmrc`,
			},
		},
		{
			ID: "supply-pickle-ml", Name: "Unsafe ML Model Deserialization",
			Description: "Loading pickle/torch models without safe restrictions — ML supply chain RCE (CVE-2025-1716)",
			Category:    CategorySupplyChain, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`pickle\.loads?\s*\(`,
				`torch\.load\s*\([^)]*weights_only\s*=\s*False`,
				`joblib\.load\s*\(`,
				`__reduce__\s*\(\s*\)\s*:`,
			},
			Languages: []string{"py"},
		},
		{
			ID: "supply-large-hex-payload", Name: "Dense Hex Literal Array (Obfuscated Payload)",
			Description: "Large arrays of hex values — common in 10MB+ obfuscated payloads (Shai-Hulud bun_environment.js)",
			Category:    CategoryObfuscation, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`(?:0x[0-9a-fA-F]{2,4},\s*){50,}`,
			},
		},

		// ========================
		// JS OBFUSCATION — Modern Techniques
		// ========================
		{
			ID: "obf-string-array-push-shift", Name: "String Array Push-Shift Rotation",
			Description: "javascript-obfuscator canonical pattern — string array rotated via push/shift IIFE",
			Category:    CategoryObfuscation, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`\['push'\]\s*\(\s*\w+\['shift'\]\s*\(\s*\)\s*\)`,
				`\.push\s*\(\s*\w+\.shift\s*\(\s*\)\s*\)`,
			},
		},
		{
			ID: "obf-eval-decode-chain", Name: "Eval + Decode Chain",
			Description: "eval/Function with decode step — most common payload delivery in compromised extensions",
			Category:    CategoryObfuscation, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(`,
				`(?:eval|Function)\s*\(\s*Buffer\.from\s*\([^)]+,\s*["']base64["']\s*\)`,
			},
		},
		{
			ID: "obf-string-concat-split", Name: "String Concatenation Splitting",
			Description: "Keywords split across string concatenations to evade keyword scanners",
			Category:    CategoryObfuscation, Severity: SeverityLow, Weight: 8,
			Patterns: []string{
				`(?:["'][a-zA-Z]{1,4}["']\s*\+\s*){5,}`,
			},
		},
		{
			ID: "obf-bracket-notation", Name: "Bracket Notation Property Access",
			Description: "Property access via bracket notation with encoded strings — hides API calls",
			Category:    CategoryObfuscation, Severity: SeverityMedium, Weight: 12,
			Patterns: []string{
				`\w+\[\s*["'](?:eval|exec|spawn|fetch|XMLHttpRequest|Function)["']\s*\]`,
				`window\[\s*(?:["'][^"']+["']\s*\+\s*)+["'][^"']+["']\s*\]`,
			},
		},

		// ========================
		// ELECTRON — 2025 CVEs
		// ========================
		{
			ID: "electron-v8-snapshot-backdoor", Name: "V8 Heap Snapshot Backdoor (CVE-2025-55305)",
			Description: "V8 snapshot file tampering — RCE in Signal, 1Password, Slack via unsigned heap snapshots",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`snapshot_blob\.bin`,
				`v8_context_snapshot\.bin`,
				`\.v8\.snapshot`,
			},
		},
		{
			ID: "electron-open-external", Name: "shell.openExternal Without Validation",
			Description: "User-controlled input passed to shell.openExternal — arbitrary URL/protocol launch",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`shell\.openExternal\s*\([^)]*(?:req\.|event\.|msg\.|data\.|args\.)`,
				`shell\.openExternal\s*\(\s*\w+\s*\)`, // variable (not literal)
			},
		},
		{
			ID: "electron-ipc-bridge-expose", Name: "IPC Bridge Over-Exposure",
			Description: "Preload exposes raw ipcRenderer without input validation — XSS to RCE bridge",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`contextBridge\.exposeInMainWorld\s*\([^)]*ipcRenderer\.(?:invoke|send|on)`,
				`contextBridge\.exposeInMainWorld\s*\([^)]*require\s*\(`,
			},
		},

		// ========================
		// EXTENSION — 2024-2025 Compromise Wave
		// ========================
		{
			ID: "ext-externally-connectable-wildcard", Name: "externally_connectable Wildcard",
			Description: "Extension accepts messages from any website — backdoor channel from any page",
			Category:    CategoryEvasion, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`"externally_connectable"[^}]*"matches"\s*:\s*\[[^]]*"\*`,
				`"externally_connectable"[^}]*"matches"\s*:\s*\[[^]]*"\*://\*/\*"`,
			},
		},
		{
			ID: "ext-phishing-overlay", Name: "Content Script Phishing Overlay",
			Description: "Content script creates iframes on sensitive pages — credential phishing overlay",
			Category:    CategoryDataAccess, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`chrome\.storage\.(?:local|sync)\.get[^;]*document\.createElement\s*\(\s*["']iframe["']\s*\)`,
				`document\.createElement\s*\(\s*["']iframe["']\s*\)[^;]*(?:bank|login|auth|signin|password)`,
			},
		},
		{
			ID: "ext-permission-escalation", Name: "Dynamic Permission Escalation",
			Description: "Extension requests additional permissions at runtime after install",
			Category:    CategoryEvasion, Severity: SeverityMedium, Weight: 15,
			Patterns: []string{
				`chrome\.permissions\.request\s*\(\s*\{`,
				`browser\.permissions\.request\s*\(\s*\{`,
			},
		},

		// ========================
		// CVE PATTERNS — 2025
		// ========================
		{
			ID: "cve-react-rsc-rce", Name: "React Server Components RCE (CVE-2025-55182)",
			Description: "RSC Flight protocol prototype pollution — CVSS 10.0, server-side RCE via Server Actions",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`_\$\$typeof.*Symbol\.for\s*\(\s*["']react\.`,
				`__proto__.*constructor.*Function.*process`,
			},
		},
		{
			ID: "cve-zip-slip", Name: "Path Traversal in Archive Extraction (Zip Slip)",
			Description: "Archive entry names with ../ — escape extraction directory for arbitrary file write",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`(?:entry|member|filename|name).*(?:\.\.[/\\]){2,}`,
				`path\.join\s*\([^)]*(?:entry|member|header)\.(?:name|path|filename)`,
				`extractPath\s*\+\s*(?:entry|member|filename)`,
			},
		},
		{
			ID: "cve-log4shell-evasion", Name: "Log4Shell JNDI Evasion Variants",
			Description: "Obfuscated JNDI lookup patterns designed to bypass WAFs",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`\$\{(?:\$\{[^}]*\})*(?:j|J)(?:\$\{[^}]*\})*(?:n|N)(?:\$\{[^}]*\})*(?:d|D)(?:\$\{[^}]*\})*(?:i|I)\s*:`,
				`\$\{\s*(?:::-[jJ]|lower:[jJ])\s*\}`,
			},
			Languages: []string{"java", "xml", "properties", "yaml", "json"},
		},

		// ========================
		// FILELESS — PowerShell/WMI 2025
		// ========================
		{
			ID: "fileless-ps-download-cradle", Name: "PowerShell Download Cradle (LOTL)",
			Description: "Download and execute payload entirely in memory — no file on disk",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`\[System\.Net\.WebClient\]::new\(\)\.DownloadString`,
				`(?:Net\.WebClient|WebClient).*Download(?:String|Data|File)`,
				`Invoke-WebRequest.*\|\s*Invoke-Expression`,
				`iwr\s+.*\|\s*iex`,
			},
		},
		{
			ID: "fileless-wmi-persist", Name: "WMI Event Subscription Persistence",
			Description: "WMI event subscriptions for fileless persistence — survives reboot without writing files",
			Category:    CategoryPersistence, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`New-CimInstance.*EventFilter`,
				`Set-WmiInstance.*__EventFilter`,
				`ActiveScriptEventConsumer`,
				`CommandLineEventConsumer`,
			},
		},

		// ========================
		// WASM — Advanced Payloads
		// ========================
		{
			ID: "wasm-crypto-mine", Name: "WebAssembly Cryptomining",
			Description: "WASM module for crypto mining — 75% of WASM samples are malicious (CrowdStrike)",
			Category:    CategoryCrypto, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`WebAssembly\.instantiate.*(?:mine|hash|crypto|stratum)`,
				`(?:CryptoNight|RandomX|Argon2).*(?:wasm|WebAssembly)`,
				`(?:wasm|WebAssembly).*(?:CryptoNight|RandomX|Argon2)`,
			},
		},
		{
			ID: "wasm-eval-export", Name: "WASM Export to Eval Bridge",
			Description: "WASM module exports used to construct and eval JavaScript — obfuscation carrier",
			Category:    CategoryObfuscation, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`WebAssembly\.instantiate(?:Streaming)?\s*\([^)]+\).*\.exports\.\w+.*(?:eval|Function)`,
				`Module\._malloc.*(?:eval|Function|exec)`,
			},
		},

		// ========================
		// DATA THEFT — Credential Harvesting
		// ========================
		{
			ID: "data-token-harvest", Name: "Token/Credential Harvesting",
			Description: "Scanning for tokens, API keys, and credentials in environment or storage",
			Category:    CategoryDataAccess, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`(?:GITHUB_TOKEN|NPM_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_|GCP_)`,
				`localStorage\.getItem\s*\(\s*["'](?:token|auth|session|jwt|api_?key)["']\s*\)`,
				`(?:chrome|browser)\.storage\.(?:local|sync)\.get\s*\(\s*(?:["'](?:token|auth|session|password)["']|null)\s*\)`,
			},
		},
		{
			ID: "data-discord-token", Name: "Discord Token Theft",
			Description: "Scanning for Discord tokens in browser storage — common in info-stealers",
			Category:    CategoryDataAccess, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`(?:discord|Discord).*(?:token|Token).*(?:leveldb|localStorage|LevelDB)`,
				`(?:mfa\.|Nz|OD|MT)[a-zA-Z0-9_-]{20,}\.[\w-]{6}\.[\w-]{27}`, // Discord token format
				`(?:discord\.com|discordapp\.com)/api.*(?:token|auth)`,
			},
		},
	}
}

func init() {
	// Patterns2025 are merged via DefaultPatterns
}
