package heuristic

// DefaultPatterns returns all built-in heuristic detection patterns.
func DefaultPatterns() []Pattern {
	all := corePatterns()
	all = append(all, AdvancedPatterns()...)
	all = append(all, Patterns2025()...)
	return all
}

// corePatterns returns the core heuristic detection patterns.
func corePatterns() []Pattern {
	return []Pattern{
		// ========================
		// NETWORK — External Connections
		// ========================
		{
			ID: "net-fetch-dynamic", Name: "Dynamic Fetch/XHR",
			Description: "HTTP request with dynamically constructed URL (potential C2 or exfiltration)",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`fetch\s*\(\s*[^"'\s]`,                  // fetch(variable) not fetch("literal")
				`\.open\s*\(\s*["']\w+["']\s*,\s*[^"']`, // xhr.open("GET", variable)
				`axios\.\w+\s*\(\s*[^"'\s]`,
			},
		},
		{
			ID: "net-websocket", Name: "WebSocket Connection",
			Description: "WebSocket connection (potential real-time data exfiltration or C2 channel)",
			Category:    CategoryNetwork, Severity: SeverityMedium, Weight: 15,
			Patterns: []string{
				`new\s+WebSocket\s*\(`,
				`(?:ws|wss)://[^\s"']+`,
				`\.createWebSocketStream\s*\(`,
				`socket\.connect\s*\(`,
			},
		},
		{
			ID: "net-raw-ip", Name: "Raw IP Address Connection",
			Description: "Direct connection to IP address (bypasses DNS, common in malware)",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`(?:https?|wss?|ftp)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`,
				`net\.(?:Dial|Listen)\s*\(\s*["']tcp["']\s*,\s*["']\d{1,3}\.\d{1,3}`,
				`socket\.connect\s*\(\s*\d+\s*,\s*["']\d{1,3}\.\d{1,3}`,
			},
		},
		{
			ID: "net-dns-lookup", Name: "DNS Lookup/Resolution",
			Description: "Programmatic DNS resolution (may indicate DNS-based C2 or tunneling)",
			Category:    CategoryNetwork, Severity: SeverityMedium, Weight: 10,
			Patterns: []string{
				`dns\.resolve\s*\(`,
				`dns\.lookup\s*\(`,
				`net\.LookupHost\s*\(`,
				`DnsQuery`,
			},
		},
		{
			ID: "net-exfil-encode", Name: "Data Encoding Before Transmission",
			Description: "Base64/hex encoding combined with network send (data exfiltration pattern)",
			Category:    CategoryNetwork, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`(?:btoa|atob|Buffer\.from|base64\.encode)\s*\([^)]+\)[^;]*(?:fetch|axios|request|http|send)\s*\(`,
				`(?:fetch|axios|request|http|send)\s*\([^)]*(?:btoa|base64|encode)`,
				`encodeURIComponent\s*\([^)]+\)[^;]*(?:fetch|send|post)`,
			},
		},
		{
			ID: "net-reverse-shell", Name: "Reverse Shell Pattern",
			Description: "Network connection piped to shell (reverse shell indicator)",
			Category:    CategoryNetwork, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`(?:net\.Socket|child_process).*(?:pipe|stdin|stdout)`,
				`exec\s*\(\s*["'](?:/bin/(?:ba)?sh|cmd(?:\.exe)?|powershell)`,
				`(?:bash|sh|cmd)\s+-[ic]\s+["'].*(?:nc|ncat|netcat)`,
				`\.exec\s*\(\s*["'].*\b(?:nc|ncat)\s+-[elp]`,
				`os/exec.*(?:Dial|Listen|Connect)`,
			},
		},
		{
			ID: "net-telegram-discord", Name: "Bot/Webhook Exfiltration",
			Description: "Data sent to Telegram bot or Discord webhook (common exfil channel)",
			Category:    CategoryNetwork, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`api\.telegram\.org/bot`,
				`discord(?:app)?\.com/api/webhooks`,
				`hooks\.slack\.com/services`,
			},
		},
		{
			ID: "net-pastebin", Name: "Paste Service Communication",
			Description: "Communication with paste/bin services (C2 drop or payload download)",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`(?:pastebin|paste\.ee|hastebin|dpaste|ghostbin|rentry)\.(?:com|org|co)/`,
				`gist\.githubusercontent\.com`,
				`raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/[^"'\s]+\.(?:sh|ps1|py|exe|bat)`,
			},
		},

		// ========================
		// OBFUSCATION — Code Hiding
		// ========================
		{
			ID: "obf-eval", Name: "Dynamic Code Execution (eval)",
			Description: "eval() or Function() constructor used for dynamic code execution",
			Category:    CategoryObfuscation, Severity: SeverityCritical, Weight: 35,
			Patterns: []string{
				`\beval\s*\(`,
				`new\s+Function\s*\(`,
				`setTimeout\s*\(\s*["'][^"']*["']`, // setTimeout with string arg
				`setInterval\s*\(\s*["'][^"']*["']`,
			},
		},
		{
			ID: "obf-packed", Name: "Packed/Encoded Code",
			Description: "Code appears packed or heavily encoded (common in malware payloads)",
			Category:    CategoryObfuscation, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)`, // p.a.c.k.e.r
				`(?:\\x[0-9a-fA-F]{2}){10,}`,                   // long hex escape sequence
				`\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}`,  // long unicode escape
				`atob\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']\s*\)`, // base64 decoded inline
			},
		},
		{
			ID: "obf-string-array", Name: "String Array Rotation",
			Description: "Array of encoded strings with rotation/decoding function (common obfuscation)",
			Category:    CategoryObfuscation, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`var\s+_0x[a-f0-9]+\s*=\s*\[`,                      // _0x4a2f = ["...", "..."]
				`\bfunction\s+_0x[a-f0-9]+\s*\(`,                   // function _0x4a2f()
				`\[["'][^"']+["'](?:\s*,\s*["'][^"']+["']){20,}\]`, // array with 20+ strings
			},
		},
		{
			ID: "obf-char-code", Name: "CharCode Construction",
			Description: "String built from character codes (hides readable strings)",
			Category:    CategoryObfuscation, Severity: SeverityMedium, Weight: 20,
			Patterns: []string{
				`String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){5,}`,
				`charCodeAt\s*\(.*\)\s*\^`,                               // XOR on char codes
				`\.split\s*\(\s*["']['"]?\s*\)\.reverse\s*\(\s*\)\.join`, // reverse string
			},
		},
		{
			ID: "obf-jsfuck", Name: "JSFuck/Symbolic Obfuscation",
			Description: "Code uses JSFuck-style symbolic obfuscation",
			Category:    CategoryObfuscation, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`\(\s*!\s*\[\s*\]\s*\+\s*\[\s*\]\s*\)`,              // (![]+[])
				`\[\s*\+\s*!\s*\+\s*\[\s*\]\s*\]`,                   // [+!+[]]
				`\(\s*\[\s*\]\s*\[\s*["']constructor["']\s*\]\s*\)`, // ([][\"constructor\"])
			},
		},
		{
			ID: "obf-hex-identifiers", Name: "Hex-Encoded Identifiers",
			Description: "Variables/functions use hex-like names (machine-generated obfuscation)",
			Category:    CategoryObfuscation, Severity: SeverityMedium, Weight: 15,
			Patterns: []string{
				`(?:var|let|const|function)\s+_0x[a-f0-9]{4,}`,
				`(?:var|let|const|function)\s+[a-zA-Z]\s*=`, // single-char variable names in bulk
			},
		},

		// ========================
		// EXECUTION — Process/Command Execution
		// ========================
		{
			ID: "exec-child-process", Name: "Child Process Spawn",
			Description: "Spawning child processes (potential command execution)",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`child_process.*(?:exec|spawn|fork)\s*\(`,
				`require\s*\(\s*["']child_process["']\s*\)`,
				`execSync\s*\(`,
				`spawnSync\s*\(`,
			},
		},
		{
			ID: "exec-shell-command", Name: "Shell Command Execution",
			Description: "Direct shell command execution",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 35,
			Patterns: []string{
				`os\.system\s*\(`,
				`subprocess\.(?:call|run|Popen|check_output)\s*\(`,
				`os/exec\.Command\s*\(`,
				`Runtime\.getRuntime\(\)\.exec\s*\(`,
				`ProcessBuilder\s*\(`,
			},
		},
		{
			ID: "exec-powershell", Name: "PowerShell Execution",
			Description: "PowerShell command execution (common in Windows malware)",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`powershell\s+-(?:e(?:nc)?|EncodedCommand)\s+`,
				`powershell.*-(?:Exec(?:utionPolicy)?)\s+Bypass`,
				`IEX\s*\(\s*(?:New-Object|Invoke-WebRequest)`,
				`\[System\.Convert\]::FromBase64String`,
				`Invoke-Expression`,
			},
		},
		{
			ID: "exec-install-hook", Name: "Package Install Script",
			Description: "Code in npm/pip install hooks (supply chain attack vector)",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`"(?:preinstall|postinstall|preuninstall)"\s*:\s*"`,
				`"install"\s*:\s*"(?:node|python|sh|bash|cmd)`,
				`setup\s*\(\s*[^)]*cmdclass`,
			},
		},

		// ========================
		// DATA ACCESS — Sensitive Data Collection
		// ========================
		{
			ID: "data-keylogger", Name: "Keylogger Pattern",
			Description: "Keyboard event interception (potential keylogger)",
			Category:    CategoryDataAccess, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`addEventListener\s*\(\s*["']key(?:down|up|press)["']`,
				`onkey(?:down|up|press)\s*=`,
				`document\.onkeydown`,
				`SetWindowsHookEx.*(?:WH_KEYBOARD|13)`,
				`GetAsyncKeyState`,
				`CGEventTapCreate.*kCGEventKeyDown`,
			},
		},
		{
			ID: "data-clipboard", Name: "Clipboard Access",
			Description: "Clipboard read/write access (data theft or clipboard hijacking)",
			Category:    CategoryDataAccess, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`navigator\.clipboard\.read`,
				`document\.execCommand\s*\(\s*["'](?:copy|paste)["']`,
				`clipboard\.(?:readText|writeText|read|write)`,
				`electron\.clipboard\.readText`,
				`pbcopy|pbpaste|xclip|xsel`,
			},
		},
		{
			ID: "data-screenshot", Name: "Screen Capture",
			Description: "Screen/window capture functionality",
			Category:    CategoryDataAccess, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`desktopCapturer\.getSources`,
				`navigator\.mediaDevices\.getDisplayMedia`,
				`html2canvas`,
				`captureVisibleTab`,
				`PrintWindow|BitBlt.*GetDC`,
			},
		},
		{
			ID: "data-browser-creds", Name: "Browser Credential Access",
			Description: "Access to browser passwords, cookies, or stored credentials",
			Category:    CategoryDataAccess, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`Login\s*Data|Web\s*Data|Cookies`,
				`(?:Chrome|Firefox|Edge).*(?:Profile|Default).*(?:Login|Cookie|History)`,
				`CryptUnprotectData`,
				`Security\.framework.*SecItemCopyMatching`,
				`gnome-keyring|kwallet|libsecret`,
			},
		},
		{
			ID: "data-env-harvest", Name: "Environment Variable Harvesting",
			Description: "Bulk collection of environment variables (credential/token theft)",
			Category:    CategoryDataAccess, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`process\.env(?:\s|$|\[)`,
				`os\.environ`,
				`os\.Getenv\s*\(`,
				`System\.getenv\s*\(`,
				`(?:HOME|USER|PATH|TOKEN|KEY|SECRET|PASSWORD|AWS_|GITHUB_)`,
			},
			Languages: []string{"js", "py", "go", "java"},
		},

		// ========================
		// PERSISTENCE — Maintaining Access
		// ========================
		{
			ID: "persist-registry", Name: "Windows Registry Modification",
			Description: "Registry key creation/modification (auto-start, settings hijack)",
			Category:    CategoryPersistence, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`(?:HKLM|HKCU|HKEY_).*\\(?:Run|RunOnce|Software)`,
				`RegCreateKeyEx|RegSetValueEx`,
				`New-ItemProperty.*-Path.*Registry`,
				`reg\s+add\s+`,
			},
		},
		{
			ID: "persist-cron-task", Name: "Scheduled Task/Cron Creation",
			Description: "Creating scheduled tasks or cron jobs for persistence",
			Category:    CategoryPersistence, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`schtasks\s+/create`,
				`crontab\s+-`,
				`Register-ScheduledTask`,
				`launchctl\s+load`,
				`systemctl\s+enable`,
			},
		},
		{
			ID: "persist-startup", Name: "Startup Directory/Autostart",
			Description: "Writing to startup directories for automatic execution",
			Category:    CategoryPersistence, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`(?:Start\s*Menu|Startup).*\.(?:lnk|bat|cmd|vbs|exe)`,
				`autostart|\.config/autostart`,
				`LoginItems|LaunchAgents|LaunchDaemons`,
				`app\.setLoginItemSettings`,
			},
		},

		// ========================
		// EVASION — Anti-Analysis
		// ========================
		{
			ID: "evasion-debugger", Name: "Anti-Debugging",
			Description: "Debug detection or prevention (anti-analysis technique)",
			Category:    CategoryEvasion, Severity: SeverityHigh, Weight: 20,
			Patterns: []string{
				`\bdebugger\b`,
				`IsDebuggerPresent`,
				`NtQueryInformationProcess.*ProcessDebugPort`,
				`ptrace\s*\(\s*PTRACE_TRACEME`,
				`anti_debug|antiDebug|isDebugged`,
			},
		},
		{
			ID: "evasion-vm-detect", Name: "Virtual Machine Detection",
			Description: "VM/sandbox detection (malware trying to evade analysis)",
			Category:    CategoryEvasion, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`(?:VMware|VirtualBox|QEMU|Xen|Hyper-V|Parallels)`,
				`vmtoolsd|vboxservice|vboxguest`,
				`SMBIOS.*Virtual|dmidecode.*manufacturer`,
				`SystemInfo.*(?:VM|Virtual)`,
			},
		},
		{
			ID: "evasion-sandbox", Name: "Sandbox Detection",
			Description: "Sandbox environment detection (evading automated analysis)",
			Category:    CategoryEvasion, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`(?:sandbox|malwr|anubis|cuckoo|joe\s*sandbox)`,
				`SbieDll\.dll|snxhk\.dll|dbghelp\.dll`,
				`(?:GetTickCount|QueryPerformanceCounter).*(?:Sleep|delay)`,
				`navigator\.(?:webdriver|languages\.length)`,
			},
		},
		{
			ID: "evasion-timing", Name: "Timing-Based Evasion",
			Description: "Delayed execution to evade sandboxes with short timeouts",
			Category:    CategoryEvasion, Severity: SeverityMedium, Weight: 15,
			Patterns: []string{
				`setTimeout\s*\([^,]+,\s*(?:[3-9]\d{4}|\d{5,})`, // >30s delay
				`sleep\s*\(\s*(?:[3-9]\d|[1-9]\d{2,})`,          // sleep(30+)
				`time\.Sleep\s*\(\s*\d+\s*\*\s*time\.(?:Minute|Hour)`,
			},
		},

		// ========================
		// CRYPTO — Mining & Wallet Theft
		// ========================
		{
			ID: "crypto-miner", Name: "Cryptocurrency Miner",
			Description: "Crypto mining code or library references",
			Category:    CategoryCrypto, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`coinhive|cryptonight|stratum\+tcp://`,
				`(?:CoinImp|JSEcoin|Crypto-Loot|WebMinePool)`,
				`wasm.*(?:mining|miner|hash)`,
				`navigator\.hardwareConcurrency.*Worker`,
			},
		},
		{
			ID: "crypto-wallet", Name: "Cryptocurrency Wallet Access",
			Description: "Access to cryptocurrency wallets or seed phrases",
			Category:    CategoryCrypto, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`wallet\.dat|\.ethereum/keystore`,
				`(?:bitcoin|ethereum|monero|solana).*(?:address|wallet|key)`,
				`(?:seed|mnemonic|recovery)\s*(?:phrase|words)`,
				`(?:MetaMask|Phantom|Trust\s*Wallet).*(?:vault|storage|keyring)`,
			},
		},

		// ========================
		// SUPPLY CHAIN — Package Manipulation
		// ========================
		{
			ID: "supply-typosquat", Name: "Typosquatting Indicators",
			Description: "Package naming patterns that suggest typosquatting",
			Category:    CategorySupplyChain, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`"(?:name|packageName)"\s*:\s*"[^"]*(?:lodassh|reacct|axio5|expresss|requets)[^"]*"`,
			},
		},
		{
			ID: "supply-postinstall-net", Name: "Install Hook with Network",
			Description: "Package install script that makes network requests",
			Category:    CategorySupplyChain, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`"postinstall"\s*:\s*"(?:node|python|curl|wget|bash)`,
				`"preinstall"\s*:\s*"(?:node|python|curl|wget|bash)`,
			},
		},
		{
			ID: "supply-dep-confusion", Name: "Dependency Confusion Indicators",
			Description: "Internal package name patterns with private registry references",
			Category:    CategorySupplyChain, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`"publishConfig"\s*:\s*\{[^}]*"registry"\s*:\s*"https?://(?:artifactory|nexus|verdaccio|gitlab|jfrog)`,
				`--registry\s+https?://(?:artifactory|nexus|verdaccio|gitlab|jfrog)`,
			},
		},
	}
}
