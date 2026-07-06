package heuristic

// AdvancedPatterns returns modern attack technique and CVE detection patterns.
func AdvancedPatterns() []Pattern {
	return []Pattern{
		// ========================
		// CVE EXPLOITATION PATTERNS
		// ========================
		{
			ID: "cve-prototype-pollution", Name: "Prototype Pollution (CVE-2019-11358, CVE-2020-28499)",
			Description: "Object prototype manipulation — can lead to RCE or property injection",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`__proto__\s*[\[.]`,
				`constructor\s*\[\s*["']prototype["']\s*\]`,
				`Object\.assign\s*\(\s*\{\}\s*,.*__proto__`,
				`\.prototype\s*\[\s*[^"'\]]+\s*\]\s*=`,
			},
		},
		{
			ID: "cve-log4shell", Name: "Log4Shell Pattern (CVE-2021-44228)",
			Description: "JNDI lookup injection — remote code execution via logging",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`\$\{jndi:(?:ldap|rmi|dns|iiop)://`,
				`\$\{(?:lower|upper|env|sys|java):`,
				`BasicDataSource.*(?:jdbc|jndi)`,
			},
			Languages: []string{"java", "xml", "properties", "yaml"},
		},
		{
			ID: "cve-path-traversal", Name: "Path Traversal (CWE-22)",
			Description: "Directory traversal allowing file access outside intended path",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`\.\.[/\\](?:\.\.[/\\]){2,}`,                                         // ../../../ (3+ levels)
				`(?:readFile|readFileSync|open)\s*\([^)]*(?:req\.|params\.|query\.)`, // user input in file ops
				`path\.join\s*\([^)]*(?:req\.|params\.|query\.)`,
				`os\.Open\s*\([^)]*(?:r\.|params\.|vars)`,
			},
		},
		{
			ID: "cve-ssrf", Name: "Server-Side Request Forgery (CWE-918)",
			Description: "User-controlled URL in server-side request — SSRF vector",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`(?:fetch|axios|request|http\.get|urllib)\s*\([^)]*(?:req\.(?:body|query|params)|user_?input)`,
				`(?:url|uri|endpoint)\s*=\s*(?:req\.|request\.|params\.)`,
				`169\.254\.169\.254`, // AWS metadata endpoint
				`metadata\.google\.internal`,
			},
		},
		{
			ID: "cve-sqli", Name: "SQL Injection (CWE-89)",
			Description: "String concatenation in SQL queries — SQL injection vector",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*[+]\s*(?:req\.|params\.|user|input)`,
				`(?:query|exec|execute)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE).*[+$]`,
				`(?:query|exec)\s*\(\s*["'].*\$\{`,
				`fmt\.Sprintf\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)`,
				`f["'](?:SELECT|INSERT|UPDATE|DELETE).*\{`,
			},
		},
		{
			ID: "cve-xss", Name: "Cross-Site Scripting (CWE-79)",
			Description: "Unescaped user input in HTML output — XSS vector",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`innerHTML\s*=\s*[^"'\s]`,
				`document\.write\s*\(`,
				`\.html\s*\(\s*[^"'<\s)"]`,
				`dangerouslySetInnerHTML`,
				`v-html\s*=`,
				`\{\{\{.*\}\}\}`, // triple mustache (unescaped Handlebars)
			},
		},
		{
			ID: "cve-deserialization", Name: "Unsafe Deserialization (CWE-502)",
			Description: "Deserializing untrusted data — remote code execution risk",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`pickle\.loads?\s*\(`,
				`yaml\.unsafe_load\s*\(`,
				`yaml\.load\s*\(\s*[^,)]+\s*\)`, // yaml.load() with no Loader arg
				`ObjectInputStream\s*\(`,
				`unserialize\s*\(\s*\$`,
				`Marshal\.load\s*\(`,
				`jsonpickle\.decode`,
				`shelve\.open`,
			},
		},
		{
			ID: "cve-cmd-injection", Name: "Command Injection (CWE-78)",
			Description: "User input in system command — command injection vector",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`(?:exec|system|popen|spawn)\s*\([^)]*(?:req\.|params\.|user|input|\$|` + "`" + `)`,
				`os\.system\s*\(\s*f["']`,
				`subprocess\.\w+\s*\(\s*f["']`,
				`exec\.Command\s*\([^)]*fmt\.Sprintf`,
				`Runtime\.exec\s*\([^)]*\+`,
			},
		},
		{
			ID: "cve-xxe", Name: "XML External Entity (CWE-611)",
			Description: "XML parser with external entity processing enabled",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`<!ENTITY\s+\w+\s+SYSTEM`,
				`<!DOCTYPE[^>]*\[.*<!ENTITY`,
				`XMLReader.*(?:PROCESS_NAMESPACES|external)`,
				`xml\.NewDecoder.*(?:Strict|Entity)`,
				`DocumentBuilderFactory.*setFeature.*false`,
			},
		},

		// ========================
		// MODERN SUPPLY CHAIN ATTACKS
		// ========================
		{
			ID: "supply-event-stream", Name: "Event-Stream Style Attack",
			Description: "Conditional payload that activates only for specific targets (like event-stream CVE-2018-16492)",
			Category:    CategorySupplyChain, Severity: SeverityCritical, Weight: 45,
			Patterns: []string{
				`process\.env\.npm_package_(?:name|description)`,
				`require\s*\(\s*["'](?:flatmap-stream|event-stream)["']\s*\)`,
				`Buffer\.from\s*\([^)]+,\s*["']hex["']\s*\)\.toString\s*\(`,
			},
		},
		{
			ID: "supply-colors-faker", Name: "Protestware/Sabotage Pattern",
			Description: "Infinite loop or data destruction in package (like colors.js/faker.js)",
			Category:    CategorySupplyChain, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`for\s*\(\s*;;\s*\)\s*\{`, // for(;;){
				`while\s*\(\s*true\s*\)\s*\{[^}]*(?:console\.log|process\.stdout)`,
				`(?:fs\.)?(?:rm|unlink)Sync\s*\(\s*["']/`,
				`process\.exit\s*\(\s*[1-9]`,
			},
		},
		{
			ID: "supply-node-ipc", Name: "Geopolitical Payload (node-ipc style)",
			Description: "Code targeting specific geolocations or overwriting files based on locale",
			Category:    CategorySupplyChain, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone`,
				`(?:timezone|locale|country).*(?:writeFile|unlink|rm|overwrite)`,
				`(?:RU|BY|CN|IR|KP).*(?:delete|destroy|overwrite|wipe)`,
			},
		},

		// ========================
		// MODERN OBFUSCATION TECHNIQUES
		// ========================
		{
			ID: "obf-control-flow-flat", Name: "Control Flow Flattening",
			Description: "Switch-case inside while(true) loop — control flow flattening obfuscation",
			Category:    CategoryObfuscation, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`while\s*\(\s*!!\[\]\s*\)\s*\{[^}]*switch\s*\(`,
				`while\s*\(\s*true\s*\)\s*\{[^}]*switch\s*\(\s*\w+\[\w+\+\+\]`,
				`var\s+\w+\s*=\s*["'][0-9|]+["']\.split\s*\(\s*["']\|["']\s*\)`,
			},
		},
		{
			ID: "obf-dead-code", Name: "Dead Code Injection",
			Description: "Unreachable code blocks designed to confuse analysis",
			Category:    CategoryObfuscation, Severity: SeverityMedium, Weight: 10,
			Patterns: []string{
				`if\s*\(\s*(?:false|0|null|void\s*0|!""\s*)\s*\)\s*\{`,
				`if\s*\(\s*typeof\s+\w+\s*===?\s*["']undefined["']\s*&&\s*typeof\s+\w+\s*===?\s*["']undefined["']\s*\)`,
			},
		},
		{
			ID: "obf-rc4-decrypt", Name: "RC4/Custom Decryption Routine",
			Description: "Embedded decryption routine for payload deobfuscation",
			Category:    CategoryObfuscation, Severity: SeverityCritical, Weight: 35,
			Patterns: []string{
				`(?:rc4|decrypt|decipher|decode)\s*(?:=\s*function|\s*\().*(?:charCodeAt|fromCharCode|XOR|\^)`,
				`for\s*\([^)]*\)\s*\{[^}]*\^\s*(?:key|password|secret)`,
				`(?:AES|DES|RC4).*(?:decrypt|decipher).*(?:eval|Function|exec)`,
			},
		},
		{
			ID: "obf-proxy-handler", Name: "Proxy/Reflect Obfuscation",
			Description: "JavaScript Proxy or Reflect API used to trap property access (anti-analysis)",
			Category:    CategoryObfuscation, Severity: SeverityMedium, Weight: 15,
			Patterns: []string{
				`new\s+Proxy\s*\([^,]+,\s*\{[^}]*(?:get|set|apply|construct)\s*:`,
				`Reflect\.(?:apply|construct|get|set)\s*\(`,
			},
		},

		// ========================
		// MODERN C2 / EXFILTRATION
		// ========================
		{
			ID: "net-doh-exfil", Name: "DNS-over-HTTPS Exfiltration",
			Description: "DNS queries via HTTPS (covert C2 channel that bypasses traditional DNS monitoring)",
			Category:    CategoryNetwork, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`dns\.google/resolve`,
				`cloudflare-dns\.com/dns-query`,
				`doh\.(?:opendns|cleanbrowsing|quad9)`,
				`(?:application/dns-json|application/dns-message)`,
			},
		},
		{
			ID: "net-webrtc-exfil", Name: "WebRTC Data Channel Exfiltration",
			Description: "WebRTC data channel used for covert peer-to-peer data transfer",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`RTCPeerConnection.*createDataChannel`,
				`RTCDataChannel.*(?:send|onmessage)`,
				`\.createOffer\s*\(.*\.setLocalDescription`,
			},
		},
		{
			ID: "net-stego", Name: "Steganography Indicators",
			Description: "Pixel-level image manipulation suggesting steganographic data hiding",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`getImageData.*(?:charCodeAt|fromCharCode)`,
				`putImageData.*(?:data\[\w+\]\s*&\s*0xfe|data\[\w+\]\s*\|\s*[01])`,
				`(?:LSB|lsb|least.significant.bit)`,
				`canvas.*toDataURL.*(?:fetch|send|post)`,
			},
		},
		{
			ID: "net-sse-abuse", Name: "Server-Sent Events C2",
			Description: "EventSource/SSE used as persistent C2 channel",
			Category:    CategoryNetwork, Severity: SeverityMedium, Weight: 15,
			Patterns: []string{
				`new\s+EventSource\s*\(\s*[^"']`, // dynamic SSE URL
				`EventSource.*(?:onmessage|addEventListener).*(?:eval|Function|exec)`,
			},
		},

		// ========================
		// ELECTRON-SPECIFIC BACKDOORS
		// ========================
		{
			ID: "electron-preload-inject", Name: "Electron Preload Injection",
			Description: "Dynamic preload script path or eval in preload context",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`webPreferences.*preload.*(?:\+|concat|join|resolve)\s*\(`,
				`(?:contextBridge|ipcRenderer).*(?:eval|Function)`,
				`nodeIntegration\s*:\s*true`,
				`contextIsolation\s*:\s*false`,
			},
		},
		{
			ID: "electron-protocol-abuse", Name: "Electron Protocol Handler Abuse",
			Description: "Custom protocol handler that can execute code",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`protocol\.register(?:File|Buffer|String|Http|Stream)Protocol`,
				`protocol\.interceptFileProtocol`,
				`registerFileProtocol.*(?:req\.url|request\.url)`,
				`app\.setAsDefaultProtocolClient`,
			},
		},
		{
			ID: "electron-remote-module", Name: "Electron Remote Module",
			Description: "Remote module enabled (deprecated, allows renderer RCE)",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 35,
			Patterns: []string{
				`enableRemoteModule\s*:\s*true`,
				`@electron/remote`,
				`require\s*\(\s*["']electron["']\s*\)\.remote`,
			},
		},

		// ========================
		// BROWSER EXTENSION ATTACKS (MV3)
		// ========================
		{
			ID: "ext-offscreen-abuse", Name: "Offscreen Document Abuse",
			Description: "Offscreen document used for hidden computation or network activity",
			Category:    CategoryEvasion, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`chrome\.offscreen\.createDocument`,
				`offscreen.*(?:fetch|XMLHttpRequest|WebSocket)`,
				`"reasons"\s*:\s*\[\s*"WORKERS"`,
			},
		},
		{
			ID: "ext-dnr-redirect", Name: "DeclarativeNetRequest Hijack",
			Description: "Network request redirection via declarativeNetRequest rules",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`declarativeNetRequest.*redirect`,
				`"action"\s*:\s*\{[^}]*"type"\s*:\s*"redirect"`,
				`updateDynamicRules.*addRules`,
			},
		},
		{
			ID: "ext-content-script-eval", Name: "Content Script Code Injection",
			Description: "Content script that injects or evaluates external code",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 35,
			Patterns: []string{
				`chrome\.scripting\.executeScript.*(?:func|code)`,
				`chrome\.tabs\.executeScript.*(?:code|file)`,
				`document\.head\.appendChild.*script.*src`,
			},
		},

		// ========================
		// FILELESS / IN-MEMORY ATTACKS
		// ========================
		{
			ID: "fileless-dotnet-reflect", Name: ".NET Reflection Loading",
			Description: "Loading assemblies from memory via reflection (fileless execution)",
			Category:    CategoryExecution, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`Assembly\.Load\s*\(\s*(?:byte|Convert)`,
				`\[Reflection\.Assembly\]::Load`,
				`Activator\.CreateInstance`,
				`CompileAssemblyFromSource`,
			},
		},
		{
			ID: "fileless-amsi-bypass", Name: "AMSI Bypass Attempt",
			Description: "Attempting to disable Windows Antimalware Scan Interface",
			Category:    CategoryEvasion, Severity: SeverityCritical, Weight: 50,
			Patterns: []string{
				`amsi\.dll`,
				`AmsiScanBuffer`,
				`amsiInitFailed`,
				`\[Ref\]\.Assembly\.GetType.*amsi`,
				`Set-MpPreference.*-DisableRealtimeMonitoring`,
			},
		},
		{
			ID: "fileless-wmi-exec", Name: "WMI Execution",
			Description: "Windows Management Instrumentation used for code execution",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 30,
			Patterns: []string{
				`Win32_Process.*Create`,
				`wmic\s+process\s+call\s+create`,
				`ManagementClass.*Win32_Process`,
				`Get-WmiObject.*Win32_Process`,
			},
		},

		// ========================
		// WASM / ADVANCED PAYLOADS
		// ========================
		{
			ID: "wasm-suspicious", Name: "Suspicious WebAssembly Usage",
			Description: "WebAssembly instantiation from network or encoded source",
			Category:    CategoryExecution, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`WebAssembly\.instantiate\s*\(\s*(?:fetch|response|buffer)`,
				`WebAssembly\.compile\s*\(\s*(?:new\s+Uint8Array|Buffer)`,
				`\.wasm.*(?:crypto|mine|hash|encrypt)`,
			},
		},

		// ========================
		// DATA THEFT — MODERN TECHNIQUES
		// ========================
		{
			ID: "data-formjacking", Name: "Form Jacking / Input Interception",
			Description: "Intercepting form submissions to steal credentials",
			Category:    CategoryDataAccess, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`addEventListener\s*\(\s*["']submit["'].*(?:fetch|XMLHttpRequest|sendBeacon|navigator\.sendBeacon)`,
				`querySelector.*(?:password|credit.?card|cvv|ssn).*(?:value|textContent)`,
				`input\[type=["']password["']\].*(?:addEventListener|onchange|oninput)`,
				`MutationObserver.*(?:input|form).*(?:send|fetch|post)`,
			},
		},
		{
			ID: "data-camera-mic", Name: "Camera/Microphone Access",
			Description: "Accessing camera or microphone (potential surveillance)",
			Category:    CategoryDataAccess, Severity: SeverityHigh, Weight: 25,
			Patterns: []string{
				`getUserMedia\s*\(\s*\{[^}]*(?:video|audio)\s*:\s*true`,
				`mediaDevices\.getUserMedia`,
				`enumerateDevices.*(?:videoinput|audioinput)`,
				`MediaRecorder\s*\(`,
			},
		},
		{
			ID: "data-cookie-theft", Name: "Cookie Exfiltration",
			Description: "Reading and transmitting cookies to external server",
			Category:    CategoryDataAccess, Severity: SeverityCritical, Weight: 40,
			Patterns: []string{
				`document\.cookie.*(?:fetch|XMLHttpRequest|sendBeacon|img\.src|new\s+Image)`,
				`(?:fetch|axios|request)\s*\([^)]*document\.cookie`,
				`(?:chrome|browser)\.cookies\.getAll`,
			},
		},

		// ========================
		// NETWORK — ADDITIONAL MODERN
		// ========================
		{
			ID: "net-beacon", Name: "Navigator.sendBeacon Exfiltration",
			Description: "sendBeacon API used for stealthy data exfiltration (fires even on page close)",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 20,
			Patterns: []string{
				`navigator\.sendBeacon\s*\(\s*[^"']`, // dynamic URL
				`sendBeacon.*(?:cookie|password|token|credential|localStorage)`,
			},
		},
		{
			ID: "net-service-worker-intercept", Name: "Service Worker Network Interception",
			Description: "Service worker intercepting and modifying network requests",
			Category:    CategoryNetwork, Severity: SeverityHigh, Weight: 20,
			Patterns: []string{
				`addEventListener\s*\(\s*["']fetch["'].*respondWith`,
				`FetchEvent.*(?:clone|redirect|Response\s*\()`,
				`caches\.open.*(?:put|add)`,
			},
		},
	}
}

func init() {
	// Merge advanced patterns into default set.
	// This is done via init so NewDefaultScanner picks them up.
}
