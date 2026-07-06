/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"fmt"
	"path/filepath"
	"strings"
)

// GenerateAIPrompt builds a contextual system prompt for AI-assisted Android
// app dissection based on the collected dissect results. The prompt instructs
// the AI to extract and analyze every resource layer of the APK, leaving
// nothing unexamined.
func GenerateAIPrompt(r *DissectResult) string {
	var sb strings.Builder

	sb.WriteString("# Android APK Deep Dissection — AI System Prompt\n\n")
	sb.WriteString("You are performing an exhaustive reverse-engineering analysis of an Android application.\n")
	sb.WriteString("Your goal is to extract, decode, and document **every single resource** in the package\n")
	sb.WriteString("until there is nothing left to examine. Leave no file unopened, no bytecode unread,\n")
	sb.WriteString("no string unexplored.\n\n")

	// --- Target overview ---
	sb.WriteString("## Target\n\n")
	sb.WriteString(fmt.Sprintf("- **File:** `%s`\n", r.FileName))
	sb.WriteString(fmt.Sprintf("- **Path:** `%s`\n", r.Path))
	sb.WriteString(fmt.Sprintf("- **Size:** %s\n", formatReportSize(r.Size)))
	sb.WriteString(fmt.Sprintf("- **Detected Type:** %s\n", r.Detection.FileType))

	if r.Detection.Details != "" {
		sb.WriteString(fmt.Sprintf("- **Details:** %s\n", r.Detection.Details))
	}

	sb.WriteString("\n")

	// --- APK structure ---
	if r.APKInfo != nil {
		sb.WriteString("## APK Structure (already collected)\n\n")
		sb.WriteString(fmt.Sprintf("- Format: **%s**\n", r.APKInfo.Format))
		sb.WriteString(fmt.Sprintf("- Total files: **%d**\n", r.APKInfo.TotalFiles))
		sb.WriteString(fmt.Sprintf("- DEX files: **%d** — `%s`\n", r.APKInfo.DEXCount, strings.Join(r.APKInfo.DEXFiles, "`, `")))
		sb.WriteString(fmt.Sprintf("- Has AndroidManifest.xml: **%v**\n", r.APKInfo.HasManifest))
		sb.WriteString(fmt.Sprintf("- Has resources (res/): **%v**\n", r.APKInfo.HasResources))
		sb.WriteString(fmt.Sprintf("- Has assets (assets/): **%v**\n", r.APKInfo.HasAssets))
		sb.WriteString(fmt.Sprintf("- Has Kotlin metadata: **%v**\n", r.APKInfo.HasKotlin))

		if len(r.APKInfo.NativeLibs) > 0 {
			var abis []string
			for abi, count := range r.APKInfo.NativeLibs {
				abis = append(abis, fmt.Sprintf("%s (%d .so)", abi, count))
			}

			sb.WriteString(fmt.Sprintf("- Native libraries: **%s**\n", strings.Join(abis, ", ")))
		} else {
			sb.WriteString("- Native libraries: **none**\n")
		}

		if len(r.APKInfo.SignatureSchemes) > 0 {
			sb.WriteString(fmt.Sprintf("- Signature schemes: **%s**\n", strings.Join(r.APKInfo.SignatureSchemes, ", ")))
		}

		if r.APKInfo.BundleInfo != nil {
			bi := r.APKInfo.BundleInfo
			if bi.PackageName != "" {
				sb.WriteString(fmt.Sprintf("- Package name: **%s**\n", bi.PackageName))
			}

			if bi.VersionName != "" {
				sb.WriteString(fmt.Sprintf("- Version: **%s** (code %d)\n", bi.VersionName, bi.VersionCode))
			}
		}

		if len(r.APKInfo.SplitAPKs) > 0 {
			sb.WriteString(fmt.Sprintf("- Split APKs: **%s**\n", strings.Join(r.APKInfo.SplitAPKs, ", ")))
		}

		sb.WriteString("\n")
	}

	// --- Signing & certificates ---
	if r.APKVerify != nil || r.APKCert != nil {
		sb.WriteString("## Signing & Certificates (already collected)\n\n")

		if r.APKVerify != nil {
			sb.WriteString(fmt.Sprintf("- Overall valid: **%v**\n", r.APKVerify.OverallValid))
		}

		if r.APKCert != nil {
			for i, c := range r.APKCert.Certificates {
				sb.WriteString(fmt.Sprintf("- Cert %d — Subject: `%s`, Issuer: `%s`, Algo: %s, SHA-256: `%s`\n",
					i+1, c.Subject, c.Issuer, c.SignatureAlgorithm, c.Fingerprint.SHA256))
			}
		}

		sb.WriteString("\n")
	}

	// --- Parsed manifest ---
	if r.ManifestInfo != nil {
		sb.WriteString("## Parsed AndroidManifest.xml (already decoded)\n\n")
		sb.WriteString(fmt.Sprintf("- Package: **%s**\n", r.ManifestInfo.Package))
		sb.WriteString(fmt.Sprintf("- Version: **%s** (code %d)\n", r.ManifestInfo.VersionName, r.ManifestInfo.VersionCode))
		sb.WriteString(fmt.Sprintf("- Min SDK: **%d**, Target SDK: **%d**\n", r.ManifestInfo.MinSDK, r.ManifestInfo.TargetSDK))
		sb.WriteString(fmt.Sprintf("- Debuggable: **%v**, Allow Backup: **%v**, Cleartext: **%v**\n",
			r.ManifestInfo.Security.Debuggable, r.ManifestInfo.Security.AllowBackup,
			r.ManifestInfo.Security.UsesCleartextTraffic))

		if len(r.ManifestInfo.Permissions) > 0 {
			sb.WriteString(fmt.Sprintf("- Permissions: **%d** total\n", len(r.ManifestInfo.Permissions)))

			for _, p := range r.ManifestInfo.Permissions {
				tag := ""
				if p.RiskLevel == "dangerous" {
					tag = " ⚠ DANGEROUS"
				}

				sb.WriteString(fmt.Sprintf("  - `%s`%s\n", p.Name, tag))
			}
		}

		if len(r.ManifestInfo.Components) > 0 {
			sb.WriteString(fmt.Sprintf("- Components: **%d**\n", len(r.ManifestInfo.Components)))

			for _, c := range r.ManifestInfo.Components {
				exported := ""
				if c.Exported != nil && *c.Exported {
					exported = " **[EXPORTED]**"
				}

				sb.WriteString(fmt.Sprintf("  - [%s] `%s`%s\n", c.Type, c.Name, exported))
			}
		}

		sb.WriteString("\n")
	}

	// --- Secret scan results ---
	if r.Secrets != nil && r.Secrets.TotalFindings > 0 {
		sb.WriteString("## Secret Scan Results (already collected)\n\n")
		sb.WriteString(fmt.Sprintf("- **%d** findings (%d high confidence, %d medium)\n",
			r.Secrets.TotalFindings, r.Secrets.HighConfidence, r.Secrets.MedConfidence))

		for _, f := range r.Secrets.Findings {
			sb.WriteString(fmt.Sprintf("- [%s] **%s** `%s` in `%s`\n",
				f.Confidence, f.Type, f.Value, f.File))
		}

		sb.WriteString("\n")
	}

	// --- Output directories ---
	if r.APKExtract != nil || r.Decompile != nil {
		sb.WriteString("## Extracted Artifacts\n\n")

		if r.APKExtract != nil {
			sb.WriteString(fmt.Sprintf("- **Raw extraction:** `%s` (%d files, %s)\n",
				r.APKExtract.Output, r.APKExtract.Files, formatReportSize(r.APKExtract.TotalSize)))
		}

		if r.Decompile != nil {
			sb.WriteString(fmt.Sprintf("- **Decompiled output:** `%s`\n", r.Decompile.OutputDir))

			if len(r.Decompile.ToolsUsed) > 0 {
				sb.WriteString(fmt.Sprintf("- Tools that ran: **%s**\n", strings.Join(r.Decompile.ToolsUsed, ", ")))
			}

			if len(r.Decompile.ToolsMissing) > 0 {
				sb.WriteString(fmt.Sprintf("- Tools missing (install to unlock deeper analysis): **%s**\n",
					strings.Join(r.Decompile.ToolsMissing, ", ")))
			}
		}

		sb.WriteString("\n")
	}

	// --- Available tools ---
	if r.ToolsStatus != nil {
		sb.WriteString("## Available RE Tools\n\n")
		sb.WriteString(fmt.Sprintf("%d of %d tools detected on this system.\n\n", r.ToolsStatus.Available, r.ToolsStatus.Total))

		for _, t := range r.ToolsStatus.Tools {
			status := "NOT FOUND"
			if t.Available {
				status = "available"
				if t.Version != "" {
					status = t.Version
				}
			}

			sb.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", t.Name, t.Description, status))
		}

		sb.WriteString("\n")
	}

	// --- Extraction instructions ---
	sb.WriteString("## Extraction Checklist — Leave Nothing Behind\n\n")
	sb.WriteString("Work through every layer below. For each item, extract the content, analyze it,\n")
	sb.WriteString("and report what you find. Do NOT skip any step, even if it seems empty.\n\n")

	sb.WriteString("### 1. AndroidManifest.xml\n\n")
	sb.WriteString("- Decode the binary XML to human-readable form (apktool or aapt2 dump).\n")
	sb.WriteString("- Extract: package name, version, min/target SDK, all permissions,\n")
	sb.WriteString("  all activities, services, receivers, providers, intent-filters,\n")
	sb.WriteString("  meta-data entries, uses-features, application attributes.\n")
	sb.WriteString("- Flag any dangerous or custom permissions.\n")
	sb.WriteString("- Flag exported components with no permission guards.\n")
	sb.WriteString("- Flag android:debuggable, android:allowBackup, android:usesCleartextTraffic.\n")

	if r.APKExtract != nil {
		sb.WriteString(fmt.Sprintf("- Raw file: `%s/AndroidManifest.xml`\n", r.APKExtract.Output))
	}

	if r.Decompile != nil {
		sb.WriteString(fmt.Sprintf("- Decoded file: `%s/apktool/AndroidManifest.xml`\n", r.Decompile.OutputDir))
	}

	sb.WriteString("\n")

	sb.WriteString("### 2. DEX / Java Source Code\n\n")
	sb.WriteString("- If jadx output exists, read the decompiled Java/Kotlin source tree.\n")
	sb.WriteString("- If only smali exists (apktool), analyze the smali bytecode directly.\n")
	sb.WriteString("- Map the full class hierarchy. Identify:\n")
	sb.WriteString("  - Entry points (Application subclass, launcher Activity, ContentProviders).\n")
	sb.WriteString("  - Network layer (OkHttp, Retrofit, Volley, HttpURLConnection usage).\n")
	sb.WriteString("  - API endpoints, base URLs, hardcoded tokens or keys.\n")
	sb.WriteString("  - Crypto usage (AES, RSA, certificate pinning, key derivation).\n")
	sb.WriteString("  - Obfuscated or packed code (check for ProGuard/R8/DexGuard markers).\n")
	sb.WriteString("  - Dynamic code loading (DexClassLoader, PathClassLoader, reflection).\n")
	sb.WriteString("  - Root / emulator / Frida detection routines.\n")
	sb.WriteString("  - WebView usage and JavaScript bridges (addJavascriptInterface).\n")
	sb.WriteString("  - SharedPreferences, SQLite, Room, DataStore usage.\n")
	sb.WriteString("  - Firebase, analytics, crash reporting, tracking SDKs.\n")
	sb.WriteString("  - IPC mechanisms (Intents, AIDL, Messenger, Binder).\n")

	if r.Decompile != nil {
		sb.WriteString(fmt.Sprintf("- Jadx source tree: `%s/jadx/`\n", r.Decompile.OutputDir))
		sb.WriteString(fmt.Sprintf("- Smali from apktool: `%s/apktool/smali*/`\n", r.Decompile.OutputDir))
	}

	sb.WriteString("\n")

	sb.WriteString("### 3. Resources (res/)\n\n")
	sb.WriteString("- Decode all binary XML resources (layouts, drawables, values, xml/).\n")
	sb.WriteString("- Extract from `res/values/strings.xml`: all user-visible strings, URLs,\n")
	sb.WriteString("  API keys, configuration values.\n")
	sb.WriteString("- Check `res/xml/` for: network_security_config.xml (cleartext, pinning),\n")
	sb.WriteString("  backup_rules.xml, file_provider_paths.xml, shortcuts.xml.\n")
	sb.WriteString("- Check `res/raw/` for: embedded databases, certificates, config files, JSON, scripts.\n")
	sb.WriteString("- Examine layouts for WebView configurations.\n")

	if r.Decompile != nil {
		sb.WriteString(fmt.Sprintf("- Decoded resources: `%s/apktool/res/`\n", r.Decompile.OutputDir))
	}

	sb.WriteString("\n")

	sb.WriteString("### 4. Assets (assets/)\n\n")
	sb.WriteString("- List every file in assets/. This is where apps hide:\n")
	sb.WriteString("  - Embedded databases (.db, .sqlite, .realm)\n")
	sb.WriteString("  - Web content (HTML, JS, CSS — hybrid apps, Cordova, React Native bundles)\n")
	sb.WriteString("  - Configuration files (JSON, YAML, TOML, .properties)\n")
	sb.WriteString("  - Model files (TFLite, ONNX, ML models)\n")
	sb.WriteString("  - Encrypted or packed payloads (look for high-entropy blobs)\n")
	sb.WriteString("  - Certificate bundles, custom CA stores\n")
	sb.WriteString("  - Lua/Python/Wasm scripts\n")
	sb.WriteString("- For each file, identify its type and extract meaningful content.\n")

	if r.APKExtract != nil {
		sb.WriteString(fmt.Sprintf("- Raw assets: `%s/assets/`\n", r.APKExtract.Output))
	}

	sb.WriteString("\n")

	sb.WriteString("### 5. Native Libraries (lib/)\n\n")

	// Consult BOTH the thin APKInfo parse AND the dedicated native_analysis
	// result: `app dissect` populates r.NativeAnalysis (native.ScanAPK), not
	// APKInfo.NativeLibs, so relying on APKInfo alone falsely reports "no native
	// libraries" on APKs that clearly have them.
	if (r.APKInfo != nil && len(r.APKInfo.NativeLibs) > 0) ||
		(r.NativeAnalysis != nil && r.NativeAnalysis.TotalLibs > 0) {
		sb.WriteString("- This APK contains native code. For each .so file:\n")
		sb.WriteString("  - Run `file` to confirm architecture and linking.\n")
		sb.WriteString("  - Extract strings (look for URLs, paths, format strings, error messages).\n")
		sb.WriteString("  - Check for JNI exports (Java_* symbols) — these bridge Java to native.\n")
		sb.WriteString("  - Look for anti-tampering or integrity checks.\n")
		sb.WriteString("  - If retdec is available, decompile to pseudo-C for deeper analysis.\n")
		sb.WriteString("  - Check for known libraries: libflutter.so (Flutter), libreactnativejni.so (RN),\n")
		sb.WriteString("    libmonodroid.so (Xamarin), libil2cpp.so (Unity).\n")
	} else {
		sb.WriteString("- No native libraries detected. Confirm by checking `lib/` in extraction.\n")
	}

	if r.APKExtract != nil {
		sb.WriteString(fmt.Sprintf("- Raw .so files: `%s/lib/`\n", r.APKExtract.Output))
	}

	if r.Decompile != nil {
		sb.WriteString(fmt.Sprintf("- Decompiled native: `%s/native/`\n", r.Decompile.OutputDir))
	}

	sb.WriteString("\n")

	sb.WriteString("### 6. META-INF/\n\n")
	sb.WriteString("- Extract and examine:\n")
	sb.WriteString("  - MANIFEST.MF — hashes of every file in the APK.\n")
	sb.WriteString("  - *.SF — signed hashes.\n")
	sb.WriteString("  - *.RSA / *.DSA / *.EC — signing certificates (parse with openssl).\n")
	sb.WriteString("  - Any extra files (some apps put configs or version files here).\n")

	if r.APKExtract != nil {
		sb.WriteString(fmt.Sprintf("- Raw META-INF: `%s/META-INF/`\n", r.APKExtract.Output))
	}

	sb.WriteString("\n")

	sb.WriteString("### 7. Kotlin Metadata\n\n")

	// Same fix as native: dissect populates r.KotlinAnalysis (kotlin.ScanDEX),
	// not APKInfo.HasKotlin, so consult both.
	if (r.APKInfo != nil && r.APKInfo.HasKotlin) ||
		(r.KotlinAnalysis != nil && r.KotlinAnalysis.HasKotlin) {
		sb.WriteString("- This app uses Kotlin. Check `kotlin/` directory for:\n")
		sb.WriteString("  - kotlin-stdlib version markers.\n")
		sb.WriteString("  - Kotlin module metadata (.kotlin_module) — reveals real module names\n")
		sb.WriteString("    even when code is obfuscated.\n")
		sb.WriteString("  - Kotlin builtins.\n")
	} else {
		sb.WriteString("- No Kotlin metadata detected. The app may be pure Java or the metadata\n")
		sb.WriteString("  was stripped. Check for Kotlin-specific patterns in decompiled code.\n")
	}

	sb.WriteString("\n")

	sb.WriteString("### 8. Embedded Databases & Storage\n\n")
	sb.WriteString("- Search extracted files for:\n")
	sb.WriteString("  - SQLite databases (`.db`, `.sqlite`, `.sqlite3`) — dump all tables and data.\n")
	sb.WriteString("  - Realm databases (`.realm`) — use realm-browser or parse header.\n")
	sb.WriteString("  - SharedPreferences XML files — extract key-value pairs.\n")
	sb.WriteString("  - Protocol Buffer files (`.pb`, `.proto`) — decode with protoc.\n")
	sb.WriteString("  - Serialized Java objects — check for insecure deserialization.\n")
	sb.WriteString("\n")

	sb.WriteString("### 9. Hardcoded Secrets & Sensitive Data\n\n")
	sb.WriteString("- Scan ALL extracted text content (source code, XML, JSON, strings) for:\n")
	sb.WriteString("  - API keys (Google Maps, Firebase, AWS, Azure, Stripe, etc.)\n")
	sb.WriteString("  - OAuth client IDs and secrets\n")
	sb.WriteString("  - Private keys, certificates, JKS/BKS keystores\n")
	sb.WriteString("  - Hardcoded passwords, tokens, session identifiers\n")
	sb.WriteString("  - Internal server URLs, staging/debug endpoints\n")
	sb.WriteString("  - Database connection strings\n")
	sb.WriteString("  - Encryption keys or IVs\n")
	sb.WriteString("- Use regex patterns: `(?i)(api[_-]?key|secret|token|password|auth)\\s*[:=]`\n")
	sb.WriteString("- Check `BuildConfig.java` for build-time constants.\n")
	sb.WriteString("- Check `res/values/strings.xml` for keys disguised as string resources.\n")
	sb.WriteString("\n")

	sb.WriteString("### 10. Network & API Surface\n\n")
	sb.WriteString("- Collect every URL, domain, and IP address from all sources.\n")
	sb.WriteString("- Map the full API surface: base URLs, endpoint paths, HTTP methods.\n")
	sb.WriteString("- Check network_security_config.xml for cleartext and pinning.\n")
	sb.WriteString("- Identify certificate pinning implementations in code.\n")
	sb.WriteString("- Look for WebSocket, MQTT, gRPC, or custom protocol usage.\n")
	sb.WriteString("- Check for proxy detection or SSL pinning bypass countermeasures.\n")
	sb.WriteString("\n")

	sb.WriteString("### 11. Obfuscation & Protection Analysis\n\n")
	sb.WriteString("- Identify the obfuscation tool used:\n")
	sb.WriteString("  - ProGuard/R8: mapping.txt presence, short class names (a.b.c).\n")
	sb.WriteString("  - DexGuard: encrypted strings, class encryption, asset encryption.\n")
	sb.WriteString("  - Allatori, Zelix, iXGuard: tool-specific markers.\n")
	sb.WriteString("- Check for string encryption (runtime decryption methods).\n")
	sb.WriteString("- Check for control flow obfuscation (switch-based state machines in smali).\n")
	sb.WriteString("- Check for packer/loader (classes.dex loads another DEX dynamically).\n")
	sb.WriteString("- Check for integrity verification (APK hash checks, signature checks at runtime).\n")
	sb.WriteString("\n")

	// --- Bundle-specific ---
	if r.APKInfo != nil && len(r.APKInfo.SplitAPKs) > 0 {
		sb.WriteString("### 12. Split APK / Bundle Analysis\n\n")
		sb.WriteString("- This is a multi-APK bundle. You MUST extract and analyze each split:\n")

		for _, split := range r.APKInfo.SplitAPKs {
			sb.WriteString(fmt.Sprintf("  - `%s`\n", split))
		}

		sb.WriteString("- Each split may contain additional DEX files, native libs, resources,\n")
		sb.WriteString("  or locale-specific content not in base.apk.\n")
		sb.WriteString("- Treat every split as a separate mini-APK and repeat steps 1-11 on it.\n")
		sb.WriteString("\n")
	}

	// --- Output format ---
	sb.WriteString("## Output Requirements\n\n")
	sb.WriteString("For every artifact you extract, provide:\n\n")
	sb.WriteString("1. **What it is** — file type, purpose, which component uses it.\n")
	sb.WriteString("2. **Key content** — the actual data: strings, URLs, keys, code logic.\n")
	sb.WriteString("3. **Security relevance** — any risk, vulnerability, or sensitive data exposed.\n")
	sb.WriteString("4. **Cross-references** — which other components reference this artifact.\n\n")
	sb.WriteString("Do not summarize away details. If a file contains 50 strings, list all 50.\n")
	sb.WriteString("If a class has 20 methods, describe every one. Completeness is more important\n")
	sb.WriteString("than brevity. The user wants *everything* — extract until the last piece.\n\n")

	// --- File paths reference ---
	if r.APKExtract != nil || r.Decompile != nil {
		sb.WriteString("## Quick Path Reference\n\n")
		sb.WriteString("```\n")

		if r.APKExtract != nil {
			base := r.APKExtract.Output
			sb.WriteString(fmt.Sprintf("%-50s  # Raw extracted APK contents\n", base+"/"))
			sb.WriteString(fmt.Sprintf("%-50s  # Binary manifest\n", filepath.Join(base, "AndroidManifest.xml")))
			sb.WriteString(fmt.Sprintf("%-50s  # DEX bytecode\n", filepath.Join(base, "classes*.dex")))
			sb.WriteString(fmt.Sprintf("%-50s  # Native .so libraries\n", filepath.Join(base, "lib/")))
			sb.WriteString(fmt.Sprintf("%-50s  # Compiled resources\n", filepath.Join(base, "res/")))
			sb.WriteString(fmt.Sprintf("%-50s  # Uncompiled assets\n", filepath.Join(base, "assets/")))
			sb.WriteString(fmt.Sprintf("%-50s  # Signing metadata\n", filepath.Join(base, "META-INF/")))
		}

		if r.Decompile != nil {
			base := r.Decompile.OutputDir
			sb.WriteString(fmt.Sprintf("%-50s  # Decoded resources + smali\n", filepath.Join(base, "apktool/")))
			sb.WriteString(fmt.Sprintf("%-50s  # Decompiled Java source\n", filepath.Join(base, "jadx/")))
			sb.WriteString(fmt.Sprintf("%-50s  # Decompiled native code\n", filepath.Join(base, "native/")))
		}

		sb.WriteString("```\n\n")
	}

	sb.WriteString("---\n")
	sb.WriteString("*Generated by unravel dissect. Feed this prompt to an AI assistant alongside\n")
	sb.WriteString("the extracted files to perform a complete, no-stone-unturned analysis.*\n")

	return sb.String()
}
