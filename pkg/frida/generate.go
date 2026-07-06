/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"fmt"
	"strings"
)

// Generate creates Frida scripts based on the provided configuration. The
// Target field selects between the JVM-flavored generator (Android, default)
// and the native-export generator (Windows PE, with Mach-O / ELF reusing the
// same surface).
func Generate(config ScriptConfig) *GenerateResult {
	result := &GenerateResult{
		PackageName: config.PackageName,
		Scripts:     []GeneratedScript{},
	}

	switch config.Target {
	case TargetWindowsPE, TargetMachO, TargetELF:
		result.Scripts = generatePE(config)
		return result
	}

	if config.IncludeSSL {
		result.Scripts = append(result.Scripts, sslPinningBypass())
	}

	if config.IncludeRoot {
		result.Scripts = append(result.Scripts, rootDetectionBypass())
	}

	if config.IncludeDebug {
		result.Scripts = append(result.Scripts, antiDebugBypass())
	}

	if config.IncludeNetwork {
		result.Scripts = append(result.Scripts, networkCapture())
	}

	if config.IncludeStorage {
		result.Scripts = append(result.Scripts, storageMonitor())
	}

	if config.IncludeCrypto {
		result.Scripts = append(result.Scripts, cryptoMonitor())
	}

	if config.IncludeIPC {
		result.Scripts = append(result.Scripts, ipcMonitor())
	}

	for _, hook := range config.CustomHooks {
		result.Scripts = append(result.Scripts, customHook(hook))
	}

	return result
}

// GenerateFromAnalysis auto-detects what to hook based on analysis results.
func GenerateFromAnalysis(input AnalysisInput) *GenerateResult {
	config := ScriptConfig{
		IncludeNetwork: true, // always include network monitoring
	}

	var autoDetected []string

	// Extract package name
	if input.PackageName != "" {
		config.PackageName = input.PackageName
		autoDetected = append(autoDetected, "package: "+input.PackageName)
	}

	// Cert pinning detected -> enable SSL bypass
	if input.HasCertPinning {
		config.IncludeSSL = true
		autoDetected = append(autoDetected, "cert pinning detected")
	}

	// Root/anti-debug detection from native analysis
	for _, f := range input.NativeFindings {
		switch f.Category {
		case "root-detection":
			if !config.IncludeRoot {
				config.IncludeRoot = true
				autoDetected = append(autoDetected, "root detection in native libs")
			}
		case "anti-debug":
			if !config.IncludeDebug {
				config.IncludeDebug = true
				autoDetected = append(autoDetected, "anti-debug in native libs")
			}
		}
	}

	// Crypto APIs found in DEX analysis
	for _, api := range input.DEXRiskAPIs {
		if strings.Contains(api, "Cipher") ||
			strings.Contains(api, "MessageDigest") ||
			strings.Contains(api, "SecretKey") {
			config.IncludeCrypto = true
			autoDetected = append(autoDetected, "crypto APIs in DEX")

			break
		}
	}

	// Exported components -> enable IPC monitoring
	if input.HasExportedComp {
		config.IncludeIPC = true
		autoDetected = append(autoDetected, "exported components in manifest")
	}

	result := Generate(config)
	result.AutoDetected = autoDetected
	result.CaptureTemplates = GenerateCaptureFromAnalysis(input)

	return result
}

func sslPinningBypass() GeneratedScript {
	return GeneratedScript{
		Name:        "ssl_pinning_bypass",
		Description: "Bypass SSL certificate pinning (OkHttp, TrustManager, WebView)",
		Category:    "bypass",
		Content: `'use strict';

Java.perform(function () {
    // --- OkHttp CertificatePinner bypass ---
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log('[SSL] OkHttp pinning bypass for: ' + hostname);
        };
        console.log('[SSL] OkHttp CertificatePinner hooked');
    } catch (e) {
        console.log('[SSL] OkHttp not found: ' + e.message);
    }

    // --- TrustManager bypass ---
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[SSL] TrustManager bypass for: ' + host);
            return untrustedChain;
        };
        console.log('[SSL] TrustManagerImpl hooked');
    } catch (e) {
        console.log('[SSL] TrustManagerImpl not found: ' + e.message);
    }

    // --- WebView SSL error bypass ---
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[SSL] WebView SSL error bypassed');
            handler.proceed();
        };
        console.log('[SSL] WebViewClient.onReceivedSslError hooked');
    } catch (e) {
        console.log('[SSL] WebViewClient not found: ' + e.message);
    }
});
`,
	}
}

func rootDetectionBypass() GeneratedScript {
	return GeneratedScript{
		Name:        "root_detection_bypass",
		Description: "Bypass common root detection checks (su, Magisk, build tags)",
		Category:    "bypass",
		Content: `'use strict';

Java.perform(function () {
    // --- File.exists() bypass for root binaries ---
    try {
        var File = Java.use('java.io.File');
        var rootPaths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
            '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
            '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
            '/su/bin/su', '/system/xbin/busybox', '/sbin/magisk', '/system/bin/magisk'];

        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) {
                    console.log('[ROOT] Hiding root path: ' + path);
                    return false;
                }
            }
            return this.exists.call(this);
        };
        console.log('[ROOT] File.exists hooked for root paths');
    } catch (e) {
        console.log('[ROOT] File.exists hook failed: ' + e.message);
    }

    // --- Runtime.exec bypass for su/which ---
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdArray) {
            var cmd = cmdArray.join(' ');
            if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 || cmd.indexOf('magisk') !== -1) {
                console.log('[ROOT] Blocked exec: ' + cmd);
                throw Java.use('java.io.IOException').$new('Permission denied');
            }
            return this.exec(cmdArray);
        };
        console.log('[ROOT] Runtime.exec hooked');
    } catch (e) {
        console.log('[ROOT] Runtime.exec hook failed: ' + e.message);
    }

    // --- Build.TAGS bypass ---
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        console.log('[ROOT] Build.TAGS set to release-keys');
    } catch (e) {
        console.log('[ROOT] Build.TAGS hook failed: ' + e.message);
    }

    // --- PackageManager bypass for root apps ---
    try {
        var PackageManager = Java.use('android.app.ApplicationPackageManager');
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (name, flags) {
            var rootPkgs = ['com.topjohnwu.magisk', 'eu.chainfire.supersu', 'com.koushikdutta.superuser',
                'com.noshufou.android.su', 'com.thirdparty.superuser'];
            for (var i = 0; i < rootPkgs.length; i++) {
                if (name === rootPkgs[i]) {
                    console.log('[ROOT] Hiding package: ' + name);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(name);
                }
            }
            return this.getPackageInfo(name, flags);
        };
        console.log('[ROOT] PackageManager.getPackageInfo hooked');
    } catch (e) {
        console.log('[ROOT] PackageManager hook failed: ' + e.message);
    }
});
`,
	}
}

func antiDebugBypass() GeneratedScript {
	return GeneratedScript{
		Name:        "anti_debug_bypass",
		Description: "Bypass anti-debugging checks (ptrace, TracerPid, isDebuggerConnected)",
		Category:    "bypass",
		Content: `'use strict';

Java.perform(function () {
    // --- Debug.isDebuggerConnected bypass ---
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            console.log('[DEBUG] isDebuggerConnected bypassed');
            return false;
        };
        console.log('[DEBUG] Debug.isDebuggerConnected hooked');
    } catch (e) {
        console.log('[DEBUG] Debug.isDebuggerConnected hook failed: ' + e.message);
    }

    // --- TracerPid check bypass via /proc/self/status ---
    try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.implementation = function () {
            var line = this.readLine.call(this);
            if (line !== null && line.indexOf('TracerPid') !== -1) {
                console.log('[DEBUG] TracerPid spoofed to 0');
                return 'TracerPid:\t0';
            }
            return line;
        };
        console.log('[DEBUG] BufferedReader.readLine hooked for TracerPid');
    } catch (e) {
        console.log('[DEBUG] BufferedReader hook failed: ' + e.message);
    }
});

// --- Native ptrace bypass ---
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
    onEnter: function (args) {
        this.request = args[0].toInt32();
        console.log('[DEBUG] ptrace called with request: ' + this.request);
    },
    onLeave: function (retval) {
        if (this.request === 0) { // PTRACE_TRACEME
            console.log('[DEBUG] ptrace TRACEME bypassed');
            retval.replace(0);
        }
    }
});
`,
	}
}

func networkCapture() GeneratedScript {
	return GeneratedScript{
		Name:        "network_capture",
		Description: "Log HTTP request/response traffic (OkHttp, HttpURLConnection)",
		Category:    "monitor",
		Content: `'use strict';

Java.perform(function () {
    // --- OkHttp request logging ---
    try {
        var Request = Java.use('okhttp3.Request');
        Request.url.implementation = function () {
            var url = this.url.call(this);
            console.log('[NET] OkHttp request URL: ' + url.toString());
            return url;
        };
        console.log('[NET] OkHttp Request.url hooked');
    } catch (e) {
        console.log('[NET] OkHttp hooking failed: ' + e.message);
    }

    // --- HttpURLConnection ---
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getInputStream.implementation = function () {
            console.log('[NET] HttpURLConnection -> ' + this.getURL().toString());
            return this.getInputStream.call(this);
        };
        console.log('[NET] HttpURLConnection.getInputStream hooked');
    } catch (e) {
        console.log('[NET] HttpURLConnection hook failed: ' + e.message);
    }

    // --- URL.openConnection ---
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            console.log('[NET] URL.openConnection: ' + this.toString());
            return this.openConnection();
        };
        console.log('[NET] URL.openConnection hooked');
    } catch (e) {
        console.log('[NET] URL.openConnection hook failed: ' + e.message);
    }
});
`,
	}
}

func storageMonitor() GeneratedScript {
	return GeneratedScript{
		Name:        "storage_monitor",
		Description: "Monitor SharedPreferences writes and SQLite database operations",
		Category:    "monitor",
		Content: `'use strict';

Java.perform(function () {
    // --- SharedPreferences.Editor ---
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Editor.putString.implementation = function (key, value) {
            console.log('[STORAGE] SharedPrefs.putString("' + key + '", "' + value + '")');
            return this.putString(key, value);
        };
        Editor.putInt.implementation = function (key, value) {
            console.log('[STORAGE] SharedPrefs.putInt("' + key + '", ' + value + ')');
            return this.putInt(key, value);
        };
        Editor.putBoolean.implementation = function (key, value) {
            console.log('[STORAGE] SharedPrefs.putBoolean("' + key + '", ' + value + ')');
            return this.putBoolean(key, value);
        };
        console.log('[STORAGE] SharedPreferences.Editor hooked');
    } catch (e) {
        console.log('[STORAGE] SharedPreferences hook failed: ' + e.message);
    }

    // --- SQLiteDatabase ---
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            console.log('[STORAGE] SQLite.execSQL: ' + sql);
            return this.execSQL(sql);
        };
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, args) {
            console.log('[STORAGE] SQLite.rawQuery: ' + sql);
            return this.rawQuery(sql, args);
        };
        console.log('[STORAGE] SQLiteDatabase hooked');
    } catch (e) {
        console.log('[STORAGE] SQLiteDatabase hook failed: ' + e.message);
    }
});
`,
	}
}

func cryptoMonitor() GeneratedScript {
	return GeneratedScript{
		Name:        "crypto_monitor",
		Description: "Hook Cipher, MessageDigest, and SecretKeySpec operations",
		Category:    "monitor",
		Content: `'use strict';

Java.perform(function () {
    // --- Cipher ---
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
            console.log('[CRYPTO] Cipher.getInstance: ' + transformation);
            return this.getInstance(transformation);
        };
        Cipher.doFinal.overload('[B').implementation = function (input) {
            console.log('[CRYPTO] Cipher.doFinal (input ' + input.length + ' bytes)');
            var result = this.doFinal(input);
            console.log('[CRYPTO] Cipher.doFinal (output ' + result.length + ' bytes)');
            return result;
        };
        console.log('[CRYPTO] Cipher hooked');
    } catch (e) {
        console.log('[CRYPTO] Cipher hook failed: ' + e.message);
    }

    // --- MessageDigest ---
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.getInstance.overload('java.lang.String').implementation = function (algorithm) {
            console.log('[CRYPTO] MessageDigest.getInstance: ' + algorithm);
            return this.getInstance(algorithm);
        };
        console.log('[CRYPTO] MessageDigest hooked');
    } catch (e) {
        console.log('[CRYPTO] MessageDigest hook failed: ' + e.message);
    }

    // --- SecretKeySpec ---
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algorithm) {
            console.log('[CRYPTO] SecretKeySpec(' + algorithm + ', key ' + keyBytes.length + ' bytes)');
            return this.$init(keyBytes, algorithm);
        };
        console.log('[CRYPTO] SecretKeySpec hooked');
    } catch (e) {
        console.log('[CRYPTO] SecretKeySpec hook failed: ' + e.message);
    }
});
`,
	}
}

func ipcMonitor() GeneratedScript {
	return GeneratedScript{
		Name:        "ipc_monitor",
		Description: "Monitor startActivity, sendBroadcast, and ContentResolver operations",
		Category:    "monitor",
		Content: `'use strict';

Java.perform(function () {
    // --- Activity.startActivity ---
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
            console.log('[IPC] startActivity: ' + intent.toString());
            var extras = intent.getExtras();
            if (extras !== null) {
                console.log('[IPC]   extras: ' + extras.toString());
            }
            return this.startActivity(intent);
        };
        console.log('[IPC] Activity.startActivity hooked');
    } catch (e) {
        console.log('[IPC] Activity.startActivity hook failed: ' + e.message);
    }

    // --- Context.sendBroadcast ---
    try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
            console.log('[IPC] sendBroadcast: ' + intent.toString());
            return this.sendBroadcast(intent);
        };
        console.log('[IPC] sendBroadcast hooked');
    } catch (e) {
        console.log('[IPC] sendBroadcast hook failed: ' + e.message);
    }

    // --- ContentResolver.query ---
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            console.log('[IPC] ContentResolver.query: ' + uri.toString());
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
        console.log('[IPC] ContentResolver.query hooked');
    } catch (e) {
        console.log('[IPC] ContentResolver.query hook failed: ' + e.message);
    }

    // --- Context.startService ---
    try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.startService.implementation = function (intent) {
            console.log('[IPC] startService: ' + intent.toString());
            return this.startService(intent);
        };
        console.log('[IPC] startService hooked');
    } catch (e) {
        console.log('[IPC] startService hook failed: ' + e.message);
    }
});
`,
	}
}

func customHook(pattern string) GeneratedScript {
	parts := strings.SplitN(pattern, ".", 2)
	className := pattern
	methodName := ""

	if len(parts) == 2 {
		className = parts[0]
		methodName = parts[1]
	}

	var content string
	if methodName != "" {
		content = fmt.Sprintf(`'use strict';

Java.perform(function () {
    try {
        var targetClass = Java.use('%s');
        targetClass.%s.implementation = function () {
            console.log('[HOOK] %s.%s called');
            console.log('[HOOK]   args: ' + JSON.stringify(arguments));
            var result = this.%s.apply(this, arguments);
            console.log('[HOOK]   return: ' + result);
            return result;
        };
        console.log('[HOOK] %s.%s hooked successfully');
    } catch (e) {
        console.log('[HOOK] Failed to hook %s.%s: ' + e.message);
    }
});
`, className, methodName, className, methodName, methodName, className, methodName, className, methodName)
	} else {
		content = fmt.Sprintf(`'use strict';

Java.perform(function () {
    try {
        var targetClass = Java.use('%s');
        console.log('[HOOK] Class %s loaded');
        console.log('[HOOK] Methods: ' + Object.getOwnPropertyNames(targetClass.__proto__).join(', '));
    } catch (e) {
        console.log('[HOOK] Failed to load %s: ' + e.message);
    }
});
`, className, className, className)
	}

	safeName := strings.ReplaceAll(pattern, ".", "_")

	return GeneratedScript{
		Name:        "custom_" + safeName,
		Description: fmt.Sprintf("Custom hook for %s", pattern),
		Category:    "monitor",
		Content:     content,
	}
}
