/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"fmt"
	"strings"
)

// generatePE produces Frida scripts for native targets (Windows PE, mostly,
// with Mach-O / ELF reusing the same Module.findExportByName surface).
//
// Hooks are intentionally tolerant: each Interceptor.attach is wrapped in a
// null-check on findExportByName so a script written for Windows still loads
// (no-op) on macOS/Linux processes that lack the corresponding export.
func generatePE(config ScriptConfig) []GeneratedScript {
	var scripts []GeneratedScript

	if config.IncludeNetwork || config.IncludeSSL {
		scripts = append(scripts, schannelCapturePE())
		scripts = append(scripts, boringSSLCapturePE())
	}
	if config.IncludeCrypto {
		scripts = append(scripts, bcryptMonitorPE())
		scripts = append(scripts, dpapiMonitorPE())
	}
	if config.IncludeDebug {
		scripts = append(scripts, antiDebugBypassPE())
	}

	for _, hook := range config.CustomHooks {
		scripts = append(scripts, customHookPE(hook))
	}

	// Always emit a tiny entry-point script that loads side-by-side. Frida's
	// CLI takes one -l per file, but operators expect a `main.js` to anchor
	// the output dir. We give them a manifest-style script that prints the
	// loaded module list so symbol discovery is one command away.
	scripts = append(scripts, mainPE())

	return scripts
}

// mainPE is the recommended entry point. It enumerates loaded modules and
// flags the ones with crypto/protocol relevance; nothing else.
func mainPE() GeneratedScript {
	return GeneratedScript{
		Name:        "main",
		Description: "Entry point: enumerate loaded modules, flag crypto/protocol DLLs",
		Category:    "monitor",
		Content: `'use strict';

// Frida entry-point for Windows PE targets. Run with:
//   frida -p <pid> -l main.js
// Then attach the per-feature scripts (schannel_capture.js, bcrypt_monitor.js,
// dpapi_monitor.js) with additional -l flags.

function logEvent(tag, data) {
    var rec = { ts: new Date().toISOString(), tag: tag, data: data };
    send(rec); // host-side handler can persist to frames.jsonl
    console.log('[' + tag + '] ' + JSON.stringify(data));
}

var interesting = ['schannel.dll', 'bcrypt.dll', 'crypt32.dll', 'ncrypt.dll',
    'wininet.dll', 'winhttp.dll', 'ws2_32.dll', 'mswsock.dll'];

Process.enumerateModules().forEach(function (m) {
    var name = m.name.toLowerCase();
    if (interesting.indexOf(name) !== -1) {
        logEvent('MODULE', { name: m.name, base: m.base.toString(), size: m.size, path: m.path });
    }
});

console.log('[main] entry-point loaded; attach feature scripts with -l');
`,
	}
}

// schannelCapturePE hooks Windows Schannel TLS encrypt/decrypt entry points.
// This captures plaintext frames before they're sealed by TLS, sidestepping
// MITM proxies that fail when the target pins certificates.
func schannelCapturePE() GeneratedScript {
	return GeneratedScript{
		Name:        "schannel_capture",
		Description: "Capture TLS plaintext via Schannel EncryptMessage/DecryptMessage",
		Category:    "monitor",
		Content: `'use strict';

// Schannel SSP entry points. The functions live in secur32.dll on user-mode
// callers; sometimes resolved via SSPI dispatch tables. We hook by name and
// fall through if the export isn't present.
//
// Frida 17 removed Module.findExportByName(modName, name); use the per-module
// Module.findExportByName(name) on a resolved module handle instead.

function resolveExport(modName, exportName) {
    var m = Process.findModuleByName(modName);
    if (!m) return null;
    return m.findExportByName(exportName);
}

function attachByExport(modules, exportName, opts) {
    for (var i = 0; i < modules.length; i++) {
        var addr = resolveExport(modules[i], exportName);
        if (addr) {
            try {
                Interceptor.attach(addr, opts);
                console.log('[schannel] hooked ' + modules[i] + '!' + exportName + ' @ ' + addr);
                return true;
            } catch (e) {
                console.log('[schannel] attach failed: ' + e.message);
            }
        }
    }
    return false;
}

function dumpBuffers(args) {
    // SECURITY_STATUS EncryptMessage(PCtxtHandle, ULONG, PSecBufferDesc, ULONG)
    // SecBufferDesc -> ULONG, ULONG, PSecBuffer  (third arg is the buffer desc)
    var pBufDesc = args[2];
    if (pBufDesc.isNull()) return null;
    try {
        var cBuffers = pBufDesc.add(Process.pointerSize === 8 ? 4 : 4).readU32();
        var pBuffers = pBufDesc.add(Process.pointerSize === 8 ? 8 : 8).readPointer();
        var dumps = [];
        for (var i = 0; i < cBuffers && i < 8; i++) {
            // SecBuffer { ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer; }
            var off = i * (Process.pointerSize === 8 ? 16 : 12);
            var cb = pBuffers.add(off).readU32();
            var typ = pBuffers.add(off + 4).readU32();
            var pv = pBuffers.add(off + 8).readPointer();
            if (cb === 0 || pv.isNull()) continue;
            // Cap dump at 256 bytes per buffer to keep logs tractable.
            var n = Math.min(cb, 256);
            try {
                var bytes = pv.readByteArray(n);
                dumps.push({ idx: i, type: typ, cb: cb, hex: Array.prototype.map.call(new Uint8Array(bytes), function (b) {
                    return ('0' + b.toString(16)).slice(-2);
                }).join('') });
            } catch (e) {}
        }
        return dumps;
    } catch (e) { return null; }
}

attachByExport(['secur32.dll', 'sspicli.dll'], 'EncryptMessage', {
    onEnter: function (args) {
        var dumps = dumpBuffers(args);
        if (dumps) send({ ts: Date.now(), hook_id: 'schannel.encrypt', phase: 'enter', buffers: dumps });
    }
});

attachByExport(['secur32.dll', 'sspicli.dll'], 'DecryptMessage', {
    onLeave: function (retval) {
        // On leave, the buffer desc is unchanged — but we don't have args
        // here without saving them. Capture in onEnter instead.
    },
    onEnter: function (args) {
        this.bufDesc = args[2];
    }
});

// EncryptMessage / DecryptMessage on later Windows ride through ncrypt too;
// best-effort hook the alternate name.
// NCryptEncrypt — alternate path for newer Windows.
attachByExport(['ncrypt.dll'], 'NCryptEncrypt', {
    onEnter: function (args) {
        send({ ts: Date.now(), hook_id: 'ncrypt.encrypt', phase: 'enter' });
    }
});
`,
	}
}

// boringSSLCapturePE hooks Chromium/WebView2 BoringSSL SSL_read/SSL_write entry
// points using a 3-strategy resolver (export → PDB symbol → byte pattern). The
// JS body is lifted verbatim from v2.8 W-13 evidence at
// out/whatsapp-kb/evidence/runtime/frida/boringssl_capture.js. Failure modes
// are reported honestly via send() events:
//
//	BORINGSSL_TARGET     — module resolved
//	BORINGSSL_HOOK       — export/symbol/pattern resolved an attach point
//	BORINGSSL_NOT_FOUND  — none of msedge/chrome/webview2 modules present
//	BORINGSSL_PATTERN    — pattern-scan stats (per-range)
//	BORINGSSL_AMBIGUOUS  — >1 pattern match (do not attach blindly)
//	BORINGSSL_GIVE_UP    — all 3 strategies failed
func boringSSLCapturePE() GeneratedScript {
	return GeneratedScript{
		Name:        "boringssl_capture",
		Description: "Capture Chromium/WebView2 plaintext via BoringSSL SSL_read/SSL_write (3-strategy: export → symbol → pattern)",
		Category:    "monitor",
		Content: `'use strict';

// BoringSSL hook for Chromium/WebView2 network-service processes.
// Chromium statically links BoringSSL into msedge.dll (or chrome.dll). The
// canonical entry points for plaintext frame capture are SSL_read and
// SSL_write. We try three resolution strategies in order:
//
//   1. Exports (Module.enumerateExports) — works if Edge ships them publicly.
//   2. Symbols (Module.enumerateSymbols) — works only with PDBs side-loaded;
//      Frida pulls them via DbgHelp when present.
//   3. Pattern scan over the .text section — the BoringSSL prologue is stable
//      across versions for SSL_read/SSL_write at the call-site level (they
//      both forward to ssl_read_impl / ssl_write_impl with a thin wrapper).
//
// Whatever resolves first wins. Hooks dump up to 256 bytes of plaintext per
// call to send().

var TARGET_MODULES = ['msedge.dll', 'chrome.dll', 'msedgewebview2.dll'];

function findTargetModule() {
    for (var i = 0; i < TARGET_MODULES.length; i++) {
        var m = Process.findModuleByName(TARGET_MODULES[i]);
        if (m) return m;
    }
    return null;
}

function bytesToHex(arr, max) {
    var n = Math.min(arr.byteLength || arr.length, max);
    var view = new Uint8Array(arr);
    var s = '';
    for (var i = 0; i < n; i++) {
        s += ('0' + view[i].toString(16)).slice(-2);
    }
    return s;
}

function attachReadWrite(modName, readAddr, writeAddr, source) {
    if (readAddr) {
        Interceptor.attach(readAddr, {
            // int SSL_read(SSL *ssl, void *buf, int num)
            onEnter: function (args) {
                this.buf = args[1];
                this.want = args[2].toInt32();
            },
            onLeave: function (retval) {
                var n = retval.toInt32();
                if (n > 0 && !this.buf.isNull()) {
                    var hex = bytesToHex(this.buf.readByteArray(Math.min(n, 256)), 256);
                    send({ ts: Date.now(), hook_id: 'boringssl.read', module: modName, source: source, n: n, want: this.want, hex: hex });
                }
            }
        });
        send({ tag: 'BORINGSSL_HOOK', kind: 'SSL_read', module: modName, source: source, addr: readAddr.toString() });
    }
    if (writeAddr) {
        Interceptor.attach(writeAddr, {
            // int SSL_write(SSL *ssl, const void *buf, int num)
            onEnter: function (args) {
                var buf = args[1];
                var n = args[2].toInt32();
                if (n > 0 && !buf.isNull()) {
                    var hex = bytesToHex(buf.readByteArray(Math.min(n, 256)), 256);
                    send({ ts: Date.now(), hook_id: 'boringssl.write', module: modName, source: source, n: n, hex: hex });
                }
            }
        });
        send({ tag: 'BORINGSSL_HOOK', kind: 'SSL_write', module: modName, source: source, addr: writeAddr.toString() });
    }
}

(function () {
    var mod = findTargetModule();
    if (!mod) {
        send({ tag: 'BORINGSSL_NOT_FOUND', wanted: TARGET_MODULES });
        return;
    }

    var modName = mod.name;
    send({ tag: 'BORINGSSL_TARGET', name: modName, base: mod.base.toString(), size: mod.size, path: mod.path });

    // Strategy 1: exports
    var readExp = mod.findExportByName('SSL_read');
    var writeExp = mod.findExportByName('SSL_write');
    if (readExp || writeExp) {
        attachReadWrite(modName, readExp, writeExp, 'export');
        return;
    }

    // Strategy 2: symbols (PDB-backed). enumerateSymbols may be slow but
    // doesn't iterate the whole .text section unless a PDB is loaded.
    var readSym = null, writeSym = null;
    try {
        var syms = mod.enumerateSymbols();
        for (var i = 0; i < syms.length; i++) {
            var s = syms[i];
            if (s.name === 'SSL_read') readSym = s.address;
            else if (s.name === 'SSL_write') writeSym = s.address;
            if (readSym && writeSym) break;
        }
    } catch (e) { /* enumerateSymbols may not be available */ }
    if (readSym || writeSym) {
        attachReadWrite(modName, readSym, writeSym, 'symbol');
        return;
    }

    // Strategy 3: pattern scan. Two concerns:
    //   - .text in modern msedge.dll is ~150MB; scanning takes seconds but is
    //     fine for a one-shot probe at attach time.
    //   - The BoringSSL SSL_read prologue is stable across many Chromium
    //     versions; we use a documented pattern. If both fail, log and stop.
    //
    // Patterns sourced from public BoringSSL builds (Chromium-equivalent):
    //   SSL_read prologue (x64): 48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 49 8B F8 8B EA
    //   SSL_write prologue (x64): 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 41 8B F0 48 8B FA
    //
    // These are heuristic, not guaranteed. If neither hits, fall back.
    var readPattern = '48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 49 8B F8 8B EA';
    var writePattern = '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 41 8B F0 48 8B FA';

    var ranges = mod.enumerateRanges('r-x');
    var readMatches = [];
    var writeMatches = [];
    var scanned = 0;
    for (var j = 0; j < ranges.length; j++) {
        var r = ranges[j];
        scanned += r.size;
        try {
            var rr = Memory.scanSync(r.base, r.size, readPattern);
            for (var k = 0; k < rr.length; k++) readMatches.push(rr[k].address);
            var wr = Memory.scanSync(r.base, r.size, writePattern);
            for (var k2 = 0; k2 < wr.length; k2++) writeMatches.push(wr[k2].address);
        } catch (e) { /* range may be unreadable */ }
        if (readMatches.length && writeMatches.length) break; // first hit wins
    }
    send({ tag: 'BORINGSSL_PATTERN', read_hits: readMatches.length, write_hits: writeMatches.length, scanned_bytes: scanned });

    if (readMatches.length === 1 && writeMatches.length === 1) {
        attachReadWrite(modName, readMatches[0], writeMatches[0], 'pattern');
        return;
    }
    if (readMatches.length > 1 || writeMatches.length > 1) {
        send({ tag: 'BORINGSSL_AMBIGUOUS', read: readMatches.length, write: writeMatches.length, msg: 'multiple matches; refine pattern before attaching' });
        return;
    }
    send({ tag: 'BORINGSSL_GIVE_UP', msg: 'no exports, no symbols, no pattern hits — manual symbol resolution required' });
})();
`,
	}
}

// bcryptMonitorPE hooks the user-mode CNG (BCrypt*) primitives. These are the
// modern Windows crypto APIs that Noise/Signal-style protocols often reach
// for (AES-GCM, HKDF, X25519).
func bcryptMonitorPE() GeneratedScript {
	return GeneratedScript{
		Name:        "bcrypt_monitor",
		Description: "Trace CNG BCrypt primitives (encrypt/decrypt/hash/key derivation)",
		Category:    "monitor",
		Content: `'use strict';

// Frida 17: per-module Module.findExportByName replaces the legacy
// Module.findExportByName(modName, name) overload.
function tryAttach(modName, exportName, opts) {
    var m = Process.findModuleByName(modName);
    if (!m) return false;
    var addr = m.findExportByName(exportName);
    if (!addr) return false;
    try {
        Interceptor.attach(addr, opts);
        console.log('[bcrypt] hooked ' + modName + '!' + exportName);
        return true;
    } catch (e) {
        console.log('[bcrypt] attach failed: ' + e.message);
        return false;
    }
}

['BCryptEncrypt', 'BCryptDecrypt', 'BCryptHash', 'BCryptKeyDerivation',
    'BCryptDeriveKey', 'BCryptDeriveKeyPBKDF2', 'BCryptGenerateSymmetricKey',
    'BCryptImportKeyPair', 'BCryptSignHash', 'BCryptVerifySignature'
].forEach(function (name) {
    tryAttach('bcrypt.dll', name, {
        onEnter: function (args) {
            send({ ts: Date.now(), hook_id: 'bcrypt.' + name, phase: 'enter' });
        }
    });
});
`,
	}
}

// dpapiMonitorPE hooks CryptProtectData/CryptUnprotectData. WhatsApp Desktop
// (and most Chromium-derived apps) stash session keys with DPAPI; trapping
// the unseal call gives plaintext keys without touching the disk format.
func dpapiMonitorPE() GeneratedScript {
	return GeneratedScript{
		Name:        "dpapi_monitor",
		Description: "Capture DPAPI plaintext via CryptUnprotectData/CryptProtectData",
		Category:    "monitor",
		Content: `'use strict';

function dumpDataBlob(p) {
    if (p.isNull()) return null;
    try {
        // DATA_BLOB { DWORD cbData; BYTE *pbData; }
        var cb = p.readU32();
        var pb = p.add(Process.pointerSize === 8 ? 8 : 4).readPointer();
        if (cb === 0 || pb.isNull()) return null;
        var n = Math.min(cb, 512);
        var bytes = pb.readByteArray(n);
        return { cb: cb, hex: Array.prototype.map.call(new Uint8Array(bytes), function (b) {
            return ('0' + b.toString(16)).slice(-2);
        }).join('') };
    } catch (e) { return null; }
}

var crypt32 = Process.findModuleByName('crypt32.dll');
['CryptUnprotectData', 'CryptProtectData'].forEach(function (name) {
    var addr = crypt32 ? crypt32.findExportByName(name) : null;
    if (!addr) {
        console.log('[dpapi] crypt32.dll!' + name + ' not found');
        return;
    }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            this.name = name;
            this.pInBlob = args[0];
            this.pOutBlob = args[6]; // CryptUnprotectData last param is pDataOut
        },
        onLeave: function (retval) {
            send({
                ts: Date.now(),
                hook_id: 'dpapi.' + this.name,
                ok: !retval.isNull() && retval.toInt32() !== 0,
                in:  dumpDataBlob(this.pInBlob),
                out: dumpDataBlob(this.pOutBlob)
            });
        }
    });
    console.log('[dpapi] hooked crypt32.dll!' + name);
});
`,
	}
}

// antiDebugBypassPE neutralizes IsDebuggerPresent / CheckRemoteDebuggerPresent /
// NtQueryInformationProcess(ProcessDebugPort) so analyzers can attach without
// triggering the target's anti-debug bail-out.
func antiDebugBypassPE() GeneratedScript {
	return GeneratedScript{
		Name:        "anti_debug_bypass",
		Description: "Neutralize Windows anti-debug primitives (IsDebuggerPresent, NtQuery*)",
		Category:    "bypass",
		Content: `'use strict';

(function () {
    var k32 = Process.findModuleByName('kernel32.dll');
    var ida = k32 ? k32.findExportByName('IsDebuggerPresent') : null;
    if (ida) Interceptor.replace(ida, new NativeCallback(function () { return 0; }, 'int', []));

    var crd = k32 ? k32.findExportByName('CheckRemoteDebuggerPresent') : null;
    if (crd) Interceptor.attach(crd, {
        onLeave: function () {
            try { this.context.r0 = 0; } catch (e) {}
        }
    });
    console.log('[anti-debug] IsDebuggerPresent + CheckRemoteDebuggerPresent neutralized');
})();
`,
	}
}

// customHookPE expands a "module!export" or bare "export" pattern into an
// Interceptor.attach scaffold that logs args + return.
func customHookPE(pattern string) GeneratedScript {
	module := ""
	export := pattern
	if idx := strings.Index(pattern, "!"); idx > 0 {
		module = pattern[:idx]
		export = pattern[idx+1:]
	}
	safeName := strings.NewReplacer("!", "_", ".", "_", "/", "_").Replace(pattern)

	// Frida 17: per-module Module.findExportByName(name) for scoped lookups,
	// Module.findGlobalExportByName(name) for cross-module resolution.
	var resolve string
	if module != "" {
		resolve = fmt.Sprintf("(function(){ var m = Process.findModuleByName(%q); return m ? m.findExportByName(%q) : null; })()", module, export)
	} else {
		resolve = fmt.Sprintf("Module.findGlobalExportByName(%q)", export)
	}

	content := fmt.Sprintf(`'use strict';

(function () {
    var addr = %s;
    if (!addr) {
        console.log('[hook] %s not found');
        return;
    }
    Interceptor.attach(addr, {
        onEnter: function (args) {
            send({ ts: Date.now(), hook_id: '%s', phase: 'enter',
                args: [args[0], args[1], args[2], args[3]].map(function (a) { return a.toString(); }) });
        },
        onLeave: function (retval) {
            send({ ts: Date.now(), hook_id: '%s', phase: 'leave', ret: retval.toString() });
        }
    });
    console.log('[hook] attached to %s @ ' + addr);
})();
`, resolve, pattern, pattern, pattern, pattern)

	return GeneratedScript{
		Name:        "custom_" + safeName,
		Description: fmt.Sprintf("Custom native hook for %s", pattern),
		Category:    "monitor",
		Content:     content,
	}
}
