/*
Copyright (c) 2026 Security Research
*/
package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunResult holds the results of a sandboxed Node.js execution.
type RunResult struct {
	PackageDir   string        `json:"package_dir"`
	EntryPoint   string        `json:"entry_point"`
	ExitCode     int           `json:"exit_code"`
	Duration     time.Duration `json:"duration"`
	Stdout       string        `json:"stdout,omitempty"`
	Stderr       string        `json:"stderr,omitempty"`
	NetworkCalls []NetworkCall `json:"network_calls,omitempty"`
	FileAccess   []FileAccess  `json:"file_access,omitempty"`
	EnvAccess    []string      `json:"env_access,omitempty"`
	SpawnedProcs []string      `json:"spawned_procs,omitempty"`
	Error        string        `json:"error,omitempty"`
	TimedOut     bool          `json:"timed_out"`
}

// NetworkCall represents an intercepted HTTP/HTTPS/WebSocket request.
type NetworkCall struct {
	Method   string `json:"method"`
	URL      string `json:"url"`
	Status   int    `json:"status,omitempty"`
	Protocol string `json:"protocol"`
}

// FileAccess represents an intercepted filesystem operation.
type FileAccess struct {
	Op   string `json:"op"`
	Path string `json:"path"`
}

// Options configures the sandbox execution.
type Options struct {
	Timeout    time.Duration // max execution time (default 30s)
	EntryPoint string        // override entry point (default: from package.json "main")
	AllowNet   bool          // allow network access (default: false for sandbox)
	CaptureEnv bool          // capture process.env access
	NodePath   string        // path to node binary (auto-discovered)
}

// wrapperJS is the Node.js interceptor script injected via --require.
// It monkey-patches http, https, fs, child_process, and process.env to emit
// JSON lines on stderr for the Go side to parse.
const wrapperJS = `
'use strict';

const _origStderrWrite = process.stderr.write.bind(process.stderr);
function _sbLog(obj) {
  _origStderrWrite(JSON.stringify(obj) + '\n');
}

// --- Intercept http.request / http.get ---
try {
  const http = require('http');
  const _httpReq = http.request;
  const _httpGet = http.get;
  http.request = function(opts, cb) {
    const url = typeof opts === 'string' ? opts :
      (opts.protocol || 'http:') + '//' + (opts.hostname || opts.host || 'localhost') + (opts.path || '/');
    _sbLog({type:'net', method: (opts && opts.method) || 'GET', url: url, protocol: 'http'});
    return _httpReq.apply(this, arguments);
  };
  http.get = function(opts, cb) {
    const url = typeof opts === 'string' ? opts :
      (opts.protocol || 'http:') + '//' + (opts.hostname || opts.host || 'localhost') + (opts.path || '/');
    _sbLog({type:'net', method: 'GET', url: url, protocol: 'http'});
    return _httpGet.apply(this, arguments);
  };
} catch(e) {}

// --- Intercept https.request / https.get ---
try {
  const https = require('https');
  const _httpsReq = https.request;
  const _httpsGet = https.get;
  https.request = function(opts, cb) {
    const url = typeof opts === 'string' ? opts :
      'https://' + (opts.hostname || opts.host || 'localhost') + (opts.path || '/');
    _sbLog({type:'net', method: (opts && opts.method) || 'GET', url: url, protocol: 'https'});
    return _httpsReq.apply(this, arguments);
  };
  https.get = function(opts, cb) {
    const url = typeof opts === 'string' ? opts :
      'https://' + (opts.hostname || opts.host || 'localhost') + (opts.path || '/');
    _sbLog({type:'net', method: 'GET', url: url, protocol: 'https'});
    return _httpsGet.apply(this, arguments);
  };
} catch(e) {}

// --- Intercept global fetch ---
if (typeof globalThis.fetch === 'function') {
  const _origFetch = globalThis.fetch;
  globalThis.fetch = function(input, init) {
    const url = typeof input === 'string' ? input : (input && input.url ? input.url : String(input));
    const method = (init && init.method) || 'GET';
    const proto = url.startsWith('https') ? 'https' : 'http';
    _sbLog({type:'net', method: method, url: url, protocol: proto});
    return _origFetch.apply(this, arguments);
  };
}

// --- Intercept fs operations ---
try {
  const fs = require('fs');
  const _ops = {
    readFile: 'read', readFileSync: 'read',
    writeFile: 'write', writeFileSync: 'write',
    appendFile: 'write', appendFileSync: 'write',
    unlink: 'delete', unlinkSync: 'delete',
    stat: 'stat', statSync: 'stat', lstat: 'stat', lstatSync: 'stat',
    mkdir: 'write', mkdirSync: 'write',
    rmdir: 'delete', rmdirSync: 'delete',
    rm: 'delete', rmSync: 'delete',
    rename: 'write', renameSync: 'write',
    copyFile: 'write', copyFileSync: 'write',
  };
  for (const [fn, op] of Object.entries(_ops)) {
    if (typeof fs[fn] === 'function') {
      const _orig = fs[fn];
      fs[fn] = function() {
        const p = arguments[0];
        if (typeof p === 'string' || (p && p.toString)) {
          _sbLog({type:'fs', op: op, path: String(p)});
        }
        return _orig.apply(this, arguments);
      };
    }
  }
} catch(e) {}

// --- Intercept child_process ---
try {
  const cp = require('child_process');
  const _fns = ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'];
  for (const fn of _fns) {
    if (typeof cp[fn] === 'function') {
      const _orig = cp[fn];
      cp[fn] = function() {
        const cmd = String(arguments[0]);
        _sbLog({type:'proc', command: cmd});
        return _orig.apply(this, arguments);
      };
    }
  }
} catch(e) {}

// --- Intercept process.env access ---
if (process.env.__SANDBOX_CAPTURE_ENV === '1') {
  const _envKeys = new Set();
  const _handler = {
    get: function(target, prop) {
      if (typeof prop === 'string' && prop !== 'toJSON' && prop !== '__SANDBOX_CAPTURE_ENV') {
        if (!_envKeys.has(prop)) {
          _envKeys.add(prop);
          _sbLog({type:'env', key: prop});
        }
      }
      return target[prop];
    }
  };
  process.env = new Proxy(process.env, _handler);
}
`

// packageJSON is a minimal struct for reading the main field.
type packageJSON struct {
	Main string `json:"main"`
}

// Run executes a Node.js package in a sandboxed environment.
// It writes a temporary wrapper script, runs node with --require to inject it,
// and parses the intercepted calls from stderr JSON lines.
func Run(ctx context.Context, packageDir string, opts Options) (*RunResult, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	nodePath := opts.NodePath
	if nodePath == "" {
		nodePath = FindNode()
	}

	if nodePath == "" {
		return nil, fmt.Errorf("node binary not found; install Node.js or set NodePath")
	}

	// Resolve entry point
	entryPoint := opts.EntryPoint
	if entryPoint == "" {
		entryPoint = resolveEntryPoint(packageDir)
	}

	entryAbs := entryPoint
	if !filepath.IsAbs(entryAbs) {
		entryAbs = filepath.Join(packageDir, entryAbs)
	}

	// Containment check: reject entry points that escape packageDir.
	// A weaponized package.json can set "main": "../../../usr/bin/node" to
	// execute an arbitrary file from the analyst's filesystem.
	cleanedEntry := filepath.Clean(entryAbs)
	cleanedPkg := filepath.Clean(packageDir) + string(os.PathSeparator)
	if !strings.HasPrefix(cleanedEntry+string(os.PathSeparator), cleanedPkg) {
		return nil, fmt.Errorf("entry point %q escapes package directory", entryAbs)
	}

	if _, err := os.Stat(entryAbs); err != nil {
		return nil, fmt.Errorf("entry point not found: %s", entryAbs)
	}

	// Write wrapper to temp file
	wrapperFile, err := os.CreateTemp("", "unravel-sandbox-*.js")
	if err != nil {
		return nil, fmt.Errorf("creating wrapper temp file: %w", err)
	}
	defer func() { _ = os.Remove(wrapperFile.Name()) }()

	if _, err := wrapperFile.WriteString(wrapperJS); err != nil {
		_ = wrapperFile.Close()
		return nil, fmt.Errorf("writing wrapper: %w", err)
	}

	if err := wrapperFile.Close(); err != nil {
		return nil, fmt.Errorf("closing wrapper: %w", err)
	}

	// Build command
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	args := []string{"--require", wrapperFile.Name(), entryAbs}
	cmd := exec.CommandContext(ctx, nodePath, args...)
	cmd.Dir = packageDir

	// Set environment
	cmd.Env = os.Environ()
	if opts.CaptureEnv {
		cmd.Env = append(cmd.Env, "__SANDBOX_CAPTURE_ENV=1")
	}

	// Capture output
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf

	// We need to capture stderr ourselves to parse JSON lines
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stderr pipe: %w", err)
	}

	start := time.Now()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting node: %w", err)
	}

	// Parse stderr JSON lines
	var (
		netCalls    []NetworkCall
		fileAccess  []FileAccess
		envAccess   []string
		spawnedProc []string
	)

	envSeen := make(map[string]bool)
	scanner := bufio.NewScanner(stderrPipe)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			// Not a JSON line from our wrapper; keep it as normal stderr
			stderrBuf.WriteString(line)
			stderrBuf.WriteByte('\n')
			continue
		}

		msgType, _ := msg["type"].(string)

		switch msgType {
		case "net":
			nc := NetworkCall{
				Method:   strVal(msg, "method"),
				URL:      strVal(msg, "url"),
				Protocol: strVal(msg, "protocol"),
			}
			netCalls = append(netCalls, nc)

		case "fs":
			fa := FileAccess{
				Op:   strVal(msg, "op"),
				Path: strVal(msg, "path"),
			}
			fileAccess = append(fileAccess, fa)

		case "proc":
			spawnedProc = append(spawnedProc, strVal(msg, "command"))

		case "env":
			key := strVal(msg, "key")
			if !envSeen[key] {
				envSeen[key] = true
				envAccess = append(envAccess, key)
			}

		default:
			// Unknown type; keep as stderr
			stderrBuf.WriteString(line)
			stderrBuf.WriteByte('\n')
		}
	}

	waitErr := cmd.Wait()
	duration := time.Since(start)

	result := &RunResult{
		PackageDir:   packageDir,
		EntryPoint:   entryPoint,
		Duration:     duration,
		Stdout:       stdoutBuf.String(),
		Stderr:       stderrBuf.String(),
		NetworkCalls: netCalls,
		FileAccess:   fileAccess,
		EnvAccess:    envAccess,
		SpawnedProcs: spawnedProc,
	}

	if ctx.Err() != nil {
		result.TimedOut = true
		result.Error = "execution timed out"
	}

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if !result.TimedOut {
			result.Error = waitErr.Error()
		}
	}

	return result, nil
}

// resolveEntryPoint reads package.json to find the main field, falling back to index.js.
func resolveEntryPoint(dir string) string {
	pkgPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return "index.js"
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil || pkg.Main == "" {
		return "index.js"
	}

	return pkg.Main
}

func strVal(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}
