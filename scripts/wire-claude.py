"""
wire-claude.py — Idempotently wire the unravel MCP server + plugin into
Claude Code's user-global config files. Safe to re-run.

Touches:
  ~/.claude/mcp.json                          (adds unravel server)
  ~/.claude/plugins/installed_plugins.json    (registers unravel@local)

Backs both up with a timestamp suffix before any write. Never overwrites
an existing unravel entry.

Usage:
  python .scripts/wire-claude.py [--dry-run]

See docs/runbooks/plugin-mcp-wiring.md for the why.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path


def patch_mcp(path: Path, binary: Path, dry_run: bool) -> bool:
    cfg = json.loads(path.read_text())
    servers = cfg.setdefault("mcpServers", {})
    if "unravel" in servers:
        print(f"[skip] mcp.json already has 'unravel' entry")
        return False
    servers["unravel"] = {"command": str(binary), "args": ["mcp", "serve"]}
    if dry_run:
        print(f"[dry-run] would add 'unravel' to {path}")
        return True
    ts = time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(path, path.with_suffix(path.suffix + f".bak-{ts}"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.replace(tmp, path)
    print(f"[ok]   added 'unravel' to {path}")
    return True


def patch_installed(path: Path, install_path: Path, dry_run: bool) -> bool:
    data = json.loads(path.read_text())
    plugins = data.setdefault("plugins", {})
    key = "unravel@local"
    if key in plugins:
        print(f"[skip] installed_plugins.json already has '{key}'")
        return False
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    plugins[key] = [{
        "scope": "user",
        "installPath": str(install_path),
        "version": "0.1.0",
        "installedAt": now,
        "lastUpdated": now,
        "gitCommitSha": "",
    }]
    if dry_run:
        print(f"[dry-run] would register '{key}' in {path}")
        return True
    ts = time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(path, path.with_suffix(path.suffix + f".bak-{ts}"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)
    print(f"[ok]   registered '{key}' in {path}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="Show planned changes without writing")
    args = ap.parse_args()

    home = Path.home()
    mcp_path = home / ".claude" / "mcp.json"
    inst_path = home / ".claude" / "plugins" / "installed_plugins.json"
    install_path = home / ".claude" / "plugins" / "local" / "unravel"
    binary = home / "go" / "bin" / "unravel.exe"

    for p in (mcp_path, inst_path):
        if not p.exists():
            print(f"[err]  missing required file: {p}")
            return 2

    if not install_path.exists():
        print(f"[warn] plugin junction not found at {install_path}")
        print(f"       create it first: mklink /J <target> {install_path}")

    if not binary.exists():
        # Try the unix-style path too (in case of WSL / msys).
        alt = home / "go" / "bin" / "unravel"
        if alt.exists():
            binary = alt
        else:
            print(f"[warn] binary not found at {binary}; expecting it later via `go install ./...`")

    print(f"home      = {home}")
    print(f"binary    = {binary}")
    print(f"plugin    = {install_path}")
    print()

    changed = False
    changed |= patch_mcp(mcp_path, binary, args.dry_run)
    changed |= patch_installed(inst_path, install_path, args.dry_run)

    if changed and not args.dry_run:
        print("\nDone. Restart Claude Code to pick up the changes.")
    elif not changed:
        print("\nNothing to do — already wired.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
