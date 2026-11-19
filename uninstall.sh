#!/bin/bash
# touchvault uninstaller. Removes the CLI, helpers, Claude Code skill and hook. Leaves your Keychain items and
# your Secure Enclave key file (~/.config/touchvault) alone: without that key file, sealed values cannot be opened.
set -euo pipefail

if [ -e /usr/local/bin/touchvault ] || [ -e /usr/local/libexec/touchvault ]; then
  echo "removing the root-owned install (sudo asks for your Mac password)"
  sudo rm -rf /usr/local/bin/touchvault /usr/local/libexec/touchvault
fi

rm -f "$HOME/.local/bin/touchvault" "$HOME"/.local/bin/__pycache__/touchvault*.pyc
rmdir "$HOME/.local/bin/__pycache__" 2>/dev/null || true
rm -rf "$HOME/.local/libexec/touchvault"
rm -rf "$HOME/.claude/skills/touchvault"
HOOK="$HOME/.claude/hooks/touchvault_keychain_guard.py"
rm -f "$HOOK"

if [ -f "$HOME/.claude/settings.json" ]; then
  python3 - "$HOME/.claude/settings.json" "$HOOK" <<'PY'
import json, shlex, shutil, sys, time
path, hook = sys.argv[1], sys.argv[2]
cmd = "python3 " + shlex.quote(hook)
with open(path) as f: cfg = json.load(f)
pre = cfg.get("hooks", {}).get("PreToolUse", [])
if not any(h.get("command") == cmd for e in pre for h in e.get("hooks", [])): sys.exit(0)
backup = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
shutil.copy2(path, backup); print(f"backed up settings.json to {backup}")
for e in pre: e["hooks"] = [h for h in e.get("hooks", []) if h.get("command") != cmd]
cfg["hooks"]["PreToolUse"] = [e for e in pre if e["hooks"]]
if not cfg["hooks"]["PreToolUse"]: del cfg["hooks"]["PreToolUse"]
if not cfg["hooks"]: del cfg["hooks"]
with open(path, "w") as f: json.dump(cfg, f, indent=2); f.write("\n")
print("removed keychain_guard hook from settings.json")
PY
fi

SERVICE="${TOUCHVAULT_SERVICE:-touchvault}"
echo "touchvault removed. Your keys are still in the Keychain (service \"$SERVICE\")."
echo "To delete them too: open Keychain Access and search \"$SERVICE\", or for each name run"
echo "  security delete-generic-password -s $SERVICE -a NAME"
