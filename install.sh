#!/bin/bash
# touchvault installer. Usage: ./install.sh [--user] [--claude]
#   default: builds the helpers into /usr/local/libexec/touchvault/ and the CLI into /usr/local/bin/touchvault,
#            owned by root:wheel 755 (sudo asks for your Mac password once), so a program running as you cannot swap them
#   --user   the old layout: ~/.local/libexec/touchvault/ + ~/.local/bin/touchvault, no sudo (swappable by same-user code)
#   --claude also installs the Claude Code skill and the keychain_guard hook (settings.json is backed up first)
# Either way, sealed values stay safe: opening one needs this Mac's Secure Enclave and your fingerprint.
set -euo pipefail
cd "$(dirname "$0")"
[ "$EUID" = 0 ] && { echo "run as yourself, not root; it will ask for sudo when it needs it"; exit 1; }

USER_MODE=0; CLAUDE=0
for a in "$@"; do case "$a" in --user) USER_MODE=1;; --claude) CLAUDE=1;; *) echo "unknown option $a"; exit 1;; esac; done

[ "$(uname -s)" = "Darwin" ] || { echo "touchvault is Mac only (needs the macOS Keychain, Secure Enclave and Touch ID)."; exit 1; }
command -v swiftc >/dev/null || { echo "swiftc not found. Install the Xcode Command Line Tools: xcode-select --install"; exit 1; }
[ -x /usr/bin/python3 ] || { echo "python3 not found. Install the Xcode Command Line Tools: xcode-select --install"; exit 1; }

BUILD=$(mktemp -d); trap 'rm -rf "$BUILD"' EXIT
for h in sevault concealed_copy; do
  echo "building $h"
  swiftc -O "helpers/$h.swift" -o "$BUILD/$h"
done
# system Python in isolated mode (-I): no PYTHONPATH, no user site-packages, no PATH lookup of python3
sed '1s|.*|#!/usr/bin/python3 -I|' touchvault > "$BUILD/touchvault"

if [ "$USER_MODE" = 1 ]; then
  BIN="$HOME/.local/bin"; LIB="$HOME/.local/libexec/touchvault"; SUDO=""
  mkdir -p "$BIN" "$LIB"
else
  BIN="/usr/local/bin"; LIB="/usr/local/libexec/touchvault"; SUDO="sudo"
  echo "installing into $LIB and $BIN as root (your Mac password is asked once)"
  sudo mkdir -p "$BIN" /usr/local/libexec
  for d in "$BIN" /usr/local/libexec; do   # a user-owned parent lets same-user code rename our files away
    owner=$(stat -f %Su "$d")
    [ "$owner" = root ] || { echo "$d is owned by $owner (Intel Homebrew does this), so a program running as you could replace touchvault in it. Use ./install.sh --user, or install somewhere root-owned."; exit 1; }
  done
  sudo install -d -o root -g wheel -m 755 "$LIB"
fi
for h in sevault concealed_copy; do $SUDO install ${SUDO:+-o root -g wheel} -m 755 "$BUILD/$h" "$LIB/$h"; done
$SUDO install ${SUDO:+-o root -g wheel} -m 755 "$BUILD/touchvault" "$BIN/touchvault"
$SUDO rm -f "$LIB/touchid_gate"   # v1 helper, no longer used
echo "installed $BIN/touchvault"

if [ "$CLAUDE" = 1 ]; then
  mkdir -p "$HOME/.claude/skills/touchvault" "$HOME/.claude/hooks"
  sed "s|~/.local/bin/touchvault|$BIN/touchvault|g" claude/SKILL.md > "$HOME/.claude/skills/touchvault/SKILL.md"
  HOOK="$HOME/.claude/hooks/touchvault_keychain_guard.py"
  install -m 755 claude/keychain_guard.py "$HOOK"
  python3 - "$HOME/.claude/settings.json" "$HOOK" <<'PY'
import json, os, shlex, shutil, sys, time
path, hook = sys.argv[1], sys.argv[2]
cmd = "python3 " + shlex.quote(hook)
cfg = {}
if os.path.exists(path):
    with open(path) as f: cfg = json.load(f)
pre = cfg.setdefault("hooks", {}).setdefault("PreToolUse", [])
if any(h.get("command") == cmd for e in pre for h in e.get("hooks", [])):
    print("keychain_guard hook already in settings.json")
else:
    entry = next((e for e in pre if e.get("matcher") == "Bash"), None)
    if entry is None: entry = {"matcher": "Bash", "hooks": []}; pre.append(entry)
    entry.setdefault("hooks", []).append({"type": "command", "command": cmd})
    if os.path.exists(path):
        backup = f"{path}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(path, backup); print(f"backed up settings.json to {backup}")
    with open(path, "w") as f: json.dump(cfg, f, indent=2); f.write("\n")
    print("added keychain_guard hook to settings.json")
PY
  echo "installed Claude Code skill + hook (restart Claude Code to load them)"
fi

case ":$PATH:" in *":$BIN:"*) ;; *) echo "note: add $BIN to your PATH, e.g. echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.zprofile";; esac
echo "done. next: touchvault init   (once per Mac), then touchvault status / touchvault migrate"
