#!/usr/bin/env python3
"""Claude Code PreToolUse(Bash) hook for touchvault.
The assistant may reach keys ONLY through touchvault, which needs the owner's Touch ID.
Blocks direct Keychain secret reads and environment dumps in any Bash command the assistant runs.
Pattern based: a convenience that stops the obvious and the accidental, not a determined program. The real lock is
the Secure Enclave: stored values are ciphertext that only this Mac's chip can open, and only after a fingerprint."""
import json, re, sys

SECRET_WORD = r"[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASS|PASSWORD|PWD|CREDENTIAL|AUTH|PRIVATE)"
SECRET_VAR = r"\$\{?" + SECRET_WORD
START = r"(^|[;&|(`]\s*|\$\(\s*|--\s+|\b(exec|command|builtin|sudo|nohup|time)\s+)"   # command position
SH = r"(?<![\w.-])(\S*/)?(ba|z|da|k|fi)?sh\b"
BLOCK = [
    # find-*-password with -w / -g anywhere after it (also inside python/shell strings). Clusters: only the no-argument
    # flags g/h/w can come before it (-gas, -hw), and anything may follow (-wj1 = -w plus -j "1"); also --password.
    (r"find-(generic|internet)-password(?=.*([\s'\",\[(]-[ghw]*[gw]|--password\b))", "reads a Keychain secret directly"),
    (r"\bsecurity\b[^|;&]*\bdump-keychain\b[^|;&]*\s-[a-z]*d\b", "dumps Keychain secret data"),
    (r"\bsecurity\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*i\b", "opens the interactive Keychain shell"),
    (r"\bsecurity\b[^|;&]*\b(export|find-certificate\s+[^|;&]*-[a-zA-Z]*p)\b", "exports Keychain items"),
    (START + r"(printenv|env)\s*($|[;&|)>`])", "prints the environment"),
    (START + r"((export|declare|typeset|readonly)(\s+-[a-zA-Z]+)*|set)\s*($|[;&|)>`])", "prints the shell variables"),
    (r"\b(export|declare|typeset|readonly)\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*p\b", "prints shell variables"),
    # decoded or downloaded text handed to a shell (hides any command from the patterns above)
    (r"(?=.*\bbase64\s+(-[a-zA-Z]*[dD]\b|--decode\b))(?=.*(\|\s*(sudo\s+)?" + SH + r"|\beval\b|\b(source|exec)\b|" + SH + r"\s+-c\b))",
     "runs base64-decoded text as a command"),
    (r"\bexec\s*\([^)]*(b64decode|base64|decode\()", "execs decoded text"),
    (r"\b(curl|wget)\b[^;&]*\|\s*(sudo\s+)?" + SH + r"|" + SH + r"[^;&|]*(<\(|\$\()\s*(curl|wget)\b", "pipes a download into a shell"),
    # environment reads from python / node / ruby one-liners
    (r"(dict|print|json\.dumps|JSON\.stringify|console\.log|pprint|str|repr)\s*\(\s*(dict\()?\s*(os\.environ|process\.env)\b(?!\s*[\[.])"
     r"|(os\.environ|process\.env)\s*\)|(os\.environ|process\.env)\.(items|copy|keys|values|entries)\b|Object\.\w+\(\s*process\.env",
     "dumps the environment"),
    (r"(os\.environ\s*(\.get\s*\(|\[)|os\.getenv\s*\(|getenv\s*\(|process\.env\s*(\.|\[)|\bENV\s*(\[|\.fetch))\s*[\"'`]?" + SECRET_WORD,
     "reads a secret variable"),
    (r"\bprintenv\s+" + SECRET_WORD, "prints a secret variable"),
    (r"\b(echo|printf|print)\b[^;&|]*" + SECRET_VAR, "echoes a secret variable"),
    (r"\bkSecReturnData\b|SecItemCopyMatching|SecKeychainFindGenericPassword", "calls the Keychain API directly"),
    # the clipboard may hold a key from `touchvault copy` or a site's Copy button
    (r"\bpbpaste\b|\bosascript\b.*(\bthe\s+clipboard\b|\bclipboard\s+info\b|theClipboard|NSPasteboard)", "reads the clipboard"),
]

def blocked(cmd):
    """Return the reason a command is blocked, or None. Checks the raw text and a copy with quotes/backslashes removed."""
    for text in (cmd, re.sub(r"[\"'\\]", "", cmd)):
        for pat, why in BLOCK:
            if re.search(pat, text): return why
    return None

if __name__ == "__main__":
    try:
        cmd = json.load(sys.stdin).get("tool_input", {}).get("command", "")
    except Exception:
        sys.exit(0)
    why = blocked(cmd or "")
    if why:
        sys.stderr.write(f"Blocked by keychain_guard: this command {why}. Keys come out only through "
                         "touchvault (Touch ID). Use `touchvault run NAME -- cmd` or get(NAME) in a script.\n")
        sys.exit(2)
    sys.exit(0)
