---
name: touchvault
description: Use whenever a task needs an API key, token, password or app secret, or the user mentions keys, credentials, secrets or the vault. Keys live encrypted in the macOS Keychain via touchvault; Claude never reads, prints or asks for key values.
---

# touchvault: one Touch ID-gated home for every key

Every key lives in the macOS Keychain (service `touchvault`, or `$TOUCHVAULT_SERVICE`) as a `tv1:` envelope sealed to
this Mac's Secure Enclave. Opening one needs the owner's fingerprint, enforced by the chip (run / copy / verify, or
`get()` from Python). There is no password fallback, so a person must be at the Mac.
Tell the user to expect the fingerprint prompt before running anything that reads a key. One touch covers all the
names in one `run A,B -- cmd`; each separate `get()` name costs its own touch. The prompt shows the key names and
the command they are being given to.
Claude handles key NAMES only. Values go from the user straight into the Keychain and from the Keychain
straight into the program that needs them.

Tool: `~/.local/bin/touchvault <command>`

## Commands
- `status`: is the Secure Enclave key there, its pubhash and whether it matches the pin, how many items are sealed vs
  legacy plain text (names only). If the key is MISSING, tell the user to run `touchvault init` once. If items are
  legacy, suggest `touchvault migrate` (legacy items cannot be read until then). If it says `pinned: NO`, stop and
  tell the user; sealing refuses until they decide.
- Full command list: `touchvault --help`.
- `has NAME` / `list`: check what is stored (no Touch ID). Always check before asking the user for anything.
- `set NAME`: pops a hidden-entry dialog on the user's screen. Run it yourself, then tell the user
  "paste it into the touchvault box that just opened." Never ask them to paste a key into chat.
- `set NAME --clipboard`: when a website has a "Copy" button for a token, Claude may click Copy, then run this.
  The clipboard is wiped right after.
- `import NAME --from FILE [--var VAR]`: move a value out of a .env, shell profile, or JSON (`--var a.b.c`).
  `--raw` takes the whole file as the value.
- `verify NAME --from FILE [--var VAR]`: prints `match` or `DIFFERENT`. Run after every import.
- `scan [DIR...]`: lists keys still sitting in plain text (file + name only).
- `run NAME[,NAME] -- CMD ...`: run a program with those keys as environment variables.
- `copy NAME [--seconds 30]`: for a PERSON to paste somewhere. Claude never reads the clipboard after it.
- `delete NAME`: remove one key.
- `pubkey [--out FILE]`, `send NAME[,NAME...]|--all --to PUBFILE --expect PUBHASH -o BUNDLE`,
  `receive BUNDLE --expect BUNDLEHASH [--overwrite] [--only NAMES] [--verify]`: move keys to the user's other Mac
  (see rules 10-12).
- Python: load the module by path and call `get("NAME")`:
  ```python
  import os, importlib.util as u
  from importlib.machinery import SourceFileLoader
  p = os.path.expanduser("~/.local/bin/touchvault")
  ld = SourceFileLoader("touchvault", p); tv = u.module_from_spec(u.spec_from_loader("touchvault", ld))
  ld.exec_module(tv); token = tv.get("OPENAI_API_KEY")
  ```

## Rules
1. Never cat, Read, grep -A, or print .env files, ~/.zshrc, keys.json, token files or database contents.
   To see names in such a file, use `scan`.
2. Never `echo $SECRET`, never `run NAME -- env`, never put a key in a URL you print, a commit, a log, or chat.
3. New tools read keys with `get()` (or `run`), never from a plain-text file.
4. Migrating a key: `import`, then `verify`; only after `match`, ask the user before deleting the plain-text copy.
5. Typing a secret into a web form stays the user's job. Clicking a site's Copy button then `set --clipboard` is fine.
6. Names: UPPER_SNAKE with a service prefix, e.g. `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`.
7. If the keychain_guard hook blocks a command, do not look for a way around it. Use touchvault.
8. Never run `touchvault init --force` or pass `--repin`: the first makes every sealed value unreadable, the second
   accepts a changed key. Only the user may do either.
9. Never read the clipboard (`pbpaste`, `osascript`): it may hold a key.
10. Moving keys between Macs goes ONLY through `pubkey` / `send` / `receive`. Claude never moves plain values between
    machines (no copying .env files, no scp of secrets, no pasting values into a message).
11. `send` always gets `--expect`. Never fill it from the .pub file or the message that carried it: ask the user to
    read the pubhash off the RECEIVING Mac's screen (`touchvault pubkey` there) and tell you. Tell them it must match.
12. Both checks, every time. `send` prints a `bundle hash`; `receive` always gets `--expect` with it. Never fill it
    from the bundle file, a hash file next to it, or the message or folder that carried the file: ask the user to read
    it off the SENDING Mac's screen and tell you (a photo of that screen or an iMessage is fine). Suggest AirDrop or a
    USB stick to move the bundle, never git: a committed bundle stays in history and its key names are readable.
    Never add `--overwrite` unless the user asks for it.
