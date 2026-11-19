# touchvault

A fingerprint-locked API key vault for macOS, built so an AI coding assistant can use your keys without ever seeing them.

Version 2: every key is sealed to your Mac's **Secure Enclave** (the security chip) before it goes into the Keychain.
The Keychain only ever holds scrambled `tv1:` envelopes. Opening one needs your enrolled fingerprint, and that rule is
enforced by the chip itself, not by this program and not by a hook. The assistant (or any script) only ever handles
key **names**. Values go from you into a sealed envelope, and from the envelope straight into the program that needs
them, after you touch the sensor.

Mac only.

## Why

AI coding assistants are great at wiring up APIs, and terrible places to keep secrets. Keys pasted into chat end up
in transcripts. Keys in `.env` files and `~/.zshrc` get read, grepped, printed and committed by accident.

touchvault gives the assistant a better path: "run this program with `OPENAI_API_KEY`". You touch the sensor,
the program gets the key as an environment variable, and nothing prints it.

## Install

Needs macOS on a Mac with a Secure Enclave and Touch ID (Apple silicon, or an Intel Mac with a T2 chip and Touch ID),
plus the Xcode Command Line Tools (`xcode-select --install`).

```sh
./install.sh                     # CLI into /usr/local, owned by root (asks for your Mac password once)
./install.sh --claude            # same, plus the Claude Code skill and safety hook
./install.sh --user [--claude]   # old layout in ~/.local, no password needed
touchvault init                  # once per Mac: makes the Secure Enclave key
touchvault status                # key there? anything still in plain text?
touchvault migrate               # seal keys stored by touchvault v1 (plain text) in place
```

The default install builds two small Swift helpers (`sevault`, `concealed_copy`) into `/usr/local/libexec/touchvault/`
and puts the CLI at `/usr/local/bin/touchvault`, all owned by root, so a program running as you cannot swap them for
look-alikes. The CLI runs with the system Python in isolated mode, so your PATH and Python settings cannot redirect it.
`--user` puts everything in `~/.local` instead, where any program running as you could replace it. Either way your
values stay safe at rest, because opening one needs the Secure Enclave and your fingerprint. A swapped helper could
only show you a fake prompt (see the limits below).

`init` writes the key file to `~/.config/touchvault/se_key.blob` (folder and file readable only by you). That file is
not the key itself; it is a wrapped handle that only this Mac's Secure Enclave can use. `init` refuses to replace an
existing key unless you add `--force`, and you should almost never do that: a new key makes every sealed value
unreadable.

`init` also prints the key's **pubhash** and pins it in the Keychain (service `touchvault-pin`, not a secret). Write
the pubhash down. Every seal checks that the key on disk still matches the pin and refuses if not. After a deliberate
`init --force` that happens automatically; for a key made before pinning existed, check `touchvault status` and add
`--repin` to your next `set` / `import` / `migrate`.

The install refuses to run as root (it asks for sudo itself), and the default install refuses a `/usr/local/bin` that
you own (Intel Homebrew does this): use `--user` or a root-owned prefix there.

`./uninstall.sh` removes the CLI, helpers, skill and hook. Your Keychain items and your key file are left alone.

## 60-second quick start

```sh
touchvault init                                  # once
touchvault set OPENAI_API_KEY                    # a hidden box pops up; paste the key there
touchvault has OPENAI_API_KEY                    # yes
touchvault run OPENAI_API_KEY -- python3 app.py  # touch the sensor once; app.py sees $OPENAI_API_KEY
```

Moving keys out of a `.env` file:

```sh
touchvault scan ~/code                            # which files hold keys in plain text (names only)
touchvault import STRIPE_SECRET_KEY --from ~/code/shop/.env
touchvault verify STRIPE_SECRET_KEY --from ~/code/shop/.env   # match
# now delete the plain-text copy yourself
```

Coming from touchvault v1 (plain values in the Keychain): `touchvault init`, then `touchvault migrate`. It needs no
fingerprint (those values are already readable by any program running as you, and migrate never prints them). It
seals each one in place, then checks that every item starts with `tv1:`. Use `TOUCHVAULT_SERVICE=name touchvault
migrate` for another service. Reading a legacy item is refused until you migrate.

From Python:

```python
import os, importlib.util as u
from importlib.machinery import SourceFileLoader
p = "/usr/local/bin/touchvault"   # or os.path.expanduser("~/.local/bin/touchvault") for --user
ld = SourceFileLoader("touchvault", p); tv = u.module_from_spec(u.spec_from_loader("touchvault", ld))
ld.exec_module(tv)
key = tv.get("OPENAI_API_KEY")   # Touch ID for this name; later get() of the same name is free
```

## Commands

Run `touchvault --help` for the full list. Only `verify`, `run`, `copy`, `send`, `receive --verify` and `get()` read
a value, so only they ask for Touch ID.

Details worth knowing:

- No command ever prints a value. Sealing happens over stdin, and the sealed envelope goes into the Keychain over
  stdin as hex, never on the command line.
- Values must be printable ASCII, up to 1400 characters (the sealed envelope is about a third bigger and has to fit
  the Keychain input path). A v1 item longer than that is skipped by `migrate` and named.
- Only the keys you name are opened. `run A,B -- cmd` opens A and B with one touch; `get("A")` opens A only, and a
  later `get("B")` costs one more touch. Opened values stay in that process's memory until it exits. A missing name
  fails before any prompt.
- The prompt always starts with `touchvault:` and says which keys are being released and, for `run`, which command
  gets them. Read it.
- No password fallback and no reuse of an earlier unlock. Cancel means no key, and the CLI prints `LOCKED`.
- `copy` keeps the key on this Mac (no Universal Clipboard), marks it concealed and transient so well-behaved
  clipboard managers skip it, and wipes it after N seconds unless you copied something else meanwhile.
  The CLI returns right away; a small helper does the wipe in the background.
- `TOUCHVAULT_SERVICE` picks the Keychain service name (default `touchvault`). The self-test uses
  `touchvault-selftest` so it never touches your real keys.

## Share keys with your other Mac

Each Mac has its own Secure Enclave key, so a value sealed on one Mac cannot be opened on another. To get your keys
onto a second Mac, the sending Mac opens them (one touch) and seals them again to the receiving Mac's public key. The
values never exist as plain text outside the sending process.

On the **receiving** Mac:

```sh
touchvault init                              # once, if this Mac has no key yet
touchvault pubkey --out mymac.pub            # prints this Mac's pubhash; the file is public
```

Move `mymac.pub` to the sending Mac by AirDrop or a USB stick (it is public, so email works too). Keep the receiving
Mac's screen in view: the pubhash it just printed is what you check next.

On the **sending** Mac:

```sh
touchvault send OPENAI_API_KEY,GITHUB_TOKEN --to mymac.pub --expect <pubhash> -o keys.bundle
touchvault send --all --to mymac.pub --expect <pubhash> -o keys.bundle
```

If the key ID you typed does not match the file, `send` refuses before asking for your fingerprint. If it matches,
you touch the sensor once, and `keys.bundle` (mode 0600) holds the names and sealed envelopes. `send` prints the names,
a count, and a **bundle hash** with the exact line to run on the other Mac. Leave that screen up.

Move `keys.bundle` to the receiving Mac by AirDrop or a USB stick. Do not put it in git (see below). Then on the
**receiving** Mac, typing the bundle hash from the sending Mac's screen:

```sh
touchvault receive keys.bundle --expect <bundle hash>              # no fingerprint needed
touchvault receive keys.bundle --expect <bundle hash> --verify     # then opens the received keys once (one touch)
touchvault receive keys.bundle --expect <bundle hash> --only GITHUB_TOKEN
touchvault receive keys.bundle --expect <bundle hash> --overwrite  # replace names that already exist here
```

**The two checks, in plain words.** Each one is a number you carry by eye from one Mac's screen to the other:

1. **Receiver key ID into `send --expect`.** The receiving Mac shows its pubhash on its own screen; you type it into
   `send` on the sending Mac. This proves the bundle is locked to YOUR other Mac and not to a stranger's key swapped
   in on the way.
2. **Bundle hash into `receive --expect`.** The sending Mac shows the bundle hash on its own screen; you type it into
   `receive` on the receiving Mac. This proves the file you are storing is the exact one your Mac made, not a fake
   built by someone who knows your (public) key. Without it, `receive` refuses and stores nothing.

Typing it from a photo of the other screen or an iMessage is fine; copying it from the same place the file came from
is not. Whoever can swap the file can swap a hash sitting next to it.

`receive` also refuses a bundle made for another key, a damaged header, or any malformed line, and then stores
nothing. It stores each envelope exactly as it came (it is already sealed to this Mac's key). Names that already exist
are skipped and listed unless you add `--overwrite`. If the Keychain refuses a write part way through, it names what
was already stored; run the same command again (without `--overwrite`) and those are skipped.

What is protected: the bundle can only be opened by the receiving Mac's chip, after a fingerprint on that Mac. Anyone
who reads it in transit gets ciphertext. Sending needs the sender's fingerprint.

Limits:

- **Keep bundles out of git.** If a bundle is ever committed, it stays in the history forever, even after you delete
  the file. The values are still ciphertext that only the receiving Mac's chip plus an enrolled finger can open, but
  the key NAMES are plain text for anyone who can read the repo. AirDrop or USB leaves no such trail.
- **The checks are only as good as your eyes.** Copying a hash from the same email, chat or folder that carried the
  file proves nothing.
- Values over 1400 characters cannot be sent (they could not be stored either).

## Claude Code integration

`./install.sh --claude` adds two things:

1. **A skill** (`~/.claude/skills/touchvault/SKILL.md`) that teaches Claude to check `has` / `list` / `status` before
   asking you for anything, to use `set` (the pop-up box) instead of asking you to paste a key into chat, and to use
   keys only through `run` or `get()`.
2. **A PreToolUse hook** (`~/.claude/hooks/touchvault_keychain_guard.py`, added to `~/.claude/settings.json` under the
   `Bash` matcher). It blocks Bash commands that read Keychain items directly, dump the environment or echo
   secret-looking variables, plus the bypasses found in a pentest of v1: the long `--password` flag, flag clusters
   with an attached value like `-wj1`, bare `export` / `declare` / `typeset` and their `-p` forms, base64 decoded into
   a shell, `curl | bash`, environment reads from Python, Node and Ruby one-liners, and clipboard reads (`pbpaste`,
   `osascript` asking for the clipboard). Your `settings.json` is backed
   up with a timestamp before it changes, and running the installer twice does not add the hook twice.

The hook is a convenience that keeps honest mistakes out of the transcript. **It is not the lock. The Secure Enclave
is.** Restart Claude Code after installing.

## Threat model and honest limits

### What the hardware now enforces

- **No plain text at rest.** The Keychain holds only `tv1:` envelopes: a one-time P-256 public key, then AES-GCM
  ciphertext under a key made from an ECDH exchange with your Secure Enclave key (HKDF-SHA256, salt `touchvault-v1`).
  Any program can read an envelope. On its own it is useless.
- **Opening needs an enrolled fingerprint, checked by the chip.** The Secure Enclave key was made with
  `privateKeyUsage` and `biometryAny`, and only works while this Mac is unlocked. The chip will not do the decryption
  step until an enrolled fingerprint is presented. Patching this script, swapping a helper or getting past the Claude
  hook does not change that for values already sealed. At most it gets ciphertext.
- **The key file is useless anywhere else.** `se_key.blob` is a handle wrapped by this Mac's Secure Enclave. Copied
  to another machine, or restored from a backup onto new hardware, it does nothing.
- **Enrolling another finger keeps your keys.** `biometryAny` accepts any enrolled finger, now or later.
- **Sealing checks the key against the pin.** Before sealing, the CLI compares the key's pubhash with the one pinned at
  `init`, and `sevault` checks that `se_key.pub` matches the key file and refuses a key that works with no prompt at
  all. That last probe does not prove the key needs a fingerprint (a key gated by an app password also passes it);
  the pin is the real check.

### What is still up to you

- **Your Mac login password can add a fingerprint.** `biometryAny` means any finger enrolled in Touch ID, including
  one added later. Anyone who knows your login password can enroll their own finger in System Settings and then open
  your keys. Guard the login password like the keys.
- **A same-user attacker can redirect FUTURE seals.** A program running as you that replaces the key files AND the
  pin in the Keychain (it can write both) can make values you seal from then on readable without your fingerprint.
  Values already sealed stay safe; they need the original key. To check: `touchvault status` shows the pubhash; compare
  it with what `init` printed. `TOUCHVAULT_KEYDIR` (for tests) moves the key, so the CLI warns when it is set.
- **Confidentiality, not integrity.** Anyone can seal a value to your public key and overwrite an item in the
  Keychain. The vault keeps values secret; it does not prove a value is the one you stored. If a key suddenly stops
  working, `verify` it against the provider.
- **No Touch ID, no keys.** With the lid closed and no Touch ID keyboard, or Touch ID off, every read prints `LOCKED`
  and exits 1.

- **Only touch the sensor for a prompt you expected.** A program running as you can pop up its own Touch ID prompt,
  or run the real `touchvault` with a command of its own choosing. The real prompt always starts with `touchvault:`
  and names the keys and the command. If you did not just ask for that, press Cancel. A `--user` install can be
  swapped by such a program; the root-owned default install cannot.
- **Once a program has a value, it can do anything with it.** Approving `run KEY -- some-command` gives that command
  the key; it can print it or send it anywhere. Inside one touchvault process, the keys it opened stay in memory.
- **If the Secure Enclave is replaced or the key file is deleted, sealed values are gone.** A logic board repair, a
  new Mac, or `init --force` means nothing can open the old envelopes. Keep the originals where they came from (each
  provider's dashboard) so you can issue or copy them again.
- **Unattended jobs cannot use it.** Cron jobs, launch agents and anything that runs while you are away cannot get a
  fingerprint. That is the point, but plan for it.
- **The hook can be talked around.** These still get past it (listed in `tests/test_guard.py`): text built at run time
  (`eval "$(printf ...)"`, string pieces glued together inside `python -c`), Python `{**os.environ}` or
  `getattr(os, 'env'+'iron')`, Node `process["en"+"v"]`, decoding or downloading to a file and then running the file,
  `xxd -r` into a shell. For stored keys, none of them reach a value, only ciphertext. For keys already in a
  program's environment, they can, which is why `run` shows you the command.
- **Clipboard managers.** `copy` and `set --clipboard` rely on the concealed / transient clipboard markers. A clipboard
  manager that ignores them may keep a copy. The pop-up box (`set NAME`) avoids the clipboard entirely.

## Tests

```sh
python3 tests/test_guard.py   # hook: table of commands that must be blocked / allowed, plus known gaps
bash tests/test_cli.sh        # CLI: init, pin, sealing, envelope format, migrate, status, scan, guards,
                              # pubkey / send / receive between two throwaway key dirs; fake TV_TEST_ keys
```

`test_cli.sh` tests the `touchvault` on your PATH (or `TV=/path/to/touchvault`), uses its own Keychain service
(`touchvault-selftest`) and a throwaway Secure Enclave key in a temp folder (`TOUCHVAULT_KEYDIR`), and cleans up after
itself. It needs the helpers built (`./install.sh --user`). Opening a value needs a person at the Mac, so the script
prints the exact manual steps at the end.

## License

MIT. See `LICENSE`.
