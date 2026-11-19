#!/bin/bash
# CLI self-test. Uses a SEPARATE Keychain service (touchvault-selftest), fake TV_TEST_ values only, and a throwaway
# Secure Enclave key in a temp dir (TOUCHVAULT_KEYDIR), so your real keys and your real key file are never touched.
# Covers everything that needs no Touch ID; prints manual Touch ID steps at the end.
# Run: bash tests/test_cli.sh     (tests the installed `touchvault` on PATH; TV=/path/to/touchvault to pick another)
set -uo pipefail
cd "$(dirname "$0")/.."
export TOUCHVAULT_SERVICE=touchvault-selftest
TV="${TV:-$(command -v touchvault || echo ./touchvault)}"
SEVAULT="$(dirname "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$TV")")/../libexec/touchvault/sevault"
[ -x "$SEVAULT" ] || SEVAULT="$(dirname "$TV")/helpers/sevault"
[ -x "$SEVAULT" ] || { echo "build helpers first: ./install.sh --user"; exit 1; }
T=$(mktemp -d); LOG="$T/all-output.log"
export TOUCHVAULT_KEYDIR="$T/key"
realp() { python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
VAL_A="TV_TEST_fake_value_A_0123456789"
VAL_B="TV_TEST_fake_value_B_abcdef"
VAL_C="TV_TEST_fake_raw_value_C"
VAL_L="TV_TEST_fake_legacy_plain_L"
pass=0; fail=0

cleanup() {
  for n in TV_TEST_A TV_TEST_B TV_TEST_C TV_TEST_API_KEY TV_TEST_L; do "$TV" delete "$n" >/dev/null 2>&1; done
  security delete-generic-password -s touchvault-pin -a "$(realp "$T/key")" >/dev/null 2>&1
  for n in TV_TEST_X TV_TEST_Y TV_TEST_Z TV_TEST_W TV_TEST_A TV_TEST_C; do
    TOUCHVAULT_SERVICE=touchvault-selftest-b "$TV" delete "$n" >/dev/null 2>&1; done
  [ -d "$T/keyB" ] && security delete-generic-password -s touchvault-pin -a "$(realp "$T/keyB")" >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT

tv() { "$TV" "$@" 2>&1 | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }
ok()  { if [ "$1" = 0 ]; then pass=$((pass+1)); echo "  ok   $2"; else fail=$((fail+1)); echo "  FAIL $2"; fi; }
has_text() { grep -qF -- "$2" <<<"$1"; }
# the CLI's own functions, loaded as a module (values never printed; only checks/names come back)
mod() { python3 - "$TV" "$@" <<PY 2>&1 | tee -a "$LOG"
import sys, importlib.util as u
from importlib.machinery import SourceFileLoader
ld = SourceFileLoader("touchvault", sys.argv[1]); tv = u.module_from_spec(u.spec_from_loader("touchvault", ld))
ld.exec_module(tv); args = sys.argv[2:]
$(cat)
PY
}

printf 'TV_TEST_A="%s"\nexport TV_TEST_API_KEY=%s\n' "$VAL_A" "$VAL_A" > "$T/.env"
printf '{"svc": {"tokens": ["x", "%s"]}}\n' "$VAL_B" > "$T/creds.json"
printf '%s\n' "$VAL_C" > "$T/one.key"

echo "touchvault CLI self-test ($TV, service $TOUCHVAULT_SERVICE)"
out=$(tv status); has_text "$out" "MISSING"; ok $? "status before init -> key MISSING"
out=$(tv import TV_TEST_A --from "$T/.env"); [ $? != 0 ] && has_text "$out" "touchvault init"; ok $? "import before init refused, says run init"
out=$(tv init); [ $? = 0 ] && has_text "$out" "pubhash" && has_text "$out" "pinned"; ok $? "init makes a Secure Enclave key, prints + pins its pubhash"
H=$("$SEVAULT" pubhash)
has_text "$out" "$H" && [ ${#H} = 64 ]; ok $? "init printed the full pubhash"
out=$(tv status); has_text "$out" "pubhash $H" && has_text "$out" "pinned: yes"; ok $? "status shows pubhash, pinned: yes"
[ "$(stat -f %Lp "$T/key")" = 700 ] && [ "$(stat -f %Lp "$T/key/se_key.blob")" = 600 ] && [ "$(stat -f %z "$T/key/se_key.pub")" = 65 ]; ok $? "key dir 0700, blob 0600, pub 65 bytes"
cp "$T/key/se_key.blob" "$T/blob.orig"; cp "$T/key/se_key.pub" "$T/pub.orig"
out=$(tv init); [ $? != 0 ] && has_text "$out" "unreadable" && cmp -s "$T/key/se_key.blob" "$T/blob.orig"; ok $? "init again refused, key unchanged"

out=$(tv import TV_TEST_A --from "$T/.env");                   ok $? "import from .env";  has_text "$out" "stored 'TV_TEST_A' (${#VAL_A} chars, sealed)"; ok $? "import reports name + length + sealed"
has_text "$out" "TOUCHVAULT_KEYDIR is set"; ok $? "warns when TOUCHVAULT_KEYDIR is set"
out=$(tv import TV_TEST_A --from "$T/.env");                   ok $? "import again overwrites (-U)"
out=$(tv import TV_TEST_B --from "$T/creds.json" --var svc.tokens.1); ok $? "import from JSON --var a.b.1"
out=$(tv import TV_TEST_C --from "$T/one.key" --raw);          ok $? "import --raw"
out=$(tv import TV_TEST_API_KEY --from "$T/.env");             ok $? "import 'export NAME=' line"

out=$(mod "$VAL_A" <<'PY'
import base64
v = tv._stored("TV_TEST_A")
assert v.startswith("tv1:"), "no tv1 prefix"
raw = base64.b64decode(v[4:], validate=True)
assert len(raw) == 65 + 12 + len(args[0]) + 16, "wrong envelope length"
assert raw[0] == 4, "ephemeral key is not an uncompressed P-256 point"
assert args[0] not in v and args[0].encode() not in raw, "plaintext inside envelope"
assert tv.seal(args[0]) != tv.seal(args[0]), "two seals of one value are identical"
print("envelope ok")
PY
); [ "$out" = "envelope ok" ]; ok $? "Keychain holds a tv1 envelope: right length, no plaintext, fresh per seal"

# run/get open ONLY the requested names; missing names fail before any prompt (sevault open is stubbed: no touch)
out=$(mod <<'PY'
calls = []
tv._open = lambda envs, why: calls.append(len(envs)) or ["x"] * len(envs)
try: tv._load(["TV_TEST_A", "TV_TEST_NOPE"], "t"); print("no error")
except KeyError: pass
assert calls == [], "prompted before checking names"
tv._load(["TV_TEST_A", "TV_TEST_C", "TV_TEST_A"], "t")
assert calls == [2] and sorted(tv._cache) == ["TV_TEST_A", "TV_TEST_C"], "opened more than the named keys"
tv.get("TV_TEST_A"); assert calls == [2], "cached name opened again"
print("only named")
PY
); [ "$out" = "only named" ]; ok $? "_load opens only the named keys, one prompt per batch, missing name fails before prompt"

out=$(tv has TV_TEST_A);  [ $? = 0 ] && [ "$out" = yes ]; ok $? "has existing -> yes, exit 0"
out=$(tv has TV_TEST_NOPE); [ $? = 1 ] && [ "$out" = no ]; ok $? "has missing -> no, exit 1"
out=$(tv list); has_text "$out" TV_TEST_A && has_text "$out" TV_TEST_B && has_text "$out" TV_TEST_C; ok $? "list shows stored names"
out=$(TOUCHVAULT_SERVICE=touchvault "$TV" list 2>&1); ! has_text "$out" TV_TEST_; ok $? "test items stay out of the default service"

printf 'TV_TEST_A=caf\xc3\xa9\n' > "$T/bad.env"
out=$(tv import TV_TEST_A --from "$T/bad.env"); [ $? != 0 ] && has_text "$out" "printable ASCII"; ok $? "non-ASCII value refused"
printf 'TV_TEST_A=%s\n' "$(head -c 1401 /dev/zero | tr '\0' x)" > "$T/long.env"
out=$(tv import TV_TEST_A --from "$T/long.env"); [ $? != 0 ] && has_text "$out" "max 1400"; ok $? "over 1400 chars refused"
printf 'TV_TEST_A=%s\n' "$(head -c 1400 /dev/zero | tr '\0' y)" > "$T/max.env"
out=$(tv import TV_TEST_C --from "$T/max.env" --var TV_TEST_A); ok $? "exactly 1400 chars accepted (envelope fits the Keychain path)"
out=$(tv import TV_TEST_C --from "$T/one.key" --raw)
out=$(tv import "-w" --from "$T/.env"); [ $? != 0 ]; ok $? "bad key name refused"
out=$(tv import TV_TEST_A --from "$T/.env" --var MISSING); [ $? != 0 ]; ok $? "missing var refused"
out=$(tv run TV_TEST_A echo hi); [ $? != 0 ] && has_text "$out" usage; ok $? "run without -- refused before Touch ID"
out=$(perl -e 'alarm 10; exec @ARGV' "$TV" run TV_TEST_NOPE -- true 2>&1); [ $? = 1 ] && has_text "$out" "not in Keychain"; ok $? "run with a missing name fails before Touch ID"
out=$(tv copy TV_TEST_A --seconds 999); [ $? != 0 ]; ok $? "copy --seconds out of range refused before Touch ID"

# sevault open must reject a bad envelope BEFORE asking for a fingerprint (perl alarm: a prompt would hang -> fail)
BADPT="tv1:$(head -c 120 /dev/zero | base64)"   # right length, base64, but not a P-256 point
for bad in "garbage" "tv1:AAAA" "tv1:not*base64" "$BADPT"; do
  out=$(printf '%s\n' "$bad" | perl -e 'alarm 10; exec @ARGV' "$SEVAULT" open selftest 2>&1); rc=$?
  [ $rc = 1 ] && has_text "$out" "not a tv1 envelope"; ok $? "open rejects '${bad:0:16}' with no prompt"
done
out=$(printf '' | perl -e 'alarm 10; exec @ARGV' "$SEVAULT" open selftest 2>&1); [ $? = 1 ] && has_text "$out" "no envelopes"; ok $? "open with no envelopes refused (no approval-only mode)"

# seal refuses a key whose public half was swapped
head -c 65 /dev/urandom > "$T/key/se_key.pub"
out=$(tv import TV_TEST_C --from "$T/one.key" --raw); [ $? != 0 ] && has_text "$out" "does not match"; ok $? "seal refuses a swapped se_key.pub"
cp "$T/pub.orig" "$T/key/se_key.pub"

# key substitution: a different (real, fingerprint-gated) key dropped in place is refused by the pin
TOUCHVAULT_KEYDIR="$T/key2" "$SEVAULT" init >/dev/null 2>&1
cp "$T/key2/se_key.blob" "$T/key2/se_key.pub" "$T/key/"
out=$(tv import TV_TEST_C --from "$T/one.key" --raw); [ $? != 0 ] && has_text "$out" "not the pinned one"; ok $? "seal refuses a key that does not match the pin"
out=$(tv status); has_text "$out" "pinned: NO"; ok $? "status flags the unpinned key"
out=$(tv import TV_TEST_C --from "$T/one.key" --raw --repin); [ $? = 0 ] && has_text "$out" "re-pinned"; ok $? "--repin accepts the new key"
cp "$T/blob.orig" "$T/key/se_key.blob"; cp "$T/pub.orig" "$T/key/se_key.pub"
out=$(tv import TV_TEST_C --from "$T/one.key" --raw --repin); [ $? = 0 ]; ok $? "--repin back to the original key"

# probe: a Secure Enclave key with NO access control (usable without any prompt) is refused by sevault seal
cat > "$T/noacl.swift" <<'SW'
import CryptoKit
import Foundation
let dir = URL(fileURLWithPath: CommandLine.arguments[1])
let k = try! SecureEnclave.P256.KeyAgreement.PrivateKey()   // default access control: no user presence
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
try! k.dataRepresentation.write(to: dir.appendingPathComponent("se_key.blob"))
try! k.publicKey.x963Representation.write(to: dir.appendingPathComponent("se_key.pub"))
SW
if swiftc -O "$T/noacl.swift" -o "$T/noacl" 2>/dev/null && perl -e 'alarm 20; exec @ARGV' "$T/noacl" "$T/noacl_key"; then
  so=$(printf 'x' | TOUCHVAULT_KEYDIR="$T/noacl_key" perl -e 'alarm 10; exec @ARGV' "$SEVAULT" seal 2>"$T/noacl.err"); rc=$?
  [ $rc = 1 ] && [ -z "$so" ] && grep -qF "without a fingerprint" "$T/noacl.err"; ok $? "seal probe refuses a no-access-control SE key"
else ok 1 "could not build the no-access-control test key"; fi

# legacy plain-text item -> get/run refuse it -> status flags it -> migrate seals it (no Touch ID needed)
out=$(mod "$VAL_L" <<'PY'
tv._write("TV_TEST_L", args[0]); print("legacy written")
PY
); [ "$out" = "legacy written" ]; ok $? "wrote a fake legacy plain-text item"
out=$(mod <<'PY'
tv._open = lambda envs, why: (_ for _ in ()).throw(AssertionError("prompted"))
try: tv.get("TV_TEST_L"); print("read legacy")
except KeyError as e: print("refused" if "touchvault migrate" in str(e) else "wrong message")
PY
); [ "$out" = "refused" ]; ok $? "get() refuses a legacy item: run touchvault migrate (no prompt)"
out=$(tv status); has_text "$out" "1 legacy" && has_text "$out" "legacy  TV_TEST_L" && has_text "$out" "present"; ok $? "status: key present, legacy item named"
out=$(tv migrate); [ $? = 0 ] && has_text "$out" "sealed 'TV_TEST_L'" && has_text "$out" "all items sealed"; ok $? "migrate seals the legacy item"
out=$(tv status); has_text "$out" "0 legacy"; ok $? "status: 0 legacy after migrate"
out=$(tv migrate); has_text "$out" "nothing to migrate"; ok $? "migrate again -> nothing to migrate"

mkdir -p "$T/proj/sub" && cp "$T/.env" "$T/proj/sub/.env" && printf 'TV_TEST_SECRET=zzz\n' > "$T/proj/.env.example"
out=$(HOME="$T/emptyhome" tv scan "$T/proj")
has_text "$out" TV_TEST_API_KEY && has_text "$out" "sub/.env"; ok $? "scan finds names + files"
# HOME is swapped so scan never reads your real shell profiles; the Keychain lookup is done first with the real HOME
out=$(mod "$T" <<'PY'
import os
stored = tv.names(); tv.names = lambda: stored
os.environ["HOME"] = args[0] + "/emptyhome"
tv.scan([args[0] + "/proj"])
PY
)
has_text "$out" "IN KEYCHAIN  TV_TEST_API_KEY"; ok $? "scan marks names already in the Keychain"
! has_text "$out" TV_TEST_SECRET; ok $? "scan skips .env.example"

out=$(tv delete TV_TEST_B); [ $? = 0 ] && [ "$out" = deleted ]; ok $? "delete -> deleted"
out=$(tv has TV_TEST_B); [ $? = 1 ]; ok $? "has after delete -> no"
out=$(tv delete TV_TEST_B); [ $? = 1 ] && [ "$out" = "not found" ]; ok $? "delete again -> not found"

# ---- Mac-to-Mac: key dir A ($T/key, service touchvault-selftest) sends to key dir B ($T/keyB, service ...-b) --------
# No fingerprint here: bundles are assembled from `sevault seal --to` (or send with sevault open stubbed out).
KB="$T/keyB"
VAL_X="TV_TEST_fake_moved_X_42"; VAL_Y="TV_TEST_fake_moved_Y_43"; VAL_S="TV_TEST_fake_sent_value"
# B side: service + key dir B; every call under alarm so a surprise Touch ID prompt fails instead of hanging
tvb() { TOUCHVAULT_KEYDIR="$KB" TOUCHVAULT_SERVICE=touchvault-selftest-b perl -e 'alarm 20; exec @ARGV' "$TV" "$@" 2>&1 | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }
tva() { perl -e 'alarm 20; exec @ARGV' "$TV" "$@" 2>&1 | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }
sealB() { printf '%s' "$1" | "$SEVAULT" seal --to "$T/B.pub"; }
bh() { shasum -a 256 "$1" | cut -d' ' -f1; }   # the bundle hash send prints
envB() { TOUCHVAULT_KEYDIR="$KB" TOUCHVAULT_SERVICE=touchvault-selftest-b mod "$@"; }   # module bound to B

out=$(tvb init); [ $? = 0 ]; ok $? "second key dir B: init"
HB=$(TOUCHVAULT_KEYDIR="$KB" "$SEVAULT" pubhash)
out=$(tvb pubkey --out "$T/B.pub"); [ $? = 0 ] && has_text "$out" "pubhash $HB"; ok $? "pubkey prints B's pubhash (same as status)"
out=$(python3 - "$T/B.pub" "$KB/se_key.pub" "$HB" <<'PY'
import base64, hashlib, sys
l = open(sys.argv[1]).read().split("\n")
raw = base64.b64decode(l[2][4:], validate=True)
assert l[0] == "touchvault-pubkey v1" and l[1] == "pubhash " + sys.argv[3] and l[3:] == [""], "layout"
assert raw == open(sys.argv[2], "rb").read() and hashlib.sha256(raw).hexdigest() == sys.argv[3], "key/hash"
print("pubfile ok")
PY
); [ "$out" = "pubfile ok" ]; ok $? "pubkey --out: 3-line v1 file, pub = B's x963 key, pubhash = sha256(pub)"

E1=$(sealB "$VAL_X"); E2=$(sealB "$VAL_Y"); E3=$(sealB "$VAL_X")
[ "${E1:0:4}" = tv1: ] && [ "$E1" != "$E3" ] && [ "$(printf '%s' "${E1:4}" | base64 -d | wc -c | tr -d ' ')" = $((93 + ${#VAL_X})) ]
ok $? "seal --to: tv1 envelope of the right length, fresh per seal (no local key or pin used)"
sed 's/^pubhash ./pubhash 0/' "$T/B.pub" | sed 's/^pubhash 00/pubhash 01/' > "$T/Bbadhash.pub"
out=$(printf x | "$SEVAULT" seal --to "$T/Bbadhash.pub" 2>&1); [ $? = 1 ] && has_text "$out" "does not match"; ok $? "seal --to refuses a file whose pubhash line does not match its key"
python3 - "$T/Bnotpoint.pub" <<'PY'
import base64, hashlib, sys
raw = b"\x04" + b"\x00" * 64
open(sys.argv[1], "w").write(f"touchvault-pubkey v1\npubhash {hashlib.sha256(raw).hexdigest()}\npub {base64.b64encode(raw).decode()}\n")
PY
out=$(printf x | "$SEVAULT" seal --to "$T/Bnotpoint.pub" 2>&1); [ $? = 1 ] && has_text "$out" "not a valid P-256"; ok $? "seal --to refuses a self-consistent file that is not a curve point"

bundle() {   # bundle FILE TO_HASH COUNT then "NAME ENVELOPE" lines
  local f=$1 to=$2 c=$3; shift 3
  { printf 'touchvault-bundle v1\nfrom %s\nto %s\ncount %s\n' "$H" "$to" "$c"; for x in "$@"; do printf '%s\n' "$x"; done; } > "$f"
}
stored_is() { envB "$1" "$2" <<'PY'
print("same" if tv._stored(args[0]) == args[1] else "different")
PY
}
bundle "$T/b1" "$HB" 2 "TV_TEST_X $E1" "TV_TEST_Y $E2"
out=$(tvb receive "$T/b1" --expect "$(bh "$T/b1")"); [ $? = 0 ] && has_text "$out" "from $H" && has_text "$out" "stored  TV_TEST_X" && has_text "$out" "2 stored, 0 skipped"; ok $? "receive: correct to-hash accepted, prints sender pubhash + names"
[ "$(stored_is TV_TEST_X "$E1")" = same ] && [ "$(stored_is TV_TEST_Y "$E2")" = same ]; ok $? "receive stores the exact envelopes, as-is"

E4=$(sealB "$VAL_Y")
bundle "$T/b2" "$HB" 1 "TV_TEST_X $E4"
out=$(tvb receive "$T/b2" --expect "$(bh "$T/b2")"); [ $? = 0 ] && has_text "$out" "skipped TV_TEST_X" && [ "$(stored_is TV_TEST_X "$E1")" = same ]; ok $? "existing name skipped (and listed) without --overwrite"
out=$(tvb receive "$T/b2" --expect "$(bh "$T/b2")" --overwrite); [ $? = 0 ] && has_text "$out" "stored  TV_TEST_X" && [ "$(stored_is TV_TEST_X "$E4")" = same ]; ok $? "--overwrite replaces it"
bundle "$T/b3" "$HB" 2 "TV_TEST_Z $E1" "TV_TEST_Y $E4"
out=$(tvb receive "$T/b3" --expect "$(bh "$T/b3")" --only TV_TEST_Z); [ $? = 0 ] && has_text "$out" "1 stored, 0 skipped" && [ "$(stored_is TV_TEST_Y "$E2")" = same ]; ok $? "--only stores just the named key"
out=$(tvb delete TV_TEST_Z)
out=$(tvb receive "$T/b3" --expect "$(bh "$T/b3")" --only TV_TEST_NOPE); [ $? != 0 ] && has_text "$out" "not in this bundle"; ok $? "--only with a name not in the bundle refused"

refused() {   # refused LABEL FILE: receive must fail and store nothing
  out=$(tvb receive "$2" --expect "${3:-$(bh "$2")}"); rc=$?
  [ $rc != 0 ] && has_text "$out" "refusing" && ! tvb has TV_TEST_Z >/dev/null; ok $? "$1"
}
bundle "$T/r1" "$H" 1 "TV_TEST_Z $E1";                         refused "wrong to-hash (bundle for another Mac) refused" "$T/r1"
bundle "$T/r2" "$HB" 2 "TV_TEST_Z $E1";                        refused "count that does not match refused" "$T/r2"
bundle "$T/r3" "$HB" 1 "TV_TEST_Z $E1"; sed -i '' 's/^touchvault-bundle v1/touchvault-bundle v2/' "$T/r3"; refused "tampered magic line refused" "$T/r3"
bundle "$T/r4" "$HB" 1 "TV_TEST_Z $E1"; sed -i '' 's/^from /sender /' "$T/r4"; refused "tampered header line refused" "$T/r4"
bundle "$T/r5" "$HB" 1 "TV_TEST_Z $E1 extra";                  refused "line with an extra field refused" "$T/r5"
bundle "$T/r6" "$HB" 1 "-w $E1";                               refused "bad key name refused" "$T/r6"
bundle "$T/r7" "$HB" 1 "TV_TEST_Z notanenvelope";              refused "non-tv1 value refused" "$T/r7"
bundle "$T/r8" "$HB" 1 "TV_TEST_Z $BADPT";                     refused "envelope that is not a curve point refused (no prompt)" "$T/r8"
bundle "$T/r9" "$HB" 2 "TV_TEST_Z $E1" "TV_TEST_Z $E2";        refused "duplicate name refused" "$T/r9"
bundle "$T/r10" "$HB" 2 "TV_TEST_Z $E1" "TV_TEST_Q not*b64";   refused "one bad line refuses the whole bundle" "$T/r10"
out=$(tvb receive "$T/r10" --expect "$(bh "$T/r10")"); ! grep -qF "$E1" <<<"$out"; ok $? "refusals never echo an envelope"

# bundle hash: receive needs --expect = sha256 of the exact file bytes, read off the sending Mac's screen
bundle "$T/h1" "$HB" 1 "TV_TEST_Z $E1"
out=$(tvb receive "$T/h1"); [ $? != 0 ] && has_text "$out" "--expect BUNDLEHASH is required" && ! tvb has TV_TEST_Z >/dev/null; ok $? "receive without --expect refused, nothing stored"
out=$(tvb receive "$T/h1" --expect nothex); [ $? != 0 ] && has_text "$out" "--expect BUNDLEHASH is required"; ok $? "receive with a malformed --expect refused"
refused "receive with the wrong bundle hash refused, nothing stored" "$T/h1" "$(bh "$T/b1")"
out=$(tvb receive "$T/h1" --expect "$(bh "$T/h1" | tr a-f A-F)"); [ $? = 0 ] && has_text "$out" "1 stored" && [ "$(stored_is TV_TEST_Z "$E1")" = same ]; ok $? "receive with the right bundle hash (any case) accepted"
out=$(tvb delete TV_TEST_Z)

# partial Keychain failure: says what got stored, and a rerun skips those
bundle "$T/p1" "$HB" 2 "TV_TEST_Z $E1" "TV_TEST_W $E2"
out=$(envB "$T/p1" "$(bh "$T/p1")" <<'PY'
real = tv._write
tv._write = lambda n, s: tv.sys.exit(f"Keychain refused '{n}' (rc 1)") if n == "TV_TEST_W" else real(n, s)
tv.receive(args[0], args[1])
PY
); has_text "$out" "Stored before it stopped: TV_TEST_Z" && has_text "$out" "names already stored are skipped" && ! tvb has TV_TEST_W >/dev/null; ok $? "partial write names what was stored and says a rerun skips it"
out=$(tvb receive "$T/p1" --expect "$(bh "$T/p1")"); [ $? = 0 ] && has_text "$out" "skipped TV_TEST_Z" && has_text "$out" "stored  TV_TEST_W"; ok $? "rerun after a partial write finishes the rest"
out=$(tvb delete TV_TEST_Z); out=$(tvb delete TV_TEST_W)

# send: every refusal happens before the fingerprint prompt (alarm would kill a prompt)
out=$(tva send TV_TEST_A --to "$T/B.pub" -o "$T/s0"); [ $? != 0 ] && has_text "$out" "--expect PUBHASH is required" && [ ! -e "$T/s0" ]; ok $? "send without --expect refused before Touch ID"
out=$(tva send TV_TEST_A --to "$T/B.pub" --expect "$H" -o "$T/s0"); [ $? != 0 ] && has_text "$out" "Do not send" && [ ! -e "$T/s0" ]; ok $? "send with the wrong --expect refused before Touch ID"
out=$(tva send TV_TEST_A --to "$T/Bbadhash.pub" --expect "$HB" -o "$T/s0"); [ $? != 0 ] && has_text "$out" "damaged"; ok $? "send refuses a damaged pubkey file"
out=$(tva send TV_TEST_A --to "$T/Bnotpoint.pub" --expect "$(sed -n 2p "$T/Bnotpoint.pub" | cut -c9-)" -o "$T/s0"); [ $? != 0 ] && has_text "$out" "valid P-256" && [ ! -e "$T/s0" ]; ok $? "send refuses a pubkey that is not a curve point, before Touch ID"
ln -s "$T/nowhere/x" "$T/dangling"
out=$(tva send TV_TEST_A --to "$T/B.pub" --expect "$HB" -o "$T/dangling"); [ $? != 0 ] && has_text "$out" "already exists"; ok $? "send refuses a dangling-symlink -o before Touch ID"
out=$(tva send TV_TEST_A --to "$T/B.pub" --expect "$HB" -o "$T/nowhere/x"); [ $? != 0 ] && has_text "$out" "cannot write in" && ! has_text "$out" Traceback; ok $? "send refuses an -o in a missing dir before Touch ID"
out=$(mod "$T/B.pub" "$HB" "$T/race" <<'PY'
tv._open = lambda envs, why: (open(args[2], "w").close(), ["x"] * len(envs))[1]   # file appears after the check
tv.send(["TV_TEST_A"], args[0], args[1], args[2])
PY
); has_text "$out" "cannot create" && has_text "$out" "no bundle written" && ! has_text "$out" Traceback; ok $? "send: output that appears mid-way gives a clean message"
out=$(tva send TV_TEST_NOPE --to "$T/B.pub" --expect "$HB" -o "$T/s0"); [ $? != 0 ] && has_text "$out" "not in Keychain" && [ ! -e "$T/s0" ]; ok $? "send with a missing name fails before Touch ID"
# send end to end with sevault open stubbed (fake plaintexts), then receive the real bundle into B
out=$(mod "$T/B.pub" "$HB" "$T/s1" "$VAL_S" <<'PY'
calls = []
tv._open = lambda envs, why: calls.append(len(envs)) or [args[3]] * len(envs)
tv.send(["TV_TEST_A", "TV_TEST_C", "TV_TEST_A"], args[0], args[1].upper(), args[2])
assert calls == [2], "duplicate name opened twice"
PY
); has_text "$out" "2 key(s) sealed to $HB" && ! has_text "$out" "$VAL_S"; ok $? "send dedupes names, prints names + count only"
SH1=$(bh "$T/s1")
has_text "$out" "bundle hash $SH1" && has_text "$out" "On the other Mac run: touchvault receive s1 --expect $SH1"; ok $? "send prints the sha256 of the exact bytes written + the receive line"
[ "$(stat -f %Lp "$T/s1")" = 600 ] && [ "$(sed -n 2p "$T/s1")" = "from $H" ] && [ "$(sed -n 3p "$T/s1")" = "to $HB" ] && [ "$(sed -n 4p "$T/s1")" = "count 2" ] && ! grep -qF "$VAL_S" "$T/s1"
ok $? "bundle: mode 0600, from/to/count header, no plaintext"
out=$(mod "$T/B.pub" "$HB" "$T/s1" <<'PY'
tv._open = lambda envs, why: ["x"] * len(envs)
tv.send(["TV_TEST_A"], args[0], args[1], args[2])
PY
); [ -n "$out" ] && has_text "$out" "already exists"; ok $? "send never overwrites an existing bundle file"
# forgery: someone with B's public key copies the real `from` line and seals their own values; the hash catches it
{ sed -n 1,3p "$T/s1"; printf 'count 2\nTV_TEST_A %s\nTV_TEST_C %s\n' "$(sealB TV_TEST_forged_1)" "$(sealB TV_TEST_forged_2)"; } > "$T/forged"
[ "$(sed -n 2p "$T/forged")" = "from $H" ]; ok $? "forged bundle carries the real sender's from line"
out=$(tvb receive "$T/forged" --expect "$SH1"); [ $? != 0 ] && has_text "$out" "refusing" && ! tvb has TV_TEST_A >/dev/null && ! tvb has TV_TEST_C >/dev/null; ok $? "forged bundle with a copied from line refused (hash differs), nothing stored"
out=$(tvb receive "$T/s1" --expect "$SH1"); [ $? = 0 ] && has_text "$out" "2 stored"; ok $? "receive takes a bundle made by send, with send's printed hash"
out=$(envB "$T/s1" <<'PY'
import base64
lines = open(args[0]).read().split("\n")[4:-1]
for ln in lines:
    n, e = ln.split(" ")
    assert tv._stored(n) == e and len(base64.b64decode(e[4:])) == 93 + 23, n
print("sent ok")
PY
); [ "$out" = "sent ok" ]; ok $? "envelopes from send stored exactly, sized for the sent value"

! grep -qF -e "$VAL_A" -e "$VAL_B" -e "$VAL_C" -e "$VAL_L" -e "$VAL_X" -e "$VAL_Y" -e "$VAL_S" -e "$(printf %s "$VAL_A" | xxd -p | tr -d '\n')" "$LOG"; ok $? "no value (or its hex) ever printed"

echo "$pass passed, $fail failed"
cat <<EOF

MANUAL Touch ID tests (need a person at the Mac; uses a throwaway key and the selftest service):
  export TOUCHVAULT_SERVICE=touchvault-selftest TOUCHVAULT_KEYDIR=/tmp/tv_manual_key
  $TV init
  printf 'TV_TEST_M=TV_TEST_manual_value\nTV_TEST_N=TV_TEST_other_value\n' > /tmp/tv_m.env
  $TV import TV_TEST_M --from /tmp/tv_m.env; $TV import TV_TEST_N --from /tmp/tv_m.env   (no prompt: sealing needs no touch)
  1. Approve: $TV verify TV_TEST_M --from /tmp/tv_m.env
       prompt starts "touchvault:"; touch once -> prints "TV_TEST_M: match"
  2. Run, named key only: $TV run TV_TEST_M -- sh -c 'test "\$TV_TEST_M" = TV_TEST_manual_value && test -z "\${TV_TEST_N-}" && echo ONLY_M'
       the prompt names TV_TEST_M (not TV_TEST_N) and the command; touch once -> prints "ONLY_M"
  3. Cancel:  $TV verify TV_TEST_M --from /tmp/tv_m.env
       press Cancel -> prints "LOCKED: Touch ID not approved; no key released", exit 1
  4. Tamper:  python3 -c 'import base64,sys; r=bytearray(base64.b64decode(sys.argv[1][4:])); r[-1]^=1; print("tv1:"+base64.b64encode(r).decode())' "\$(echo -n x | "$SEVAULT" seal)" | "$SEVAULT" open tamper-test
       touch once -> "a value did not open (tampered, or sealed to another key)", exit 1, nothing on stdout
  5. Other key dir: TOUCHVAULT_KEYDIR=/tmp/tv_other_key $TV init; TOUCHVAULT_KEYDIR=/tmp/tv_other_key $TV verify TV_TEST_M --from /tmp/tv_m.env
       touch once -> LOCKED ... did not open (the blob is what holds the key; a copy on another Mac fails the same way)
  6. Copy:    $TV copy TV_TEST_M --seconds 10
       touch once, paste somewhere within 10 s; after 10 s the clipboard is empty
  7. Lid closed / no Touch ID keyboard: with the lid closed on an external display, $TV verify TV_TEST_M --from /tmp/tv_m.env
       prints LOCKED (Touch ID not available) and exits 1 right away, no hang
  8. Mac to Mac (two key dirs on one Mac stand in for two Macs; B uses its own service):
       TOUCHVAULT_KEYDIR=/tmp/tv_recv_key TOUCHVAULT_SERVICE=touchvault-selftest-b $TV init
       TOUCHVAULT_KEYDIR=/tmp/tv_recv_key TOUCHVAULT_SERVICE=touchvault-selftest-b $TV pubkey --out /tmp/tv_recv.pub
       note the pubhash it printed, then send from A with it:
       $TV send TV_TEST_M,TV_TEST_N --to /tmp/tv_recv.pub --expect <that pubhash> -o /tmp/tv_bundle
       touch once -> names + "2 key(s) sealed to ..." + "bundle hash <H>"; ls -l /tmp/tv_bundle shows -rw-------
       TOUCHVAULT_KEYDIR=/tmp/tv_recv_key TOUCHVAULT_SERVICE=touchvault-selftest-b $TV receive /tmp/tv_bundle --expect <H> --verify
       no prompt until --verify; prints "from <A's pubhash>" (same as $TV status), "2 stored", touch once -> "verified: all 2 open"
       TOUCHVAULT_KEYDIR=/tmp/tv_recv_key TOUCHVAULT_SERVICE=touchvault-selftest-b $TV verify TV_TEST_M --from /tmp/tv_m.env
       touch once -> "TV_TEST_M: match"
       TOUCHVAULT_KEYDIR=/tmp/tv_recv_key TOUCHVAULT_SERVICE=touchvault-selftest-b $TV run TV_TEST_N -- sh -c 'test "\$TV_TEST_N" = TV_TEST_other_value && echo N_MOVED'
       touch once -> "N_MOVED"
       and the other way: $TV receive /tmp/tv_bundle --expect <H>  (A's own key) -> "refusing bundle: it was made for key ..."
  Clean up:   $TV delete TV_TEST_M; $TV delete TV_TEST_N; rm -rf /tmp/tv_m.env /tmp/tv_manual_key /tmp/tv_other_key
              for n in TV_TEST_M TV_TEST_N; do TOUCHVAULT_SERVICE=touchvault-selftest-b $TV delete \$n; done
              rm -rf /tmp/tv_recv_key /tmp/tv_recv.pub /tmp/tv_bundle
              for d in tv_manual_key tv_other_key tv_recv_key; do security delete-generic-password -s touchvault-pin -a /private/tmp/\$d; done
EOF
[ "$fail" = 0 ]
