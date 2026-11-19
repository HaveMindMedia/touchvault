// sevault: values sealed to a Secure Enclave key that only this Mac's chip holds; init makes it fingerprint-gated (biometryAny).
//   sevault init [--force]      create the key (~/.config/touchvault/se_key.blob + se_key.pub, or $TOUCHVAULT_KEYDIR); no overwrite
//   sevault seal                plaintext on stdin -> one "tv1:" line on stdout (no Touch ID)
//   sevault seal --to PUBFILE   same, sealed to ANOTHER Mac's public key ("touchvault-pubkey v1" file; its pubhash line
//   sevault seal --pub-b64 B64    must match the key), or to a base64 x963 key. Only that Mac can open the result.
//   sevault open "reason"       tv1 lines on stdin (at least one) -> ONE Touch ID -> plaintexts, same order, one per line
//   sevault check               tv1 lines on stdin -> validates format and points, no Touch ID, prints the count
//   sevault pubhash             sha256 of the public key (the CLI pins it at init; no Touch ID)
//   sevault pub                 the public key, base64 x963 (safe to share; no Touch ID)
// Envelope: "tv1:" + base64(ephemeralPub(65) || nonce(12) || ciphertext || tag(16))
//   key = HKDF-SHA256(ECDH(ephemeral, sePub), salt "touchvault-v1", info ephemeralPub || sePub, 32 bytes), AES-GCM.
// Any failure: exit 1, a short reason on stderr, nothing on stdout.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

func fail(_ why: String) -> Never { FileHandle.standardError.write("sevault: \(why)\n".data(using: .utf8)!); exit(1) }

let env = ProcessInfo.processInfo.environment
// TOUCHVAULT_KEYDIR exists for the self-test. A swapped key is caught by the CLI's pubhash pin, not here (see README)
let dir = env["TOUCHVAULT_KEYDIR"].map { URL(fileURLWithPath: $0) }
    ?? URL(fileURLWithPath: env["HOME"] ?? NSHomeDirectory()).appendingPathComponent(".config/touchvault")
let blobURL = dir.appendingPathComponent("se_key.blob"), pubURL = dir.appendingPathComponent("se_key.pub")
let salt = "touchvault-v1".data(using: .utf8)!

func readStdin() -> Data { FileHandle.standardInput.readDataToEndOfFile() }

func loadKey(_ ctx: LAContext? = nil) -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    guard let blob = try? Data(contentsOf: blobURL) else { fail("no Secure Enclave key; run: touchvault init") }
    let k = ctx == nil ? try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)
                       : try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: ctx!)
    guard let key = k else { fail("key file is not usable on this Mac's Secure Enclave") }
    return key
}

func symKey(_ shared: SharedSecret, _ eph: Data, _ se: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: eph + se, outputByteCount: 32)
}

func hex(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

func point(_ raw: Data) -> P256.KeyAgreement.PublicKey {
    guard raw.count == 65, let k = try? P256.KeyAgreement.PublicKey(x963Representation: raw) else { fail("not a valid P-256 public key") }
    return k
}

// another Mac's key: no pin applies, so the file must at least agree with itself and hold a real curve point
func foreignPub(_ path: String) -> P256.KeyAgreement.PublicKey {
    guard let t = try? String(contentsOfFile: path, encoding: .utf8) else { fail("cannot read \(path)") }
    let l = t.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    guard l.count >= 3, l[0] == "touchvault-pubkey v1", l[1].hasPrefix("pubhash "), l[2].hasPrefix("pub "),
          let raw = Data(base64Encoded: String(l[2].dropFirst(4))) else { fail("not a touchvault-pubkey v1 file") }
    guard hex(raw) == l[1].dropFirst(8).lowercased() else { fail("the pubhash line does not match the key in \(path)") }
    return point(raw)
}

// "tv1:" lines -> parsed parts; any bad line fails before anything else happens
func parseEnvelopes(_ data: Data) -> [(Data, P256.KeyAgreement.PublicKey, AES.GCM.SealedBox)] {
    guard let text = String(data: data, encoding: .utf8) else { fail("input is not text") }
    let lines = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    if lines.isEmpty { fail("no envelopes") }
    return lines.map { l in
        guard l.hasPrefix("tv1:"), let raw = Data(base64Encoded: String(l.dropFirst(4))), raw.count > 65 + 12 + 16,
              let ephPub = try? P256.KeyAgreement.PublicKey(x963Representation: raw.prefix(65)),
              let box = try? AES.GCM.SealedBox(combined: raw.dropFirst(65))
        else { fail("not a tv1 envelope") }
        return (Data(raw.prefix(65)), ephPub, box)
    }
}

func opt(_ flag: String) -> String? {
    guard let i = CommandLine.arguments.firstIndex(of: flag) else { return nil }
    guard i + 1 < CommandLine.arguments.count else { fail("\(flag) needs a value") }
    return CommandLine.arguments[i + 1]
}

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "init":
    if FileManager.default.fileExists(atPath: blobURL.path) && !args.contains("--force") {
        fail("a key already exists at \(blobURL.path). A new key makes every sealed value unreadable. Use --force only if you mean that.")
    }
    guard SecureEnclave.isAvailable else { fail("this Mac has no Secure Enclave") }
    var err: Unmanaged<CFError>?
    // biometryAny: enrolling another finger does not destroy the key (biometryCurrentSet would)
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                   [.privateKeyUsage, .biometryAny], &err) else { fail("access control refused") }
    guard let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac) else { fail("Secure Enclave refused to make a key") }
    do {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        for (url, data) in [(blobURL, key.dataRepresentation), (pubURL, key.publicKey.x963Representation)] {
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    } catch { fail("could not write the key files: \(error.localizedDescription)") }
    if args.contains("--force") { FileHandle.standardError.write("sevault: NEW key made. Values sealed to the old key can no longer be opened.\n".data(using: .utf8)!) }
    print("Secure Enclave key ready: \(blobURL.path)")

case "seal":
    let to: P256.KeyAgreement.PublicKey
    if let f = opt("--to") { to = foreignPub(f) }
    else if let b = opt("--pub-b64") { to = point(Data(base64Encoded: b) ?? Data()) }
    else {
        let key = loadKey()
        to = key.publicKey
        if let pinned = try? Data(contentsOf: pubURL), pinned != to.x963Representation { fail("se_key.pub does not match se_key.blob; refusing to seal") }
        // Refuse a key that works with no user interaction at all (e.g. a swapped-in key with no access control).
        // This does NOT prove the key needs a fingerprint: a key gated by an app password also fails this probe.
        let probe = LAContext(); probe.interactionNotAllowed = true
        if (try? loadKey(probe).sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PrivateKey().publicKey)) != nil {
            fail("the key file opens without a fingerprint; refusing to seal to it")
        }
    }
    let sePub = to.x963Representation
    var plain = readStdin()
    if plain.last == 0x0a { plain.removeLast() }
    if plain.isEmpty { fail("empty value") }
    let eph = P256.KeyAgreement.PrivateKey()
    let ephPub = eph.publicKey.x963Representation
    guard let shared = try? eph.sharedSecretFromKeyAgreement(with: to),
          let box = try? AES.GCM.seal(plain, using: symKey(shared, ephPub, sePub)),
          let combined = box.combined else { fail("seal failed") }
    print("tv1:" + (ephPub + combined).base64EncodedString())

case "open":
    let why = args.dropFirst().joined(separator: " ")
    let reason = "touchvault: " + (why.isEmpty ? "use a saved key" : why)
    let parts = parseEnvelopes(readStdin())   // validate everything before asking for a fingerprint
    let ctx = LAContext()
    ctx.localizedFallbackTitle = ""                       // fingerprint or nothing, no password
    ctx.touchIDAuthenticationAllowableReuseDuration = 0   // never reuse an earlier unlock
    var err: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else { fail("Touch ID not available") }
    let done = DispatchSemaphore(value: 0)
    var ok = false
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { s, _ in ok = s; done.signal() }
    done.wait()
    guard ok else { fail("Touch ID not approved") }
    let key = loadKey(ctx)
    let sePub = key.publicKey.x963Representation
    var out: [String] = []
    for (ephRaw, ephPub, box) in parts {
        guard let shared = try? key.sharedSecretFromKeyAgreement(with: ephPub),
              let plain = try? AES.GCM.open(box, using: symKey(shared, ephRaw, sePub)),
              let s = String(data: plain, encoding: .utf8) else { fail("a value did not open (tampered, or sealed to another key)") }
        out.append(s)
    }
    print(out.joined(separator: "\n"))

case "check":
    print(parseEnvelopes(readStdin()).count)

case "pubhash":
    print(hex(loadKey().publicKey.x963Representation))

case "pub":
    print(loadKey().publicKey.x963Representation.base64EncodedString())

default:
    fail("usage: sevault init [--force] | seal [--to PUBFILE | --pub-b64 B64] | open \"reason\" | check | pubhash | pub")
}
