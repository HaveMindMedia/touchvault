// concealed_copy SECONDS  (value on stdin)
// Puts the value on the clipboard for THIS Mac only (no Universal Clipboard sync), marked concealed + transient so
// clipboard managers skip it, then clears it after SECONDS unless something else was copied meanwhile.
import AppKit

let seconds = Double(CommandLine.arguments.dropFirst().first ?? "30") ?? 30
var data = FileHandle.standardInput.readDataToEndOfFile()
guard var value = String(data: data, encoding: .utf8) else { exit(1) }
if value.hasSuffix("\n") { value.removeLast() }

let pb = NSPasteboard.general
pb.prepareForNewContents(with: .currentHostOnly)          // never leaves this Mac
pb.setString(value, forType: .string)
data.resetBytes(in: 0..<data.count)                         // best effort: wipe our input buffer (the String copy and
                                                            // the pasteboard's own copy are out of our hands)
pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))   // nspasteboard.org convention
pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
let stamp = pb.changeCount

Thread.sleep(forTimeInterval: seconds)
if pb.changeCount == stamp { pb.clearContents() }          // only wipe if it is still our key on the clipboard
exit(0)
