import AppKit

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let window = NSWindow(contentRect: NSRect(x: 120, y: 120, width: 360, height: 320), styleMask: [.titled, .closable], backing: .buffered, defer: false)
window.title = "REA source-owned UI verification"
final class FixtureController: NSObject {
  @objc func increment(_ sender: NSButton) { sender.title = "REA fixture incremented" }
  @objc func later(_ sender: NSButton) {
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { sender.title = "REA fixture finished later" }
  }
}

/// Focusable view that reports received key events through its accessibility value.
final class Canvas: NSView {
  private var log: [String] = []
  override func keyDown(with event: NSEvent) {
    let command = event.modifierFlags.contains(.command) ? "cmd+" : ""
    log.append("key:\(command)\(event.charactersIgnoringModifiers ?? "")")
    setAccessibilityValue(log.suffix(6).joined(separator: " "))
  }
  override var acceptsFirstResponder: Bool { true }
}
let controller = FixtureController()
let button = NSButton(frame: NSRect(x: 30, y: 60, width: 280, height: 40))
button.title = "Increment REA fixture"
button.target = controller
button.action = #selector(FixtureController.increment(_:))
button.setAccessibilityIdentifier("rea-increment")
window.contentView?.addSubview(button)
let disabled = NSButton(frame: NSRect(x: 30, y: 110, width: 200, height: 30))
disabled.title = "Disabled REA fixture"
disabled.isEnabled = false
disabled.setAccessibilityIdentifier("rea-disabled")
window.contentView?.addSubview(disabled)
let field = NSTextField(frame: NSRect(x: 30, y: 20, width: 280, height: 24))
field.setAccessibilityIdentifier("rea-field")
window.contentView?.addSubview(field)
let later = NSButton(frame: NSRect(x: 30, y: 150, width: 280, height: 30))
later.title = "Finish REA fixture later"
later.target = controller
later.action = #selector(FixtureController.later(_:))
later.setAccessibilityIdentifier("rea-later")
window.contentView?.addSubview(later)
let canvas = Canvas(frame: NSRect(x: 30, y: 190, width: 280, height: 110))
canvas.setAccessibilityElement(true)
canvas.setAccessibilityRole(.group)
canvas.setAccessibilityIdentifier("rea-canvas")
canvas.setAccessibilityValue("")
window.contentView?.addSubview(canvas)
window.orderFront(nil)
window.makeFirstResponder(canvas)
DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
  let record = "{\"pid\":\(ProcessInfo.processInfo.processIdentifier),\"window_id\":\(window.windowNumber)}\n"
  FileHandle.standardOutput.write(Data(record.utf8))
}
app.run()
