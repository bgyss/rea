import AppKit

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let window = NSWindow(contentRect: NSRect(x: 120, y: 120, width: 360, height: 320), styleMask: [.titled, .closable], backing: .buffered, defer: false)
window.title = "REA source-owned UI verification"
final class FixtureController: NSObject {
  @objc func increment(_ sender: NSButton) { sender.title = "REA fixture incremented" }
  var pointerClicks = 0
  @objc func counted(_ sender: NSButton) {
    pointerClicks += 1
    sender.title = "Pointer clicks: \(pointerClicks)"
  }
  @objc func later(_ sender: NSButton) {
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { sender.title = "REA fixture finished later" }
  }
}

/// Focusable view that reports pointer and key events through its accessibility
/// value, as a drawing canvas reads event locations rather than AX actions.
final class Canvas: NSView {
  private var log: [String] = []
  override var isFlipped: Bool { true }
  override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
  private func record(_ name: String, _ event: NSEvent) {
    let point = convert(event.locationInWindow, from: nil)
    let modifiers = event.modifierFlags.contains(.shift) ? "+shift" : ""
    log.append("\(name)\(modifiers)@\(Int(point.x.rounded())),\(Int(point.y.rounded()))x\(event.clickCount)")
    setAccessibilityValue(log.suffix(6).joined(separator: " "))
  }
  override func mouseDown(with event: NSEvent) {
    window?.makeFirstResponder(self)
    record("down", event)
  }
  override func mouseDragged(with event: NSEvent) {
    if log.last?.hasPrefix("drag") != true { record("drag", event) }
  }
  override func mouseUp(with event: NSEvent) { record("up", event) }
  override func rightMouseDown(with event: NSEvent) { record("right", event) }
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
let counter = NSButton(frame: NSRect(x: 240, y: 110, width: 110, height: 30))
counter.title = "Pointer clicks: 0"
counter.target = controller
counter.action = #selector(FixtureController.counted(_:))
counter.setAccessibilityIdentifier("rea-counter")
window.contentView?.addSubview(counter)
let canvas = Canvas(frame: NSRect(x: 30, y: 190, width: 280, height: 110))
canvas.setAccessibilityElement(true)
canvas.setAccessibilityRole(.group)
canvas.setAccessibilityIdentifier("rea-canvas")
canvas.setAccessibilityValue("")
window.contentView?.addSubview(canvas)
window.orderFront(nil)
window.makeFirstResponder(canvas)
// Floating window over the canvas's right edge: it stays above the raised
// main window, so pointer targets beneath it must be refused as occluded.
let canvasOnScreen = window.convertToScreen(canvas.convert(canvas.bounds, to: nil))
let cover = NSWindow(
  contentRect: NSRect(x: canvasOnScreen.maxX - 60, y: canvasOnScreen.minY, width: 60, height: canvasOnScreen.height),
  styleMask: [.borderless], backing: .buffered, defer: false)
cover.level = .floating
cover.backgroundColor = .systemOrange
cover.isOpaque = true
cover.title = "REA cover"
cover.orderFront(nil)
DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
  let record = "{\"pid\":\(ProcessInfo.processInfo.processIdentifier),\"window_id\":\(window.windowNumber)}\n"
  FileHandle.standardOutput.write(Data(record.utf8))
}
app.run()
