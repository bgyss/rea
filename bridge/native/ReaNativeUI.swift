import AppKit
import ApplicationServices
import CryptoKit
import ScreenCaptureKit
import Darwin

struct Request: Decodable {
  var pid: Int32
  var window_id: UInt32
  var executable: String
  var sha256: String
  var launch_time: Double?
  var screenshot: Bool
  var accessibility: Bool
  var max_nodes: Int
  var action: Action?
}
struct Expectation: Decodable { var role: String?; var subrole: String?; var identifier: String?; var title: String? }
struct Point: Decodable { var x: Double; var y: Double }
struct PointSpec: Decodable { var path: [Int]?; var expect: Expectation?; var offset: Point?; var window_point: Point? }
struct KeySpec: Decodable { var key: String; var modifiers: [String]?; var hold_ms: Int? }
struct Action: Decodable {
  var kind: String; var path: [Int]?; var direction: String?; var text: String?; var expect: Expectation?
  var gesture: String?; var at: PointSpec?; var to: PointSpec?; var modifiers: [String]?; var duration_ms: Int?; var keys: [KeySpec]?
}
struct BoundaryFailure: Error { var code: String; var message: String }
func fail(_ code: String, _ message: String) throws -> Never { throw BoundaryFailure(code: code, message: message) }
func attribute(_ element: AXUIElement, _ key: String) -> CFTypeRef? {
  var value: CFTypeRef?
  return AXUIElementCopyAttributeValue(element, key as CFString, &value) == .success ? value : nil
}
func childCount(_ element: AXUIElement) -> ChildCount {
  var count = 0
  let status = AXUIElementGetAttributeValueCount(element, kAXChildrenAttribute as CFString, &count)
  return captureChildCount(status: status.rawValue, success: AXError.success.rawValue, value: count)
}
func children(_ element: AXUIElement, count: Int) -> ChildBatch<AXUIElement> {
  captureChildValues(requestedCount: count) {
    var value: CFArray?
    guard AXUIElementCopyAttributeValues(element, kAXChildrenAttribute as CFString, 0, count, &value) == .success else { return nil }
    return value as? [AXUIElement]
  }
}
func string(_ element: AXUIElement, _ key: String) -> String? { attribute(element, key) as? String }
func text(_ element: AXUIElement, _ key: String) -> Any { string(element, key) ?? NSNull() as Any }
func flag(_ element: AXUIElement, _ key: String) -> Any {
  guard let value = attribute(element, key), CFGetTypeID(value) == CFBooleanGetTypeID() else { return NSNull() }
  return CFBooleanGetValue((value as! CFBoolean))
}
func relativeFrame(_ element: AXUIElement, in window: CGRect) -> Any {
  guard let frame = windowBounds(element) else { return NSNull() }
  return ["x": frame.origin.x - window.origin.x, "y": frame.origin.y - window.origin.y, "width": max(0, frame.width), "height": max(0, frame.height)]
}
func windowBounds(_ element: AXUIElement) -> CGRect? {
  guard let p = attribute(element, kAXPositionAttribute), let s = attribute(element, kAXSizeAttribute),
    CFGetTypeID(p) == AXValueGetTypeID(), CFGetTypeID(s) == AXValueGetTypeID() else { return nil }
  var point = CGPoint.zero; var size = CGSize.zero
  guard AXValueGetValue(p as! AXValue, .cgPoint, &point), AXValueGetValue(s as! AXValue, .cgSize, &size) else { return nil }
  return CGRect(origin: point, size: size)
}
func element(at path: [Int], from root: AXUIElement, pid: Int32) throws -> AXUIElement {
  var element = root
  for index in path {
    var selectedChild: CFArray?
    let count = childCount(element)
    guard let available = count.value else {
      try fail("element-count-unavailable", "Cannot validate selected accessibility path because child count failed with AXError \(count.error ?? -1)")
    }
    guard index >= 0 && index < available,
      AXUIElementCopyAttributeValues(element, kAXChildrenAttribute as CFString, index, 1, &selectedChild) == .success,
      let item = (selectedChild as? [AXUIElement])?.first else { try fail("element-missing", "Selected accessibility path no longer exists") }
    element = item
  }
  var owner: pid_t = 0
  guard AXUIElementGetPid(element, &owner) == .success && owner == pid else { try fail("element-owner-mismatch", "Selected element belongs to another process") }
  return element
}
func verify(_ element: AXUIElement, _ expected: Expectation?) throws {
  guard let expected else { return }
  let observed = Expectation(role: string(element, kAXRoleAttribute), subrole: string(element, kAXSubroleAttribute), identifier: string(element, kAXIdentifierAttribute), title: string(element, kAXTitleAttribute))
  guard observed.role == expected.role && observed.subrole == expected.subrole && observed.identifier == expected.identifier && observed.title == expected.title else {
    try fail("element-changed", "The element at the selected path changed since the preceding capture; expected role \(expected.role ?? "nil") identifier \(expected.identifier ?? "nil") title \(expected.title ?? "nil"), found role \(observed.role ?? "nil") identifier \(observed.identifier ?? "nil") title \(observed.title ?? "nil")")
  }
}


/// Screen point for a pointer target, from the element's live frame or a window-relative point.
func screenPoint(_ spec: PointSpec, root: AXUIElement, pid: Int32, window: CGRect) throws -> CGPoint {
  let point: CGPoint
  if let relative = spec.window_point {
    point = CGPoint(x: window.origin.x + relative.x, y: window.origin.y + relative.y)
  } else {
    let target = try element(at: spec.path ?? [], from: root, pid: pid)
    try verify(target, spec.expect)
    guard let frame = windowBounds(target) else { try fail("element-frame-unavailable", "The selected element does not expose a frame for pointer targeting") }
    let offset = spec.offset ?? Point(x: frame.width / 2, y: frame.height / 2)
    point = CGPoint(x: frame.origin.x + offset.x, y: frame.origin.y + offset.y)
  }
  guard window.contains(point) else {
    try fail("point-outside-window", "Pointer location \(point) lies outside the selected window \(window); events are only posted inside it")
  }
  return point
}

/// The element that would receive input at the point (a system-wide AX hit test)
/// must belong to the selected window; otherwise a system-wide event would reach
/// whatever covers it (another app, the menu bar, the Dock, another window).
func requireTopmost(_ point: CGPoint, pid: Int32, window: CGRect) throws {
  var hit: AXUIElement?
  guard AXUIElementCopyElementAtPosition(AXUIElementCreateSystemWide(), Float(point.x), Float(point.y), &hit) == .success,
    let element = hit else {
    try fail("point-unverifiable", "No accessibility element answers a hit test at \(point); no system-wide event was posted")
  }
  var owner: pid_t = 0
  guard AXUIElementGetPid(element, &owner) == .success else {
    try fail("point-unverifiable", "The element at \(point) has no owning process; no system-wide event was posted")
  }
  guard owner == pid else {
    let name = NSRunningApplication(processIdentifier: owner)?.localizedName ?? "process \(owner)"
    try fail("point-occluded", "Pointer location \(point) is covered by \(name); no system-wide event was posted")
  }
  let role = string(element, kAXRoleAttribute)
  let windowValue = attribute(element, kAXWindowAttribute)
  let hitWindow: AXUIElement? = role == (kAXWindowRole as String)
    ? element
    : windowValue.flatMap { CFGetTypeID($0) == AXUIElementGetTypeID() ? ($0 as! AXUIElement) : nil }
  guard let hitWindow, windowBounds(hitWindow) == window else {
    try fail("point-occluded", "Pointer location \(point) is covered by another window of the target application; no system-wide event was posted")
  }
}

func modifierFlags(_ names: [String]?) -> CGEventFlags {
  var flags: CGEventFlags = []
  for name in names ?? [] {
    switch name {
    case "command": flags.insert(.maskCommand)
    case "shift": flags.insert(.maskShift)
    case "option": flags.insert(.maskAlternate)
    case "control": flags.insert(.maskControl)
    default: break
    }
  }
  return flags
}

/// System-wide pointer gesture: raise the selected window, verify it is topmost at
/// every point before posting anything, post HID-level events, then restore the cursor.
func pointer(_ action: Action, pid: Int32, windowID: UInt32, window: CGRect, root: AXUIElement, app: NSRunningApplication) throws {
  guard let at = action.at else { try fail("invalid-action", "pointer requires an at target") }
  AXUIElementPerformAction(root, kAXRaiseAction as CFString)
  app.activate()
  usleep(250_000)
  let start = try screenPoint(at, root: root, pid: pid, window: window)
  var path: [CGPoint] = [start]
  if action.gesture == "drag" {
    guard let to = action.to else { try fail("invalid-action", "drag requires a to target") }
    let end = try screenPoint(to, root: root, pid: pid, window: window)
    let steps = 12
    path = (0...steps).map { step in
      let fraction = Double(step) / Double(steps)
      return CGPoint(x: start.x + (end.x - start.x) * fraction, y: start.y + (end.y - start.y) * fraction)
    }
  }
  for point in path { try requireTopmost(point, pid: pid, window: window) }
  let original = CGEvent(source: nil)?.location
  defer { if let original { CGWarpMouseCursorPosition(original) } }
  let flags = modifierFlags(action.modifiers)
  let source = CGEventSource(stateID: .hidSystemState)
  func post(_ type: CGEventType, _ point: CGPoint, button: CGMouseButton = .left, clicks: Int64 = 1) throws {
    guard let event = CGEvent(mouseEventSource: source, mouseType: type, mouseCursorPosition: point, mouseButton: button) else {
      try fail("event-unavailable", "Cannot create a \(type.rawValue) mouse event")
    }
    event.flags = flags
    event.setIntegerValueField(.mouseEventClickState, value: clicks)
    event.post(tap: .cghidEventTap)
    usleep(30_000)
  }
  try post(.mouseMoved, start)
  switch action.gesture {
  case "click":
    try post(.leftMouseDown, start); try post(.leftMouseUp, start)
  case "double_click":
    try post(.leftMouseDown, start); try post(.leftMouseUp, start)
    try post(.leftMouseDown, start, clicks: 2); try post(.leftMouseUp, start, clicks: 2)
  case "right_click":
    try post(.rightMouseDown, start, button: .right); try post(.rightMouseUp, start, button: .right)
  case "drag":
    let pause = useconds_t(max(0, action.duration_ms ?? 200) * 1000 / max(1, path.count - 1))
    try post(.leftMouseDown, start)
    for point in path.dropFirst() {
      try post(.leftMouseDragged, point)
      usleep(pause)
    }
    try post(.leftMouseUp, path[path.count - 1])
  default:
    try fail("unsupported-action", "Unsupported pointer gesture \(action.gesture ?? "nil")")
  }
}

/// US ANSI virtual key codes; produced characters depend on the active keyboard layout.
let virtualKeys: [String: CGKeyCode] = [
  "a": 0x00, "s": 0x01, "d": 0x02, "f": 0x03, "h": 0x04, "g": 0x05, "z": 0x06, "x": 0x07, "c": 0x08, "v": 0x09,
  "b": 0x0B, "q": 0x0C, "w": 0x0D, "e": 0x0E, "r": 0x0F, "y": 0x10, "t": 0x11, "1": 0x12, "2": 0x13, "3": 0x14,
  "4": 0x15, "6": 0x16, "5": 0x17, "equal": 0x18, "9": 0x19, "7": 0x1A, "minus": 0x1B, "8": 0x1C, "0": 0x1D,
  "o": 0x1F, "u": 0x20, "i": 0x22, "p": 0x23, "return": 0x24, "l": 0x25, "j": 0x26, "k": 0x28, "comma": 0x2B,
  "slash": 0x2C, "n": 0x2D, "m": 0x2E, "period": 0x2F, "tab": 0x30, "space": 0x31, "delete": 0x33, "escape": 0x35,
  "f5": 0x60, "f6": 0x61, "f7": 0x62, "f3": 0x63, "f8": 0x64, "f9": 0x65, "f11": 0x67, "f10": 0x6D, "f12": 0x6F,
  "home": 0x73, "page_up": 0x74, "forward_delete": 0x75, "f4": 0x76, "end": 0x77, "f2": 0x78, "page_down": 0x79,
  "f1": 0x7A, "left": 0x7B, "right": 0x7C, "down": 0x7D, "up": 0x7E,
]

/// Post key chords to the selected process's focused element.
func keys(_ chords: [KeySpec], pid: Int32) throws {
  let source = CGEventSource(stateID: .privateState)
  for chord in chords {
    guard let code = virtualKeys[chord.key] else { try fail("unsupported-key", "Unsupported key \(chord.key)") }
    let flags = modifierFlags(chord.modifiers)
    for down in [true, false] {
      guard let event = CGEvent(keyboardEventSource: source, virtualKey: code, keyDown: down) else {
        try fail("event-unavailable", "Cannot create a key event for \(chord.key)")
      }
      event.flags = flags
      event.postToPid(pid)
      usleep(down ? useconds_t(max(0, chord.hold_ms ?? 0) * 1000 + 20_000) : 20_000)
    }
  }
}
func observe(_ request: Request) async throws -> [String: Any] {
  guard let app = NSRunningApplication(processIdentifier: request.pid), let url = app.executableURL else {
    try fail("target-mismatch", "Selected PID does not expose an application executable URL")
  }
  guard let canonicalPointer = realpath(url.path, nil) else { try fail("target-mismatch", "Running executable path cannot be resolved") }
  defer { free(canonicalPointer) }
  let canonicalExecutable = String(cString: canonicalPointer)
  guard canonicalExecutable == request.executable else {
    try fail("target-mismatch", "Selected PID executable \(canonicalExecutable) differs from active target \(request.executable)")
  }
  guard let launch = app.launchDate?.timeIntervalSince1970 else {
    try fail("process-identity-unavailable", "Selected application does not expose a launch time; stable PID reuse checks are unavailable")
  }
  if let expected = request.launch_time, expected != launch { try fail("process-replaced", "Selected process was replaced") }
  let executableSize = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.int64Value ?? -1
  guard executableSize >= 0 && executableSize <= 256 * 1024 * 1024 else { try fail("target-limit", "Running executable exceeds the 256 MiB identity-check budget") }
  let executableBytes = try Data(contentsOf: url, options: .mappedIfSafe)
  guard SHA256.hash(data: executableBytes).map({ String(format: "%02x", $0) }).joined() == request.sha256 else {
    try fail("target-mismatch", "Running executable bytes differ from the active target digest")
  }
  guard let windows = CGWindowListCopyWindowInfo([.optionIncludingWindow], request.window_id) as? [[String: Any]],
    windows.count == 1, let window = windows.first,
    (window[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == request.pid,
    (window[kCGWindowLayer as String] as? NSNumber)?.intValue == 0,
    let boundsDictionary = window[kCGWindowBounds as String] as? [String: Any],
    let bounds = CGRect(dictionaryRepresentation: boundsDictionary as CFDictionary) else {
    try fail("window-mismatch", "Selected window is absent or belongs to another process")
  }
  if request.screenshot && !CGPreflightScreenCaptureAccess() {
    try fail("screen-recording-denied", "Grant Screen Recording to the REA host in System Settings > Privacy & Security, then retry; no broad capture fallback is used")
  }
  var selected: AXUIElement?
  if request.accessibility || request.action != nil {
    guard AXIsProcessTrusted() else { try fail("accessibility-denied", "Grant Accessibility to the REA host in System Settings > Privacy & Security, then retry") }
    let application = AXUIElementCreateApplication(request.pid)
    AXUIElementSetMessagingTimeout(application, 2)
    guard let axWindows = attribute(application, kAXWindowsAttribute) as? [AXUIElement] else {
      try fail("accessibility-unavailable", "Selected application does not expose accessibility windows")
    }
    let matches = axWindows.filter { windowBounds($0) == bounds }
    guard matches.count == 1 else { try fail("ambiguous-window", "Accessibility window geometry does not identify exactly one selected window; selected CG bounds \(bounds), AX candidates \(axWindows.map { String(describing: windowBounds($0)) })") }
    selected = matches[0]
  }
  if let action = request.action, let root = selected {
    switch action.kind {
    case "pointer": try pointer(action, pid: request.pid, windowID: request.window_id, window: bounds, root: root, app: app)
    case "keys": try keys(action.keys ?? [], pid: request.pid)
    default:
      let element = try element(at: action.path ?? [], from: root, pid: request.pid)
      try verify(element, action.expect)
      let outcome: AXError
      switch action.kind {
      case "click": outcome = AXUIElementPerformAction(element, kAXPressAction as CFString)
      case "scroll": outcome = AXUIElementPerformAction(element, (action.direction == "increment" ? kAXIncrementAction : kAXDecrementAction) as CFString)
      case "key-entry": outcome = AXUIElementSetAttributeValue(element, kAXValueAttribute as CFString, (action.text ?? "") as CFString)
      default: try fail("unsupported-action", "Only press, increment/decrement, text-value entry, pointer and keys actions are admitted")
      }
      guard outcome == .success else { try fail("action-failed", "Accessibility action failed with AXError \(outcome.rawValue)") }
    }
  }
  var nodes: [[String: Any]] = []; var truncated = false; var gaps: [String] = []
  if request.accessibility, let root = selected {
    var pending: [(AXUIElement, [Int])] = [(root, [])]
    while let (element, path) = pending.popLast() {
      if nodes.count >= request.max_nodes { truncated = true; break }
      let childCountResult = childCount(element)
      var actions: CFArray?
      AXUIElementCopyActionNames(element, &actions)
      nodes.append([
        "path": path,
        "role": text(element, kAXRoleAttribute),
        "subrole": text(element, kAXSubroleAttribute),
        "identifier": text(element, kAXIdentifierAttribute),
        "title": text(element, kAXTitleAttribute),
        "description": text(element, kAXDescriptionAttribute),
        "value": text(element, kAXValueAttribute),
        "enabled": flag(element, kAXEnabledAttribute),
        "focused": flag(element, kAXFocusedAttribute),
        "selected": flag(element, kAXSelectedAttribute),
        "bounds": relativeFrame(element, in: bounds),
        "actions": actions as? [String] ?? [],
        "children_count": childCountResult.value.map { $0 as Any } ?? NSNull(),
      ])
      guard let totalChildren = childCountResult.value else {
        truncated = true
        gaps.append("AX child count unavailable at path \(path): AXError \(childCountResult.error ?? -1)")
        continue
      }
      if path.count >= 32 { if totalChildren > 0 { truncated = true }; continue }
      let available = max(0, request.max_nodes - nodes.count - pending.count)
      let count = min(available, totalChildren)
      let batch = children(element, count: count)
      if !batch.complete { truncated = true }
      if totalChildren > count { truncated = true }
      for (index, item) in batch.values.enumerated().reversed() {
        pending.append((item, path + [index]))
      }
    }
  }
  var screenshot: Any = NSNull()
  if request.screenshot {
    guard #available(macOS 14, *) else { try fail("unsupported-host", "Selected-window screenshots require macOS 14 or later") }
    let content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: false)
    guard let scWindow = content.windows.first(where: { $0.windowID == request.window_id && $0.owningApplication?.processID == request.pid }) else {
      try fail("capture-window-missing", "Selected window disappeared before capture")
    }
    guard bounds.width > 0 && bounds.height > 0 && bounds.width <= 100000 && bounds.height <= 100000 else { try fail("window-bounds", "Selected window has invalid or oversized geometry") }
    let filter = SCContentFilter(desktopIndependentWindow: scWindow)
    let configuration = SCStreamConfiguration()
    let scale = min(1, 2048 / max(bounds.width, bounds.height))
    configuration.width = max(1, Int(bounds.width * scale)); configuration.height = max(1, Int(bounds.height * scale))
    configuration.showsCursor = false
    let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
    guard let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) else {
      try fail("capture-failed", "Selected-window PNG encoding failed")
    }
    screenshot = ["mime_type": "image/png", "base64": png.base64EncodedString(), "sha256": SHA256.hash(data: png).map({ String(format: "%02x", $0) }).joined(), "width": image.width, "height": image.height]
  }
  return ["window": ["pid": request.pid, "window_id": request.window_id, "executable": request.executable, "launch_time": launch, "title": window[kCGWindowName as String] as? String ?? ""], "nodes": nodes, "truncated": truncated, "screenshot": screenshot, "gaps": request.accessibility ? gaps : ["Accessibility capture was disabled"]]
}
Task { @MainActor in
  do {
    let request = try JSONDecoder().decode(Request.self, from: Data(CommandLine.arguments[1].utf8))
    let result = try await observe(request)
    let output = try serializeHelperOutput(["ok": true, "result": result])
    FileHandle.standardOutput.write(output)
  } catch {
    let failure = error as? BoundaryFailure
    let output: [String: Any] = ["ok": false, "code": failure?.code ?? "capture-failed", "message": failure?.message ?? error.localizedDescription]
    if let data = try? serializeHelperOutput(output) { FileHandle.standardOutput.write(data) }
  }
  exit(0)
}
RunLoop.main.run()
