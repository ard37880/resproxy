import AppKit

// The app sits next to resproxy.py, so find the script relative to the bundle.
let script = Bundle.main.bundleURL.deletingLastPathComponent()
    .appendingPathComponent("resproxy.py").path

struct Output {
    let status: Int32
    let out: String
    let err: String

    // The line to show: the last line of normal output, or of the error on failure.
    var message: String {
        let text = status == 0 ? out : (err.isEmpty ? out : err)
        return text.components(separatedBy: "\n").last ?? text
    }
}

final class Buffer {
    var data = Data()
}

let missingScript = "Can't find resproxy.py. Keep ResProxy.app in the resproxy folder."

// Blocks until the script exits, so only call this off the main thread.
func run(_ arg: String) -> Output {
    // The app was moved away from the script (into Applications, say).
    if !FileManager.default.fileExists(atPath: script) {
        return Output(status: -1, out: "", err: missingScript)
    }
    let p = Process()
    // Apps launched from Finder get a bare PATH, so add the usual python3 locations.
    p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    p.arguments = ["python3", script, arg]
    var env = ProcessInfo.processInfo.environment
    env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    p.environment = env
    // Separate pipes, so a warning on stderr can't garble the state on stdout.
    let out = Pipe()
    let err = Pipe()
    p.standardOutput = out
    p.standardError = err
    do {
        try p.run()
    } catch {
        return Output(status: -1, out: "", err: "Could not run python3: \(error.localizedDescription)")
    }
    // Read both pipes before waiting: a child with a lot of output would block on a full pipe.
    let errBuffer = Buffer()
    let group = DispatchGroup()
    group.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        errBuffer.data = err.fileHandleForReading.readDataToEndOfFile()
        group.leave()
    }
    let outData = out.fileHandleForReading.readDataToEndOfFile()
    group.wait()
    p.waitUntilExit()
    let text = { (d: Data) in
        String(data: d, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }
    return Output(status: p.terminationStatus, out: text(outData), err: text(errBuffer.data))
}

func runInBackground(_ arg: String, then done: @escaping (Output) -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let result = run(arg)
        DispatchQueue.main.async { done(result) }
    }
}

class App: NSObject, NSApplicationDelegate, NSMenuDelegate, NSMenuItemValidation {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let toggle = NSMenuItem(title: "Checking...", action: #selector(flip), keyEquivalent: "")
    let info = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    var busy = false
    // Only the newest refresh may update the menu; older ones finish late.
    var generation = 0

    func applicationDidFinishLaunching(_ n: Notification) {
        let menu = NSMenu()
        menu.delegate = self
        toggle.target = self
        menu.addItem(toggle)
        menu.addItem(info)
        menu.addItem(NSMenuItem.separator())
        let check = NSMenuItem(title: "Check exit IP", action: #selector(checkIP), keyEquivalent: "")
        check.target = self
        menu.addItem(check)
        menu.addItem(NSMenuItem(title: "Quit (leaves proxy as is)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        item.menu = menu
        item.button?.image = NSImage(systemSymbolName: "globe", accessibilityDescription: "Residential proxy")
        refresh()
    }

    func menuWillOpen(_ menu: NSMenu) {
        if !busy { refresh() }
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        return menuItem != toggle || !busy
    }

    func refresh(message: String? = nil) {
        generation += 1
        let mine = generation
        runInBackground("state") { result in
            guard mine == self.generation else { return }
            self.show(result, message: message)
        }
    }

    func show(_ result: Output, message: String?) {
        let state = result.status == 0 ? result.message : ""
        let on = state == "on"
        let broken = state == "broken"
        let partial = state == "partial"
        let unfinished = state == "unfinished"
        let unknown = state == "unknown"
        let symbol = on ? "globe.americas.fill" : broken ? "exclamationmark.triangle"
            : partial || unfinished ? "exclamationmark.circle" : unknown ? "questionmark.circle" : "globe"
        item.button?.image = NSImage(systemSymbolName: symbol, accessibilityDescription: "Residential proxy")
        // Same choice as toggle in resproxy.py: everything but off and partial turns it off.
        toggle.title = on || broken || unfinished || unknown ? "Turn Residential Proxy Off" : "Turn Residential Proxy On"
        if let message = message, !message.isEmpty {
            info.title = message
        } else if broken {
            info.title = "Status: BROKEN, forwarder not running"
        } else if partial {
            info.title = "Status: PARTIAL, this network isn't switched"
        } else if unfinished {
            info.title = "Status: UNFINISHED, off didn't finish"
        } else if unknown {
            info.title = "Status: UNKNOWN, can't read the proxy settings"
        } else if state == "off" {
            info.title = "Status: OFF"
        } else if on {
            info.title = "Status: ON"
        } else {
            info.title = result.message
        }
    }

    @objc func flip() {
        busy = true
        generation += 1
        info.title = "Working..."
        runInBackground("toggle") { result in
            self.busy = false
            self.refresh(message: result.message)
        }
    }

    @objc func checkIP() {
        runInBackground("status") { result in
            let alert = NSAlert()
            alert.messageText = "Residential proxy"
            alert.informativeText = [result.out, result.err].filter { !$0.isEmpty }.joined(separator: "\n")
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
