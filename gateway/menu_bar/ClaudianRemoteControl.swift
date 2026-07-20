import AppKit
import Foundation

private let companionLabel = "com.claudian.remote.companion"
private let companionPlist = (NSHomeDirectory() as NSString)
    .appendingPathComponent("Library/LaunchAgents/com.claudian.remote.companion.plist")

@main
final class ClaudianRemoteControl: NSObject, NSApplicationDelegate {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let stateItem = NSMenuItem(title: "服务：检查中…", action: nil, keyEquivalent: "")
    private let autoStartItem = NSMenuItem(title: "开机自动启动", action: nil, keyEquivalent: "")
    private var refreshTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem.button?.image = NSImage(systemSymbolName: "bolt.horizontal.circle", accessibilityDescription: "Claudian Remote")
        statusItem.button?.imagePosition = .imageLeading
        statusItem.menu = menu

        stateItem.isEnabled = false
        menu.addItem(stateItem)
        menu.addItem(.separator())
        menu.addItem(actionItem("启动服务", #selector(startService)))
        menu.addItem(actionItem("重新连接", #selector(restartService)))
        menu.addItem(actionItem("停止服务（下次登录会自动启动）", #selector(stopService)))
        autoStartItem.target = self
        autoStartItem.action = #selector(toggleAutoStart)
        menu.addItem(autoStartItem)
        menu.addItem(.separator())
        menu.addItem(actionItem("查看运行日志", #selector(openLogs)))
        menu.addItem(.separator())
        menu.addItem(actionItem("退出控制栏", #selector(quit), keyEquivalent: "q"))

        refreshState()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            self?.refreshState()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        refreshTimer?.invalidate()
    }

    @objc private func startService() {
        runServiceAction { domain in
            _ = self.runLaunchctl(["enable", "\(domain)/\(companionLabel)"])
            _ = self.runLaunchctl(["bootout", "\(domain)/\(companionLabel)"])
            let bootstrap = self.runLaunchctl(["bootstrap", domain, companionPlist])
            guard bootstrap.status == 0 else { return bootstrap }
            return self.runLaunchctl(["kickstart", "-k", "\(domain)/\(companionLabel)"])
        }
    }

    @objc private func restartService() {
        runServiceAction { domain in
            let result = self.runLaunchctl(["kickstart", "-k", "\(domain)/\(companionLabel)"])
            if result.status == 0 { return result }
            _ = self.runLaunchctl(["enable", "\(domain)/\(companionLabel)"])
            return self.runLaunchctl(["bootstrap", domain, companionPlist])
        }
    }

    @objc private func stopService() {
        runServiceAction { domain in
            self.runLaunchctl(["bootout", "\(domain)/\(companionLabel)"])
        }
    }

    @objc private func toggleAutoStart() {
        runServiceAction { domain in
            if self.isAutoStartDisabled() {
                let enable = self.runLaunchctl(["enable", "\(domain)/\(companionLabel)"])
                guard enable.status == 0 else { return enable }
                return self.runLaunchctl(["bootstrap", domain, companionPlist])
            }
            _ = self.runLaunchctl(["bootout", "\(domain)/\(companionLabel)"])
            return self.runLaunchctl(["disable", "\(domain)/\(companionLabel)"])
        }
    }

    @objc private func openLogs() {
        let logs = [
            "/tmp/claudian-remote-companion-v2.out.log",
            "/tmp/claudian-remote-companion-v2.err.log",
        ]
        let workspace = NSWorkspace.shared
        for path in logs where FileManager.default.fileExists(atPath: path) {
            workspace.open(URL(fileURLWithPath: path))
        }
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    private func refreshState() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            let running = self.isServiceRunning()
            let autoStartDisabled = self.isAutoStartDisabled()
            DispatchQueue.main.async {
                self.stateItem.title = running ? "服务：运行中" : "服务：已停止"
                self.autoStartItem.title = autoStartDisabled ? "开启开机自动启动" : "关闭开机自动启动"
                self.statusItem.button?.title = running ? " Claudian" : " Claudian（停）"
            }
        }
    }

    private func userDomain() -> String {
        "gui/\(getuid())"
    }

    private func actionItem(_ title: String, _ action: Selector, keyEquivalent: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: keyEquivalent)
        item.target = self
        return item
    }

    private func runServiceAction(_ action: @escaping (String) -> (status: Int32, output: String)) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = action(self.userDomain())
            DispatchQueue.main.async {
                if result.status != 0 {
                    self.showFailure("Claudian Remote 服务操作失败", detail: result.output)
                }
                self.refreshState()
            }
        }
    }

    private func isServiceRunning() -> Bool {
        let result = runLaunchctl(["print", "\(userDomain())/\(companionLabel)"])
        return result.status == 0 && result.output.contains("state = running")
    }

    private func isAutoStartDisabled() -> Bool {
        let result = runLaunchctl(["print-disabled", userDomain()])
        return result.output.contains("\(companionLabel) => true")
    }

    private func runLaunchctl(_ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (process.terminationStatus, String(decoding: data, as: UTF8.self))
        } catch {
            return (1, error.localizedDescription)
        }
    }

    private func showFailure(_ message: String, detail: String) {
        let alert = NSAlert()
        alert.messageText = message
        alert.informativeText = detail.isEmpty ? "请查看运行日志。" : detail
        alert.alertStyle = .warning
        alert.runModal()
    }
}
