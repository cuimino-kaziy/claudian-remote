import AppKit
import Foundation

private struct ManagedService {
    let label: String
    let plist: String
    let persistent: Bool
}

private struct ServiceSnapshot {
    let service: ManagedService
    let loaded: Bool
    let disabled: Bool
}

private let launchAgentsDirectory = (NSHomeDirectory() as NSString)
    .appendingPathComponent("Library/LaunchAgents")

private let managedServices = [
    ManagedService(
        label: "com.claudian.remote.relay",
        plist: (launchAgentsDirectory as NSString)
            .appendingPathComponent("com.claudian.remote.relay.plist"),
        persistent: true
    ),
    ManagedService(
        label: "com.claudian.remote.companion",
        plist: (launchAgentsDirectory as NSString)
            .appendingPathComponent("com.claudian.remote.companion.plist"),
        persistent: true
    ),
    ManagedService(
        label: "com.claudian.remote.availability",
        plist: (launchAgentsDirectory as NSString)
            .appendingPathComponent("com.claudian.remote.availability.plist"),
        persistent: false
    ),
]

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
            self.startAllServices(domain: domain)
        }
    }

    @objc private func restartService() {
        runServiceAction { domain in
            self.startAllServices(domain: domain)
        }
    }

    @objc private func stopService() {
        runServiceAction { domain in
            var outcome: (status: Int32, output: String) = (0, "")
            for service in managedServices.reversed() where self.isServiceLoaded(service, domain: domain) {
                let result = self.runLaunchctl(["bootout", self.serviceTarget(service, domain: domain)])
                if result.status != 0 && outcome.status == 0 { outcome = result }
            }
            return outcome
        }
    }

    @objc private func toggleAutoStart() {
        runServiceAction { domain in
            if self.isAutoStartDisabled() {
                return self.startAllServices(domain: domain)
            }
            let snapshots = managedServices.map {
                ServiceSnapshot(
                    service: $0,
                    loaded: self.isServiceLoaded($0, domain: domain),
                    disabled: self.isServiceDisabled($0, domain: domain)
                )
            }
            for service in managedServices {
                if self.isServiceLoaded(service, domain: domain) {
                    let bootout = self.runLaunchctl([
                        "bootout", self.serviceTarget(service, domain: domain),
                    ])
                    guard bootout.status == 0 else {
                        self.restoreServices(snapshots, domain: domain)
                        return bootout
                    }
                }
                let result = self.runLaunchctl(["disable", "\(domain)/\(service.label)"])
                guard result.status == 0 else {
                    self.restoreServices(snapshots, domain: domain)
                    return result
                }
            }
            return (0, "")
        }
    }

    @objc private func openLogs() {
        let logs = [
            (NSHomeDirectory() as NSString).appendingPathComponent(
                "Library/Application Support/Claudian Remote/logs"
            ),
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
        managedServices.filter(\.persistent).allSatisfy { service in
            let result = runLaunchctl(["print", "\(userDomain())/\(service.label)"])
            return result.status == 0 && result.output.contains("state = running")
        }
    }

    private func isAutoStartDisabled() -> Bool {
        let result = runLaunchctl(["print-disabled", userDomain()])
        return managedServices.contains { service in
            result.output.contains("\(service.label) => true")
        }
    }

    private func startAllServices(domain: String) -> (status: Int32, output: String) {
        let missingRequired = managedServices.filter {
            $0.persistent && !FileManager.default.fileExists(atPath: $0.plist)
        }
        guard missingRequired.isEmpty else {
            let labels = missingRequired.map(\.label).joined(separator: ", ")
            return (66, "缺少必需的 LaunchAgent：\(labels)")
        }
        let candidates = managedServices.filter {
            $0.persistent || FileManager.default.fileExists(atPath: $0.plist)
        }
        let snapshots = managedServices.map {
            ServiceSnapshot(
                service: $0,
                loaded: isServiceLoaded($0, domain: domain),
                disabled: isServiceDisabled($0, domain: domain)
            )
        }
        for service in managedServices {
            let enable = runLaunchctl(["enable", "\(domain)/\(service.label)"])
            guard enable.status == 0 else {
                restoreServices(snapshots, domain: domain)
                return enable
            }
        }
        for service in candidates {
            if isServiceLoaded(service, domain: domain) {
                let bootout = runLaunchctl(["bootout", serviceTarget(service, domain: domain)])
                guard bootout.status == 0 else {
                    restoreServices(snapshots, domain: domain)
                    return bootout
                }
            }
            let bootstrap = runLaunchctl(["bootstrap", domain, service.plist])
            guard bootstrap.status == 0 else {
                restoreServices(snapshots, domain: domain)
                return bootstrap
            }
        }
        return (0, "")
    }

    private func serviceTarget(_ service: ManagedService, domain: String) -> String {
        "\(domain)/\(service.label)"
    }

    private func isServiceLoaded(_ service: ManagedService, domain: String) -> Bool {
        runLaunchctl(["print", serviceTarget(service, domain: domain)]).status == 0
    }

    private func isServiceDisabled(_ service: ManagedService, domain: String) -> Bool {
        let result = runLaunchctl(["print-disabled", domain])
        return result.output.contains("\(service.label) => true")
    }

    private func restoreServices(_ snapshots: [ServiceSnapshot], domain: String) {
        for snapshot in snapshots.reversed() {
            let service = snapshot.service
            if isServiceLoaded(service, domain: domain) {
                _ = runLaunchctl(["bootout", serviceTarget(service, domain: domain)])
            }
            _ = runLaunchctl([
                snapshot.disabled ? "disable" : "enable",
                serviceTarget(service, domain: domain),
            ])
            if snapshot.loaded && FileManager.default.fileExists(atPath: service.plist) {
                _ = runLaunchctl(["bootstrap", domain, service.plist])
            }
        }
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
