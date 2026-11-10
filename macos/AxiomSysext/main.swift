// axiom-sysext — installs and controls the AxiomFilter system extension.
//
// Usage: axiom-sysext <command> [--timeout SECONDS] [--no-wait] [--force]
//
//   activate    submit the system extension activation request (install/upgrade),
//               then save and enable the NEFilterManager content filter configuration.
//               An active extension with the same version+build is kept unless --force.
//               --no-wait: exit 3 as soon as macOS asks for user approval
//               (default: wait up to --timeout seconds, 120 by default, for approval)
//   deactivate  remove the filter configuration, then request extension deactivation
//   enable      enable the filter configuration only (extension must be activated)
//   disable     disable the filter configuration only (extension stays installed)
//   status      report extension and filter state (no changes, no prompts)
//
// Output: exactly one JSON object on stdout. Human-readable progress goes to stderr.
// Exit codes (ExitCode below): 0 ok, 1 error, 2 timeout, 3 waiting for user approval,
// 4 reboot required, 64 usage.
//
// OSSystemExtensionRequest acts on the extensions embedded in the *main bundle* of the
// calling process (Bundle.main). This executable must therefore live in
// Axiom.app/Contents/MacOS/ (Foundation resolves Bundle.main to the enclosing .app for
// any executable in Contents/MacOS, whether or not it is CFBundleExecutable), and it
// needs the com.apple.developer.system-extension.install and networkextension entitlements.
//
// activate/deactivate may show macOS authorization UI (System Settings approval,
// "Filter Network Content" prompt, admin password). Run from a GUI login session;
// over SSH without a GUI session these fail with OSSystemExtensionErrorDomain 13.

import Foundation
import NetworkExtension
import SystemExtensions

// MARK: - Constants

let extensionIdentifier = "com.axiom.firewall.filter"
let filterDescription = "Axiom Firewall"
let defaultTimeout: TimeInterval = 120

enum ExitCode: Int32 {
    case ok = 0
    case error = 1
    case timeout = 2
    case needsApproval = 3
    case rebootRequired = 4
    case usage = 64
}

// MARK: - Output

/// Accumulates the single JSON result object and writes it exactly once.
final class Output {
    private var fields: [String: Any]
    private var finished = false
    /// Exit code used by the watchdog (activate switches it to needsApproval once prompted).
    var timeoutCode: ExitCode = .timeout

    init(command: String) {
        fields = ["command": command, "extensionIdentifier": extensionIdentifier,
                  "appBundle": Bundle.main.bundlePath]
    }

    subscript(key: String) -> Any? {
        get { fields[key] }
        set { fields[key] = newValue }
    }

    func progress(_ message: String) {
        FileHandle.standardError.write(Data(("axiom-sysext: " + message + "\n").utf8))
    }

    /// Prints the result and exits. Idempotent: later calls are ignored.
    func finish(_ code: ExitCode, state: String, message: String? = nil, error: Error? = nil) -> Never {
        if !finished {
            finished = true
            fields["ok"] = code == .ok
            fields["state"] = state
            fields["exitCode"] = Int(code.rawValue)
            if let message { fields["message"] = message }
            if let error {
                let ns = error as NSError
                fields["error"] = ["domain": ns.domain, "code": ns.code, "message": describe(error)]
            }
            let data = (try? JSONSerialization.data(withJSONObject: fields,
                                                    options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data("{}".utf8)
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
        exit(code.rawValue)
    }
}

/// Readable text for OSSystemExtensionError codes (their localizedDescription is often "(null)").
func describe(_ error: Error) -> String {
    let ns = error as NSError
    guard ns.domain == OSSystemExtensionErrorDomain, let code = OSSystemExtensionError.Code(rawValue: ns.code) else {
        return ns.localizedDescription
    }
    switch code {
    case .missingEntitlement: return "missing entitlement (com.apple.developer.system-extension.install)"
    case .unsupportedParentBundleLocation: return "the app must be in /Applications"
    case .extensionNotFound: return "extension not found in the app bundle"
    case .extensionMissingIdentifier: return "extension is missing its bundle identifier"
    case .duplicateExtensionIdentifer: return "duplicate extension identifier"
    case .unknownExtensionCategory: return "unknown extension category"
    case .codeSignatureInvalid: return "code signature invalid"
    case .validationFailed: return "extension validation failed"
    case .forbiddenBySystemPolicy: return "forbidden by system policy"
    case .requestCanceled: return "request canceled"
    case .requestSuperseded: return "request superseded by a newer request"
    case .authorizationRequired: return "authorization required (run from a GUI login session)"
    default: return "system extension error \(ns.code)"
    }
}

// MARK: - Extension requests

/// Bridges one OSSystemExtensionRequest to closures.
final class RequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
    var onApprovalNeeded: () -> Void = {}
    var onFinish: (OSSystemExtensionRequest.Result) -> Void = { _ in }
    var onFail: (Error) -> Void = { _ in }
    var onProperties: ([OSSystemExtensionProperties]) -> Void = { _ in }
    /// When false, an already-active extension with the same version and build is kept
    /// (no replace churn); set by `activate --force` to always replace.
    var replaceSameVersion = true
    /// Set when this delegate cancelled the request because the same version is active.
    private(set) var keptExisting = false

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        if !replaceSameVersion, existing.bundleVersion == ext.bundleVersion,
           existing.bundleShortVersion == ext.bundleShortVersion {
            keptExisting = true
            FileHandle.standardError.write(Data(
                "axiom-sysext: version \(existing.bundleShortVersion) (\(existing.bundleVersion)) already active\n".utf8))
            return .cancel
        }
        FileHandle.standardError.write(Data(
            "axiom-sysext: replacing \(existing.bundleShortVersion) (\(existing.bundleVersion)) with \(ext.bundleShortVersion) (\(ext.bundleVersion))\n".utf8))
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { onApprovalNeeded() }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        onFinish(result)
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { onFail(error) }

    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        onProperties(properties)
    }
}

/// Keeps delegates alive for the life of the process.
var liveDelegates: [RequestDelegate] = []

func submit(_ request: OSSystemExtensionRequest, _ delegate: RequestDelegate) {
    liveDelegates.append(delegate)
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
}

/// Path of the embedded extension bundle, if present.
func embeddedExtensionURL() -> URL {
    Bundle.main.bundleURL
        .appendingPathComponent("Contents/Library/SystemExtensions")
        .appendingPathComponent(extensionIdentifier + ".systemextension")
}

/// Version info of the extension embedded in this app.
func embeddedExtensionInfo() -> [String: Any]? {
    guard let bundle = Bundle(url: embeddedExtensionURL()) else { return nil }
    return [
        "path": bundle.bundlePath,
        "version": bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? NSNull(),
        "build": bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? NSNull(),
    ]
}

/// Queries installed versions of the extension (macOS 12+, no prompts).
func queryProperties(_ completion: @escaping ([[String: Any]]?, Error?) -> Void) {
    let delegate = RequestDelegate()
    delegate.onProperties = { props in
        completion(props.map { p in
            [
                "version": p.bundleShortVersion,
                "build": p.bundleVersion,
                "enabled": p.isEnabled,
                "awaitingUserApproval": p.isAwaitingUserApproval,
                "uninstalling": p.isUninstalling,
                "path": p.url.path,
            ]
        }, nil)
    }
    delegate.onFail = { completion(nil, $0) }
    submit(OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main),
           delegate)
}

// MARK: - Filter configuration

func filterState(_ manager: NEFilterManager) -> [String: Any] {
    [
        "configured": manager.providerConfiguration != nil,
        "enabled": manager.isEnabled,
        "description": manager.localizedDescription ?? NSNull(),
        "dataProvider": manager.providerConfiguration?.filterDataProviderBundleIdentifier ?? NSNull(),
    ]
}

/// Loads, mutates and saves the shared NEFilterManager configuration.
func updateFilter(enable: Bool, remove: Bool = false, _ completion: @escaping ([String: Any], Error?) -> Void) {
    let manager = NEFilterManager.shared()
    manager.loadFromPreferences { error in
        if let error { completion(filterState(manager), error); return }
        if remove {
            guard manager.providerConfiguration != nil else { completion(filterState(manager), nil); return }
            manager.removeFromPreferences { error in
                // Reload so the reported state reflects what is persisted.
                manager.loadFromPreferences { _ in completion(filterState(manager), error) }
            }
            return
        }
        if enable {
            let config = manager.providerConfiguration ?? NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            config.filterDataProviderBundleIdentifier = extensionIdentifier
            manager.providerConfiguration = config
            manager.localizedDescription = filterDescription
        } else if manager.providerConfiguration == nil {
            completion(filterState(manager), nil) // nothing to disable
            return
        }
        manager.isEnabled = enable
        manager.saveToPreferences { error in completion(filterState(manager), error) }
    }
}

// MARK: - Commands

func activate(_ out: Output, wait: Bool, force: Bool) {
    guard let embedded = embeddedExtensionInfo() else {
        out.finish(.error, state: "error",
                   message: "extension not found at \(embeddedExtensionURL().path); run axiom-sysext from Axiom.app/Contents/MacOS")
    }
    out["extension"] = embedded
    let delegate = RequestDelegate()
    delegate.replaceSameVersion = force
    delegate.onApprovalNeeded = {
        out.timeoutCode = .needsApproval
        out.progress("waiting for approval: System Settings > General > Login Items & Extensions > Network Extensions")
        if !wait {
            out.finish(.needsApproval, state: "needs_approval",
                       message: "Approve Axiom in System Settings > General > Login Items & Extensions > Network Extensions, then run activate again")
        }
    }
    let enableFilter = {
        out.progress("extension active; enabling content filter")
        updateFilter(enable: true) { state, error in
            out["filter"] = state
            if let error { out.finish(.error, state: "error", message: "extension activated but filter not enabled", error: error) }
            out.finish(.ok, state: "activated")
        }
    }
    delegate.onFail = { [unowned delegate] error in
        let ns = error as NSError
        if delegate.keptExisting, ns.domain == OSSystemExtensionErrorDomain,
           ns.code == OSSystemExtensionError.Code.requestCanceled.rawValue {
            out["replaced"] = false
            enableFilter() // same version already active: nothing to install
            return
        }
        out.finish(.error, state: "error", error: error)
    }
    delegate.onFinish = { result in
        if result == .willCompleteAfterReboot {
            out.finish(.rebootRequired, state: "reboot_required", message: "Restart the Mac to finish activation")
        }
        enableFilter()
    }
    submit(OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main),
           delegate)
}

func deactivate(_ out: Output) {
    // Remove the filter configuration first so no flows depend on the extension while it stops.
    updateFilter(enable: false, remove: true) { state, error in
        out["filter"] = state
        if let error { out.progress("removing filter configuration failed: \(describe(error))") }
        let delegate = RequestDelegate()
        delegate.onApprovalNeeded = { out.progress("deactivation needs user approval") }
        delegate.onFail = { error in
            let ns = error as NSError
            if ns.domain == OSSystemExtensionErrorDomain, ns.code == OSSystemExtensionError.Code.extensionNotFound.rawValue {
                out.finish(.ok, state: "deactivated", message: "extension was not installed")
            }
            out.finish(.error, state: "error", error: error)
        }
        delegate.onFinish = { result in
            if result == .willCompleteAfterReboot {
                out.finish(.rebootRequired, state: "reboot_required", message: "Restart the Mac to finish removal")
            }
            out.finish(.ok, state: "deactivated")
        }
        submit(OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main),
               delegate)
    }
}

func setFilter(_ out: Output, enable: Bool) {
    updateFilter(enable: enable) { state, error in
        out["filter"] = state
        if let error { out.finish(.error, state: "error", error: error) }
        out.finish(.ok, state: enable ? "enabled" : "disabled")
    }
}

func status(_ out: Output) {
    out["extension"] = embeddedExtensionInfo() ?? NSNull()
    queryProperties { installed, error in
        out["installed"] = installed ?? []
        if let error { out["installedError"] = describe(error) }
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            out["filter"] = filterState(manager)
            if let error { out.finish(.error, state: "error", error: error) }
            let active = (installed ?? []).contains { ($0["enabled"] as? Bool) == true && ($0["uninstalling"] as? Bool) != true }
            let pending = (installed ?? []).contains { ($0["awaitingUserApproval"] as? Bool) == true }
            let state: String
            if active && manager.isEnabled { state = "running" }
            else if active { state = "installed_filter_disabled" }
            else if pending { state = "needs_approval" }
            else { state = "not_installed" }
            out.finish(.ok, state: state)
        }
    }
}

// MARK: - Main

let usage = "usage: axiom-sysext activate|deactivate|enable|disable|status [--timeout SECONDS] [--no-wait] [--force]"
var args = Array(CommandLine.arguments.dropFirst())
let command = args.isEmpty ? "status" : args.removeFirst()
var timeout = defaultTimeout
var timeoutGiven = false
var wait = true
var force = false
while !args.isEmpty {
    let arg = args.removeFirst()
    switch arg {
    case "--timeout":
        guard let v = args.first.flatMap(TimeInterval.init), v > 0 else {
            Output(command: command).finish(.usage, state: "usage", message: usage)
        }
        args.removeFirst()
        timeout = v
        timeoutGiven = true
    case "--no-wait":
        wait = false
    case "--force":
        force = true
    default:
        Output(command: command).finish(.usage, state: "usage", message: usage)
    }
}

let out = Output(command: command)

// System extension requests resolve the extension through Bundle.main: refuse to run
// outside an app bundle instead of waiting for callbacks that never arrive.
if ["activate", "deactivate", "status"].contains(command), Bundle.main.bundleURL.pathExtension != "app" {
    out.finish(.error, state: "error",
               message: "axiom-sysext must run from Axiom.app/Contents/MacOS (main bundle is \(Bundle.main.bundlePath))")
}
// status never prompts; keep it snappy unless the caller asked otherwise.
if command == "status", !timeoutGiven { timeout = 15 }

switch command {
case "activate": activate(out, wait: wait, force: force)
case "deactivate": deactivate(out)
case "enable": setFilter(out, enable: true)
case "disable": setFilter(out, enable: false)
case "status": status(out)
case "-h", "--help", "help": out.finish(.ok, state: "usage", message: usage)
default: out.finish(.usage, state: "usage", message: usage)
}

// Watchdog: a pending request (e.g. user never approves) must not hang the caller forever.
DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
    let code = out.timeoutCode
    out.finish(code, state: code == .needsApproval ? "needs_approval" : "timeout",
               message: "no result after \(Int(timeout)) s")
}
dispatchMain()
