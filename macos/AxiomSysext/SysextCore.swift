// AxiomSysext — installs and controls the AxiomFilter system extension.
//
// This code is the main executable of the app-like AxiomFilterHost.app. That bundle is the
// activation host: it lives in /Applications, owns
// Contents/Library/SystemExtensions/com.axiom.firewall.filter.systemextension, and carries the
// restricted entitlements (system-extension.install, networkextension, app group) together with
// its own Contents/embedded.provisionprofile. The Avalonia/.NET UI runs the executable as a
// child process and never claims those entitlements.
//
// Nothing in here prints or exits: every command reports exactly one `SysextResult`
// through a completion closure, delivered on the queue the caller supplied.
//
// OSSystemExtensionRequest acts on the extensions embedded in the *main bundle* of the
// calling process (Bundle.main), so the extension must be inside this host bundle and the host
// must be installed in an Applications directory.
//
// activate/deactivate may show macOS authorization UI (System Settings approval,
// "Filter Network Content" prompt, admin password). Run from a GUI login session;
// over SSH without a GUI session these fail with OSSystemExtensionErrorDomain 13.
//
// Upgrade policy (review #5): `activate` replaces an installed extension whose
// version/build differ from the embedded one, or whose code directory hash (cdhash)
// differs when both can be read; `force` always replaces. build.sh gives every
// development build a distinct CFBundleVersion, so a rebuilt extension is always installed.

import Foundation
import NetworkExtension
import Security
import SystemExtensions

// MARK: - Constants

let hostBundleIdentifier = "com.axiom.firewall.host"
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

enum SysextCommand {
    /// `resetFilter`: remove and re-create the NEFilterManager configuration instead of
    /// updating it in place (see `isAdHocSigned`).
    case activate(force: Bool, wait: Bool, resetFilter: Bool)
    case deactivate
    case enable
    case disable
    case status

    var name: String {
        switch self {
        case .activate: return "activate"
        case .deactivate: return "deactivate"
        case .enable: return "enable"
        case .disable: return "disable"
        case .status: return "status"
        }
    }
}

// MARK: - Result

/// Accumulates the single JSON result object of one command and delivers it exactly once.
final class SysextResult {
    private(set) var fields: [String: Any]
    private(set) var finished = false
    private(set) var code: ExitCode = .error
    /// Exit code used by the watchdog (activate switches it to needsApproval once prompted).
    var timeoutCode: ExitCode = .timeout
    let progress: (String) -> Void
    private let completion: (SysextResult) -> Void

    init(command: String, progress: @escaping (String) -> Void, completion: @escaping (SysextResult) -> Void) {
        fields = ["command": command, "extensionIdentifier": extensionIdentifier,
                  "appBundle": Bundle.main.bundlePath]
        self.progress = progress
        self.completion = completion
    }

    subscript(key: String) -> Any? {
        get { fields[key] }
        set { fields[key] = newValue }
    }

    /// Serialised JSON (sorted keys, one object, no trailing newline).
    var json: String {
        let data = (try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
            ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    /// Records the outcome and calls the completion. Idempotent: later calls are ignored.
    func finish(_ code: ExitCode, state: String, message: String? = nil, error: Error? = nil) {
        guard !finished else { return }
        finished = true
        self.code = code
        fields["ok"] = code == .ok
        fields["state"] = state
        fields["exitCode"] = Int(code.rawValue)
        if let message { fields["message"] = message }
        if let error {
            let ns = error as NSError
            fields["error"] = ["domain": ns.domain, "code": ns.code, "message": describe(error)]
        }
        completion(self)
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
    var progress: (String) -> Void = { _ in }
    /// When true every installed extension is replaced (`activate --force`).
    var forceReplace = false
    /// Set when this delegate cancelled the request because the installed copy is identical.
    private(set) var keptExisting = false
    /// Set when an installed copy existed (the request was an upgrade, not a first install).
    private(set) var sawExisting = false
    /// cdhash of the embedded / installed copy when readable (reported in the result).
    private(set) var embeddedCdhash: String?
    private(set) var installedCdhash: String?

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        sawExisting = true
        let old = "\(existing.bundleShortVersion) (\(existing.bundleVersion))"
        let new = "\(ext.bundleShortVersion) (\(ext.bundleVersion))"
        embeddedCdhash = cdhash(of: ext.url)
        installedCdhash = cdhash(of: existing.url)
        if forceReplace {
            progress("replacing \(old) with \(new) (forced)")
            return .replace
        }
        if existing.bundleVersion != ext.bundleVersion || existing.bundleShortVersion != ext.bundleShortVersion {
            progress("replacing \(old) with \(new)")
            return .replace
        }
        if let a = embeddedCdhash, let b = installedCdhash, a != b {
            progress("replacing \(old): same version but different code (cdhash \(b) -> \(a))")
            return .replace
        }
        keptExisting = true
        progress("version \(old) already active" + (embeddedCdhash == nil ? " (cdhash not compared)" : ", same cdhash"))
        return .cancel
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
private var liveDelegates: [RequestDelegate] = []
private let liveDelegatesLock = NSLock()

func submit(_ request: OSSystemExtensionRequest, _ delegate: RequestDelegate) {
    liveDelegatesLock.lock(); liveDelegates.append(delegate); liveDelegatesLock.unlock()
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
}

/// Path of the embedded extension bundle, if present.
func embeddedExtensionURL() -> URL {
    Bundle.main.bundleURL
        .appendingPathComponent("Contents/Library/SystemExtensions")
        .appendingPathComponent(extensionIdentifier + ".systemextension")
}

/// Hex code directory hash of a signed bundle, or nil when unreadable/unsigned.
func cdhash(of url: URL) -> String? {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any], let unique = dict[kSecCodeInfoUnique as String] as? Data else { return nil }
    return unique.map { String(format: "%02x", $0) }.joined()
}

/// True when this process is ad hoc signed (development builds). An NEFilterManager
/// configuration is bound to the code signature of the app that saved it; for an ad hoc
/// signature that is the exact cdhash, so after every rebuild nesessionmanager rejects the
/// existing configuration ("does not satisfy the code signature requirements") and the filter
/// never starts. Dev builds therefore re-create the configuration whenever `activate` replaced
/// the extension (the helper is re-signed alongside); Developer ID signatures satisfy a stable
/// designated requirement and keep theirs. `--reset-filter` forces the re-creation.
func isAdHocSigned() -> Bool {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return false }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return false }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any], let flags = dict[kSecCodeInfoFlags as String] as? UInt32 else { return false }
    return flags & SecCodeSignatureFlags.adhoc.rawValue != 0
}

/// Version info of the extension embedded in this app.
func embeddedExtensionInfo() -> [String: Any]? {
    guard let bundle = Bundle(url: embeddedExtensionURL()) else { return nil }
    return [
        "path": bundle.bundlePath,
        "version": bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? NSNull(),
        "build": bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? NSNull(),
        "cdhash": cdhash(of: bundle.bundleURL) ?? NSNull(),
    ]
}

/// Queries installed versions of the extension (macOS 12+, no prompts).
func queryProperties(queue: DispatchQueue, _ completion: @escaping ([[String: Any]]?, Error?) -> Void) {
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
                "cdhash": cdhash(of: p.url) ?? NSNull(),
            ]
        }, nil)
    }
    delegate.onFail = { completion(nil, $0) }
    submit(OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: extensionIdentifier, queue: queue),
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

private func activate(_ out: SysextResult, queue: DispatchQueue, wait: Bool, force: Bool, resetFilter: Bool) {
    guard let embedded = embeddedExtensionInfo() else {
        out.finish(.error, state: "error",
                   message: "extension not found at \(embeddedExtensionURL().path); run from AxiomFilterHost.app/Contents/MacOS")
        return
    }
    out["extension"] = embedded
    let delegate = RequestDelegate()
    delegate.forceReplace = force
    delegate.progress = out.progress
    delegate.onApprovalNeeded = {
        out.timeoutCode = .needsApproval
        out.progress("waiting for approval: System Settings > General > Login Items & Extensions > Network Extensions")
        if !wait {
            out.finish(.needsApproval, state: "needs_approval",
                       message: "Approve Axiom in System Settings > General > Login Items & Extensions > Network Extensions, then run activate again")
        }
    }
    let adHoc = isAdHocSigned()
    out["adHocSigned"] = adHoc
    // `replaced`: an installed extension was replaced (every dev build has a new build number,
    // and package-app.sh re-signs the helper alongside, so this is when the ad hoc config breaks).
    let enableFilter = { (replaced: Bool) in
        let reset = resetFilter || (adHoc && replaced)
        out["filterReset"] = reset
        let save = {
            out.progress("extension active; enabling content filter")
            updateFilter(enable: true) { state, error in
                queue.async {
                    out["filter"] = state
                    if let error {
                        out.finish(.error, state: "error", message: "extension activated but filter not enabled", error: error)
                        return
                    }
                    out.finish(.ok, state: "activated")
                }
            }
        }
        if reset {
            out.progress("re-creating the content filter configuration (ad hoc signature / --reset-filter)")
            updateFilter(enable: false, remove: true) { _, error in
                if let error { out.progress("removing the old configuration failed: \(describe(error))") }
                save()
            }
        } else {
            save()
        }
    }
    delegate.onFail = { [unowned delegate] error in
        let ns = error as NSError
        if delegate.keptExisting, ns.domain == OSSystemExtensionErrorDomain,
           ns.code == OSSystemExtensionError.Code.requestCanceled.rawValue {
            out["replaced"] = false
            out["installedCdhash"] = delegate.installedCdhash ?? NSNull()
            enableFilter(false) // identical extension already active: nothing to install
            return
        }
        out.finish(.error, state: "error", error: error)
    }
    delegate.onFinish = { [unowned delegate] result in
        out["replaced"] = delegate.sawExisting
        if let h = delegate.installedCdhash { out["installedCdhash"] = h }
        if result == .willCompleteAfterReboot {
            out.finish(.rebootRequired, state: "reboot_required", message: "Restart the Mac to finish activation")
            return
        }
        enableFilter(delegate.sawExisting)
    }
    submit(OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: queue),
           delegate)
}

private func deactivate(_ out: SysextResult, queue: DispatchQueue) {
    // Remove the filter configuration first so no flows depend on the extension while it stops.
    updateFilter(enable: false, remove: true) { state, error in
        queue.async {
            out["filter"] = state
            if let error { out.progress("removing filter configuration failed: \(describe(error))") }
            let delegate = RequestDelegate()
            delegate.onApprovalNeeded = { out.progress("deactivation needs user approval") }
            delegate.onFail = { error in
                let ns = error as NSError
                if ns.domain == OSSystemExtensionErrorDomain, ns.code == OSSystemExtensionError.Code.extensionNotFound.rawValue {
                    out.finish(.ok, state: "deactivated", message: "extension was not installed")
                    return
                }
                out.finish(.error, state: "error", error: error)
            }
            delegate.onFinish = { result in
                if result == .willCompleteAfterReboot {
                    out.finish(.rebootRequired, state: "reboot_required", message: "Restart the Mac to finish removal")
                    return
                }
                out.finish(.ok, state: "deactivated")
            }
            submit(OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: queue),
                   delegate)
        }
    }
}

private func setFilter(_ out: SysextResult, queue: DispatchQueue, enable: Bool) {
    updateFilter(enable: enable) { state, error in
        queue.async {
            out["filter"] = state
            if let error { out.finish(.error, state: "error", error: error); return }
            out.finish(.ok, state: enable ? "enabled" : "disabled")
        }
    }
}

private func status(_ out: SysextResult, queue: DispatchQueue) {
    out["extension"] = embeddedExtensionInfo() ?? NSNull()
    queryProperties(queue: queue) { installed, error in
        out["installed"] = installed ?? []
        if let error { out["installedError"] = describe(error) }
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            queue.async {
                out["filter"] = filterState(manager)
                if let error { out.finish(.error, state: "error", error: error); return }
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
}

/// Runs one command. `queue` is a serial queue that must be serviced (the main queue of a
/// CLI, or a private queue for library callers); the completion arrives on it, at most once,
/// within `timeout` seconds (then with `timeout`/`needs_approval`).
func runSysextCommand(_ command: SysextCommand, queue: DispatchQueue, timeout: TimeInterval,
                      progress: @escaping (String) -> Void, completion: @escaping (SysextResult) -> Void) {
    let out = SysextResult(command: command.name, progress: progress, completion: completion)
    queue.async {
        // System extension requests resolve the extension through Bundle.main: refuse to run
        // outside the app-like host bundle instead of waiting for callbacks that never arrive.
        switch command {
        case .activate, .deactivate, .status:
            if Bundle.main.bundleURL.pathExtension != "app" || Bundle.main.bundleIdentifier != hostBundleIdentifier {
                out.finish(.error, state: "error",
                           message: "must run from AxiomFilterHost.app/Contents/MacOS (main bundle is \(Bundle.main.bundlePath))")
                return
            }
        default: break
        }
        // Ad hoc signatures cannot authorise restricted entitlements (TN3125): the build signs
        // this host with none, and every restricted call would fail with missingEntitlement.
        // Refuse once with a user-actionable message instead of a retry loop.
        if isAdHocSigned() {
            out.finish(.error, state: "unavailable",
                       message: "The Axiom network filter needs the signed Axiom package. This activation host is ad hoc signed, so macOS will not grant its restricted entitlements.")
            return
        }
        switch command {
        case let .activate(force, wait, resetFilter):
            activate(out, queue: queue, wait: wait, force: force, resetFilter: resetFilter)
        case .deactivate: deactivate(out, queue: queue)
        case .enable: setFilter(out, queue: queue, enable: true)
        case .disable: setFilter(out, queue: queue, enable: false)
        case .status: status(out, queue: queue)
        }
        // Watchdog: a pending request (e.g. user never approves) must not hang the caller forever.
        queue.asyncAfter(deadline: .now() + timeout) {
            let code = out.timeoutCode
            out.finish(code, state: code == .needsApproval ? "needs_approval" : "timeout",
                       message: "no result after \(Int(timeout)) s")
        }
    }
}
