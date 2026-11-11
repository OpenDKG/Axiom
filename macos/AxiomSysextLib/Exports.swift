// libAxiomSysext.dylib — C entry points for the .NET host (P/Invoke), review #4.
//
// Lets the main `Axiom` executable submit the system extension requests itself, so the
// restricted entitlements (system-extension.install, networkextension), the provisioning
// profile and Bundle.main all belong to the one executable Apple vouches for. The dylib
// carries no entitlements: the *calling process* must be signed with
// axiom-sysext.entitlements and run from Axiom.app/Contents/MacOS.
//
// Every function is synchronous, takes at most `timeoutSeconds` (+ a little), and returns a
// malloc'd UTF-8 JSON string with the same fields as `axiom-sysext` prints; free it with
// axiom_sysext_free. They block the calling thread: call them from a worker thread, never
// from the UI thread (callbacks are serviced on a private queue, so the main run loop is
// not required).
//
// C signatures:
//   char *axiom_sysext_activate(int force, int waitForApproval, int timeoutSeconds);
//         force: always replace the installed extension; bit 2 (value 2) of force = reset the
//         filter configuration (always done for ad hoc signed callers)
//   char *axiom_sysext_deactivate(int timeoutSeconds);
//   char *axiom_sysext_set_filter(int enable, int timeoutSeconds);
//   char *axiom_sysext_status(int timeoutSeconds);
//   int   axiom_sysext_exit_code(const char *json);   // the "exitCode" field, -1 if unparsable
//   void  axiom_sysext_free(char *p);
//   const char *axiom_sysext_version(void);           // library/contract version, static

import Darwin
import Foundation

private let libraryVersion = "1"
private let queue = DispatchQueue(label: "com.axiom.firewall.sysext.lib")

private func run(_ command: SysextCommand, timeoutSeconds: Int32) -> UnsafeMutablePointer<CChar>? {
    let timeout = timeoutSeconds > 0 ? TimeInterval(timeoutSeconds) : defaultTimeout
    let done = DispatchSemaphore(value: 0)
    var json = "{}"
    runSysextCommand(command, queue: queue, timeout: timeout, progress: { _ in },
                     completion: { json = $0.json; done.signal() })
    // The watchdog inside runSysextCommand guarantees a completion; this is a last resort.
    if done.wait(timeout: .now() + timeout + 5) == .timedOut {
        json = "{\"ok\":false,\"state\":\"timeout\",\"exitCode\":\(ExitCode.timeout.rawValue),\"message\":\"no result\"}"
    }
    return strdup(json)
}

@_cdecl("axiom_sysext_activate")
public func axiom_sysext_activate(_ force: Int32, _ waitForApproval: Int32, _ timeoutSeconds: Int32) -> UnsafeMutablePointer<CChar>? {
    run(.activate(force: force & 1 != 0, wait: waitForApproval != 0, resetFilter: force & 2 != 0), timeoutSeconds: timeoutSeconds)
}

@_cdecl("axiom_sysext_deactivate")
public func axiom_sysext_deactivate(_ timeoutSeconds: Int32) -> UnsafeMutablePointer<CChar>? {
    run(.deactivate, timeoutSeconds: timeoutSeconds)
}

@_cdecl("axiom_sysext_set_filter")
public func axiom_sysext_set_filter(_ enable: Int32, _ timeoutSeconds: Int32) -> UnsafeMutablePointer<CChar>? {
    run(enable != 0 ? .enable : .disable, timeoutSeconds: timeoutSeconds)
}

@_cdecl("axiom_sysext_status")
public func axiom_sysext_status(_ timeoutSeconds: Int32) -> UnsafeMutablePointer<CChar>? {
    run(.status, timeoutSeconds: timeoutSeconds > 0 ? timeoutSeconds : 15)
}

@_cdecl("axiom_sysext_exit_code")
public func axiom_sysext_exit_code(_ json: UnsafePointer<CChar>?) -> Int32 {
    guard let json, let object = try? JSONSerialization.jsonObject(with: Data(bytes: json, count: strlen(json))),
          let dict = object as? [String: Any], let code = dict["exitCode"] as? Int else { return -1 }
    return Int32(code)
}

@_cdecl("axiom_sysext_free")
public func axiom_sysext_free(_ p: UnsafeMutablePointer<CChar>?) {
    free(p)
}

private let versionCString: UnsafeMutablePointer<CChar> = strdup(libraryVersion)

@_cdecl("axiom_sysext_version")
public func axiom_sysext_version() -> UnsafePointer<CChar> {
    UnsafePointer(versionCString)
}
