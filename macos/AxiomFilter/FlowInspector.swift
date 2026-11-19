// AxiomFilter — extracts process identity and endpoints from an NEFilterSocketFlow.
//
// Only metadata is read here; payloads are never inspected.
//
// macOS facts this relies on:
//   * NEFilterFlow.sourceAppIdentifier is iOS-only; on macOS the source process
//     comes from sourceAppAuditToken (an audit_token_t; pid is val.5, pidversion
//     val.7). The path is resolved with proc_pidpath_audittoken, which is immune
//     to pid reuse, falling back to proc_pidpath.
//   * The *responsible* process (review #12) comes from the private but long-stable
//     `responsibility_get_pid_responsible_for_pid` (libquarantine, used by LuLu):
//     for `sh -c curl`, a WebKit networking process or an app's XPC helper it names
//     the app that the user launched. Resolved with dlsym and skipped when absent.
//   * Paths are canonicalised once per process (realpath, so /var and /private/var
//     agree) and cached per (pid, pidversion) so the verdict path does no extra
//     syscalls for a process it has already seen.
//   * remoteFlowEndpoint/localFlowEndpoint (nw_endpoint_t) exist from macOS 15;
//     earlier systems use the deprecated NWHostEndpoint properties.
//   * remoteHostname carries the name the app connected by (also on DNS flows
//     to port 53) when macOS knows it.
//
// Known limitation: App Translocation. A quarantined app launched from e.g. ~/Downloads
// runs from /private/var/folders/.../AppTranslocation/<uuid>/d/Foo.app; realpath does
// not undo that, so a rule for /Users/x/Downloads/Foo.app does not match until the app
// is moved to /Applications (or the daemon writes the translocated path it observed).

import Darwin
import Foundation
import Network
import NetworkExtension
import os
import Security

struct FlowDescription {
    let pid: Int32
    let path: String?
    /// Responsible process, only when it differs from `pid`.
    let responsiblePid: Int32?
    let responsiblePath: String?
    let direction: FlowDirection
    let proto: FlowProtocol
    let localAddress: String?
    let localPort: Int?
    let remoteAddress: String?
    let remoteIP: IPAddress?
    let remotePort: Int?
    let remoteHost: String?

    var key: FlowKey {
        FlowKey(appPath: path, direction: direction, proto: proto, remoteAddress: remoteIP,
                remotePort: remotePort.flatMap { UInt16(exactly: $0) }, responsiblePath: responsiblePath)
    }
}

/// Resolved identity of one process, cached per (pid, pidversion).
struct ProcessIdentity {
    let pid: Int32
    let path: String?
    let responsiblePid: Int32?
    let responsiblePath: String?
}

enum FlowInspector {
    static func describe(_ flow: NEFilterSocketFlow) -> FlowDescription {
        let who = process(flow.sourceAppAuditToken)
        let (remoteText, remotePort) = remoteEndpoint(flow)
        let (localText, localPort) = localEndpoint(flow)

        // Normalise numeric addresses (strip zone ids, unmap ::ffff:a.b.c.d).
        let remoteIP = remoteText.flatMap(IPAddress.init)
        let localIP = localText.flatMap(IPAddress.init)

        var host = flow.remoteHostname
        if host?.isEmpty == true { host = nil }

        return FlowDescription(
            pid: who.pid,
            path: who.path,
            responsiblePid: who.responsiblePid,
            responsiblePath: who.responsiblePath,
            direction: flow.direction == .inbound ? .inbound : .outbound,
            proto: FlowProtocol(socketProtocol: flow.socketProtocol),
            localAddress: localIP?.description ?? localText,
            localPort: localPort,
            remoteAddress: remoteIP?.description ?? remoteText,
            remoteIP: remoteIP,
            remotePort: remotePort,
            remoteHost: host
        )
    }

    // MARK: Process identity

    private typealias ResponsibleFn = @convention(c) (pid_t) -> pid_t
    /// `responsibility_get_pid_responsible_for_pid`, or nil when this macOS does not export it.
    private static let responsibleFn: ResponsibleFn? = {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2) /* RTLD_DEFAULT */,
                              "responsibility_get_pid_responsible_for_pid") else { return nil }
        return unsafeBitCast(sym, to: ResponsibleFn.self)
    }()

    private struct CacheKey: Hashable { let pid: Int32; let version: UInt32 }
    private static let cache = OSAllocatedUnfairLock<[CacheKey: ProcessIdentity]>(initialState: [:])
    /// Flushed wholesale when exceeded; pids recycle, so a bounded cache is enough.
    private static let cacheLimit = 4096

    /// pid, executable path and responsible process of the app behind an audit token.
    static func process(_ tokenData: Data?) -> ProcessIdentity {
        guard let tokenData, tokenData.count == MemoryLayout<audit_token_t>.size else {
            return ProcessIdentity(pid: -1, path: nil, responsiblePid: nil, responsiblePath: nil)
        }
        var token = tokenData.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        let pid = Int32(bitPattern: token.val.5)
        let key = CacheKey(pid: pid, version: token.val.7)
        if let hit = cache.withLock({ $0[key] }) { return hit }

        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4) // PROC_PIDPATHINFO_MAXSIZE
        var length = proc_pidpath_audittoken(&token, &buffer, UInt32(buffer.count))
        if length <= 0 { length = proc_pidpath(pid, &buffer, UInt32(buffer.count)) }
        let path = length > 0 ? PathMatch.resolve(String(cString: buffer)) : nil

        var responsiblePid: Int32? = nil
        var responsiblePath: String? = nil
        if let fn = responsibleFn, pid > 0 {
            let r = fn(pid)
            if r > 0, r != pid {
                var rbuf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
                let rlen = proc_pidpath(r, &rbuf, UInt32(rbuf.count))
                let rpath = rlen > 0 ? PathMatch.resolve(String(cString: rbuf)) : nil
                if rpath != nil, rpath != path {
                    responsiblePid = r
                    responsiblePath = rpath
                }
            }
        }
        let identity = ProcessIdentity(pid: pid, path: path, responsiblePid: responsiblePid, responsiblePath: responsiblePath)
        if path != nil {
            cache.withLock { map in
                if map.count >= cacheLimit { map.removeAll(keepingCapacity: true) }
                map[key] = identity
            }
        }
        return identity
    }

    // MARK: Socket owner (resolver-delegated flows)

    /// Path of the system resolver. Its delegated sockets are attributed to the asking app.
    static let systemResolverPath = "/usr/sbin/mDNSResponder"
    /// Code requirement the socket owner must satisfy to count as the system resolver.
    private static let resolverRequirement: SecRequirement? = {
        var requirement: SecRequirement?
        let text = "anchor apple and identifier \"com.apple.mDNSResponder\"" as CFString
        return SecRequirementCreateWithString(text, [], &requirement) == errSecSuccess ? requirement : nil
    }()
    /// Verified-resolver results per (pid, pidversion); a process cannot change its executable.
    private static let resolverCache = OSAllocatedUnfairLock<[CacheKey: Bool]>(initialState: [:])

    /// The process that really owns the flow's socket (`sourceProcessAuditToken`, macOS 13+), when it
    /// differs from the attributed process `attributedPid`; nil when it is the same process or unknown.
    /// `isSystemResolver` is set only after verifying, from the owner's audit token, that its
    /// executable is /usr/sbin/mDNSResponder (proc_pidpath_audittoken, as for every flow) *and* that its
    /// code is valid and Apple-signed as com.apple.mDNSResponder (SecCode guest lookup by audit token).
    /// Nothing here trusts a name supplied by the flow.
    static func socketOwner(_ flow: NEFilterFlow, attributedPid: Int32) -> SocketOwner? {
        guard let tokenData = flow.sourceProcessAuditToken,
              tokenData.count == MemoryLayout<audit_token_t>.size else { return nil }
        let token = tokenData.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        let pid = Int32(bitPattern: token.val.5)
        guard pid > 0, pid != attributedPid else { return nil }
        let who = process(tokenData)
        guard who.path == systemResolverPath else {
            return SocketOwner(pid: pid, path: who.path, isSystemResolver: false)
        }
        let key = CacheKey(pid: pid, version: token.val.7)
        if let hit = resolverCache.withLock({ $0[key] }) {
            return SocketOwner(pid: pid, path: who.path, isSystemResolver: hit)
        }
        let verified = verifyResolverSignature(tokenData)
        resolverCache.withLock { map in
            if map.count >= cacheLimit { map.removeAll(keepingCapacity: true) }
            map[key] = verified
        }
        return SocketOwner(pid: pid, path: who.path, isSystemResolver: verified)
    }

    private static func verifyResolverSignature(_ tokenData: Data) -> Bool {
        guard let requirement = resolverRequirement else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    // MARK: Endpoints

    private static func remoteEndpoint(_ flow: NEFilterSocketFlow) -> (String?, Int?) {
        if #available(macOS 15.0, *) {
            if let ep = flow.remoteFlowEndpoint { return parts(ep) }
            return (nil, nil)
        }
        return legacyRemote(flow)
    }

    private static func localEndpoint(_ flow: NEFilterSocketFlow) -> (String?, Int?) {
        if #available(macOS 15.0, *) {
            if let ep = flow.localFlowEndpoint { return parts(ep) }
            return (nil, nil)
        }
        return legacyLocal(flow)
    }

    /// Address (or host name) and port of a Network.framework endpoint
    /// (the Swift overlay imports nw_endpoint_t as `Network.NWEndpoint`).
    @available(macOS 15.0, *)
    private static func parts(_ ep: Network.NWEndpoint) -> (String?, Int?) {
        guard case let .hostPort(host, port) = ep else { return (nil, nil) }
        let portNumber = Int(port.rawValue)
        switch host {
        case let .ipv4(address): return (IPAddress(bytes: Array(address.rawValue)).description, portNumber)
        case let .ipv6(address): return (IPAddress(bytes: Array(address.rawValue)).description, portNumber)
        case let .name(name, _): return (name, portNumber)
        @unknown default: return (nil, portNumber)
        }
    }

    // Pre-macOS 15 endpoints (NWHostEndpoint with string hostname/port). These helpers are
    // themselves marked deprecated so the use of the deprecated properties inside them does
    // not warn (build.sh compiles with -warnings-as-errors); they only run on macOS 13/14.
    @available(macOS, deprecated: 15.0)
    private static func legacyRemote(_ flow: NEFilterSocketFlow) -> (String?, Int?) { legacyParts(flow.remoteEndpoint) }

    @available(macOS, deprecated: 15.0)
    private static func legacyLocal(_ flow: NEFilterSocketFlow) -> (String?, Int?) { legacyParts(flow.localEndpoint) }

    @available(macOS, deprecated: 15.0)
    private static func legacyParts(_ endpoint: NSObject?) -> (String?, Int?) {
        guard let host = endpoint as? NWHostEndpoint else { return (nil, nil) }
        return (host.hostname.isEmpty ? nil : host.hostname, Int(host.port))
    }
}
