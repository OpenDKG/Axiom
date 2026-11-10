// AxiomFilter — extracts process identity and endpoints from an NEFilterSocketFlow.
//
// Only metadata is read here; payloads are never inspected.
//
// macOS facts this relies on:
//   * NEFilterFlow.sourceAppIdentifier is iOS-only; on macOS the source process
//     comes from sourceAppAuditToken (an audit_token_t; pid is val.5). The path
//     is resolved with proc_pidpath_audittoken, which is immune to pid reuse,
//     falling back to proc_pidpath.
//   * remoteFlowEndpoint/localFlowEndpoint (nw_endpoint_t) exist from macOS 15;
//     earlier systems use the deprecated NWHostEndpoint properties.
//   * remoteHostname carries the name the app connected by (also on DNS flows
//     to port 53) when macOS knows it.

import Darwin
import Foundation
import Network
import NetworkExtension

struct FlowDescription {
    let pid: Int32
    let path: String?
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
                remotePort: remotePort.flatMap { UInt16(exactly: $0) })
    }
}

enum FlowInspector {
    static func describe(_ flow: NEFilterSocketFlow) -> FlowDescription {
        let (pid, path) = process(flow.sourceAppAuditToken)
        let (remoteText, remotePort) = remoteEndpoint(flow)
        let (localText, localPort) = localEndpoint(flow)

        // Normalise numeric addresses (strip zone ids, unmap ::ffff:a.b.c.d).
        let remoteIP = remoteText.flatMap(IPAddress.init)
        let localIP = localText.flatMap(IPAddress.init)

        var host = flow.remoteHostname
        if host?.isEmpty == true { host = nil }

        return FlowDescription(
            pid: pid,
            path: path,
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

    /// pid and executable path of the app responsible for the flow.
    static func process(_ tokenData: Data?) -> (Int32, String?) {
        guard let tokenData, tokenData.count == MemoryLayout<audit_token_t>.size else { return (-1, nil) }
        var token = tokenData.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        let pid = Int32(bitPattern: token.val.5)

        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4) // PROC_PIDPATHINFO_MAXSIZE
        var length = proc_pidpath_audittoken(&token, &buffer, UInt32(buffer.count))
        if length <= 0 { length = proc_pidpath(pid, &buffer, UInt32(buffer.count)) }
        return (pid, length > 0 ? String(cString: buffer) : nil)
    }

    // MARK: Endpoints

    private static func remoteEndpoint(_ flow: NEFilterSocketFlow) -> (String?, Int?) {
        if #available(macOS 15.0, *) {
            if let ep = flow.remoteFlowEndpoint { return parts(ep) }
            return (nil, nil)
        }
        return legacyParts(flow.remoteEndpoint)
    }

    private static func localEndpoint(_ flow: NEFilterSocketFlow) -> (String?, Int?) {
        if #available(macOS 15.0, *) {
            if let ep = flow.localFlowEndpoint { return parts(ep) }
            return (nil, nil)
        }
        return legacyParts(flow.localEndpoint)
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

    /// Pre-macOS 15 endpoints (NWHostEndpoint with string hostname/port).
    private static func legacyParts(_ endpoint: NSObject?) -> (String?, Int?) {
        guard let host = endpoint as? NWHostEndpoint else { return (nil, nil) }
        return (host.hostname.isEmpty ? nil : host.hostname, Int(host.port))
    }
}
