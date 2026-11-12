// AxiomFilter — compiled rule table.
//
// Parses /Library/Application Support/Axiom/filter/rules.json (contract:
// docs/MACOS_ARCHITECTURE.md §3.1) into an immutable table that the verdict
// path can evaluate without allocation-heavy work or locking.
//
// Semantics (Windows Firewall compatible):
//   * an enabled matching `block` rule wins over any `allow` rule;
//   * otherwise an enabled matching `allow` rule is reported as the deciding rule;
//   * with no match, traffic is allowed (default allow).
//
// This file is deliberately free of NetworkExtension imports so it can be
// compiled into the stand-alone rule test runner (`build.sh test`).

import Darwin
import Foundation

/// Logging subsystem shared by all extension components.
enum FilterLog {
    static let subsystem = "com.axiom.firewall.filter"
}

// MARK: - Flow-side value types

/// Initial direction of a flow, as seen from this Mac.
enum FlowDirection: String {
    case inbound
    case outbound
}

/// Transport protocol of a flow.
enum FlowProtocol: String {
    case tcp
    case udp
    case icmp
    case other

    /// Maps a BSD socket protocol number (`IPPROTO_*`) to a flow protocol.
    init(socketProtocol: Int32) {
        switch socketProtocol {
        case IPPROTO_TCP: self = .tcp
        case IPPROTO_UDP: self = .udp
        case IPPROTO_ICMP, IPPROTO_ICMPV6: self = .icmp
        default: self = .other
        }
    }
}

/// Case-insensitive path comparison (APFS/HFS+ system volumes are case-insensitive).
///
/// Paths are compared on their Unicode-lowercased form, which is what `strncasecmp`
/// semantics mean for ASCII and is good enough for bundle paths. Callers resolve
/// symlinks (`realpath`) before folding so that `/var/...` and `/private/var/...` agree.
enum PathMatch {
    static func fold(_ path: String) -> String { path.lowercased() }

    /// Resolves symlinks when the path exists; otherwise returns it unchanged
    /// (a rule may name an app that is not installed yet).
    static func resolve(_ path: String) -> String {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard realpath(path, &buffer) != nil else { return path }
        return String(cString: buffer)
    }

    /// Exact executable match, or any executable inside a directory/bundle (prefix + "/").
    /// Both arguments must already be folded.
    static func matches(rule folded: String, candidate: String) -> Bool {
        candidate == folded || candidate.hasPrefix(folded + "/")
    }
}

/// The attributes of a flow that rules can match on.
struct FlowKey {
    /// Executable path of the socket-owning process (nil when it could not be resolved).
    var appPath: String?
    var direction: FlowDirection
    var proto: FlowProtocol
    /// Remote IP address (nil when the remote endpoint is not an IP address).
    var remoteAddress: IPAddress?
    /// Remote port (nil when unknown / not applicable).
    var remotePort: UInt16?
    /// Executable path of the responsible process (the app that launched a helper such as
    /// `sh -c curl` or a WebKit networking process), when it differs from `appPath`.
    var responsiblePath: String?

    /// Folded candidate paths for app matching: the socket owner and the responsible app.
    /// Computed once per flow so the per-rule comparison does no case conversion.
    let foldedPaths: [String]

    init(appPath: String?, direction: FlowDirection, proto: FlowProtocol, remoteAddress: IPAddress?,
         remotePort: UInt16?, responsiblePath: String? = nil) {
        self.appPath = appPath
        self.direction = direction
        self.proto = proto
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.responsiblePath = responsiblePath
        var folded: [String] = []
        if let appPath { folded.append(PathMatch.fold(appPath)) }
        if let responsiblePath, responsiblePath != appPath { folded.append(PathMatch.fold(responsiblePath)) }
        self.foldedPaths = folded
    }
}

// MARK: - IP addresses and address matchers

/// An IPv4 (4 bytes) or IPv6 (16 bytes) address. IPv4-mapped IPv6 addresses
/// (`::ffff:a.b.c.d`) are normalised to plain IPv4 so rules written with IPv4
/// literals also match dual-stack sockets.
struct IPAddress: Equatable, CustomStringConvertible {
    let bytes: [UInt8]

    init(bytes: [UInt8]) {
        if bytes.count == 16, bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xff, bytes[11] == 0xff {
            self.bytes = Array(bytes[12..<16])
        } else {
            self.bytes = bytes
        }
    }

    /// Parses a numeric IPv4/IPv6 literal. Accepts `[v6]` brackets and strips `%zone` suffixes.
    init?(_ text: String) {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("["), s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        if let zone = s.firstIndex(of: "%") { s = String(s[..<zone]) }
        if s.isEmpty { return nil }

        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 {
            self.init(bytes: withUnsafeBytes(of: &v4) { Array($0) })
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, s, &v6) == 1 {
            self.init(bytes: withUnsafeBytes(of: &v6) { Array($0) })
            return
        }
        return nil
    }

    var isIPv4: Bool { bytes.count == 4 }

    /// 127.0.0.0/8 or ::1 (IPv4-mapped loopback was already normalised to IPv4).
    var isLoopback: Bool {
        if bytes.count == 4 { return bytes[0] == 127 }
        return bytes.count == 16 && bytes[0..<15].allSatisfy({ $0 == 0 }) && bytes[15] == 1
    }

    /// Canonical textual form (inet_ntop).
    var description: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let family = isIPv4 ? AF_INET : AF_INET6
        let ok = bytes.withUnsafeBytes { raw in
            inet_ntop(family, raw.baseAddress, &buffer, socklen_t(buffer.count)) != nil
        }
        return ok ? String(cString: buffer) : "?"
    }
}

/// One entry of a rule's `remoteAddresses` list.
enum AddressMatcher: Equatable {
    /// `network/prefix` (a bare IP is a /32 or /128).
    case cidr(network: [UInt8], prefix: Int)
    /// Inclusive range `first-last` (Windows Firewall syntax), same family on both ends.
    case range(first: [UInt8], last: [UInt8])

    /// Parses `1.2.3.4`, `10.0.0.0/8`, `2001:db8::/32` or `1.2.3.4-1.2.3.9`.
    init?(_ text: String) {
        let s = text.trimmingCharacters(in: .whitespaces)
        if let slash = s.firstIndex(of: "/") {
            guard let address = IPAddress(String(s[..<slash])),
                  var prefix = Int(s[s.index(after: slash)...]) else { return nil }
            // An IPv4-mapped IPv6 network ("::ffff:10.0.0.0/104") was normalised to IPv4.
            let rawIsV6 = s[..<slash].contains(":")
            if rawIsV6, address.isIPv4 { prefix -= 96 }
            let bits = address.bytes.count * 8
            guard prefix >= 0, prefix <= bits else { return nil }
            self = .cidr(network: AddressMatcher.mask(address.bytes, prefix: prefix), prefix: prefix)
            return
        }
        // A '-' range. IPv6 literals never contain '-', so splitting is unambiguous.
        if let dash = s.firstIndex(of: "-") {
            guard let first = IPAddress(String(s[..<dash])),
                  let last = IPAddress(String(s[s.index(after: dash)...])),
                  first.bytes.count == last.bytes.count,
                  !AddressMatcher.less(last.bytes, first.bytes) else { return nil }
            self = .range(first: first.bytes, last: last.bytes)
            return
        }
        guard let address = IPAddress(s) else { return nil }
        self = .cidr(network: address.bytes, prefix: address.bytes.count * 8)
    }

    /// True when the entry explicitly names loopback (its first address is a loopback
    /// address). `0.0.0.0/0` or `::/0` do not count: they cover loopback only implicitly.
    var namesLoopback: Bool {
        switch self {
        case let .cidr(network, prefix):
            let first = IPAddress(bytes: network)
            return first.isLoopback && prefix >= (first.isIPv4 ? 8 : 128)
        case let .range(first, _):
            return IPAddress(bytes: first).isLoopback
        }
    }

    func contains(_ address: IPAddress) -> Bool {
        let a = address.bytes
        switch self {
        case let .cidr(network, prefix):
            guard a.count == network.count else { return false }
            return AddressMatcher.mask(a, prefix: prefix) == network
        case let .range(first, last):
            guard a.count == first.count else { return false }
            return !AddressMatcher.less(a, first) && !AddressMatcher.less(last, a)
        }
    }

    /// Zeroes every bit after the first `prefix` bits.
    static func mask(_ bytes: [UInt8], prefix: Int) -> [UInt8] {
        var out = bytes
        for i in 0..<out.count {
            let bitsLeft = prefix - i * 8
            if bitsLeft >= 8 { continue }
            out[i] = bitsLeft <= 0 ? 0 : out[i] & UInt8(truncatingIfNeeded: 0xff << (8 - bitsLeft))
        }
        return out
    }

    /// Big-endian lexicographic comparison of equal-length byte arrays.
    static func less(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x < y }
        return false
    }
}

// MARK: - Ports

/// A set of port ranges parsed from `"80,443,1000-2000"`.
struct PortSet: Equatable {
    let ranges: [ClosedRange<UInt16>]

    /// Returns nil for an unparsable specification. `"*"`/`"any"` must be handled by the caller.
    init?(_ text: String) {
        var ranges: [ClosedRange<UInt16>] = []
        for token in text.split(separator: ",") {
            let t = token.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            let parts = t.split(separator: "-", omittingEmptySubsequences: false)
            switch parts.count {
            case 1:
                guard let p = UInt16(parts[0].trimmingCharacters(in: .whitespaces)) else { return nil }
                ranges.append(p...p)
            case 2:
                guard let lo = UInt16(parts[0].trimmingCharacters(in: .whitespaces)),
                      let hi = UInt16(parts[1].trimmingCharacters(in: .whitespaces)), lo <= hi else { return nil }
                ranges.append(lo...hi)
            default:
                return nil
            }
        }
        if ranges.isEmpty { return nil }
        self.ranges = ranges
    }

    func contains(_ port: UInt16) -> Bool { ranges.contains { $0.contains(port) } }
}

// MARK: - Rules

enum RuleAction: String {
    case allow
    case block
}

/// A validated, enabled rule ready for matching.
struct CompiledRule {
    let id: String
    let action: RuleAction
    /// nil = any app. Otherwise the resolved (realpath) rule path, matched exactly or as a
    /// directory/bundle prefix, case-insensitively, against the socket owner *and* the
    /// responsible process of a flow (either match counts).
    let appPath: String?
    /// `appPath` case-folded for comparison.
    let foldedAppPath: String?
    /// Directions this rule applies to.
    let inbound: Bool
    let outbound: Bool
    /// nil = any protocol.
    let proto: FlowProtocol?
    /// nil = any remote address.
    let addresses: [AddressMatcher]?
    /// nil = any remote port.
    let ports: PortSet?
    /// True when `remoteAddresses` explicitly names a loopback address. Only such rules
    /// apply to loopback flows (a "block app X" rule must not cut X off from local
    /// services such as the Privacy Shield resolver on 127.0.0.1:53).
    let coversLoopback: Bool

    init(id: String, action: RuleAction, appPath: String?, inbound: Bool, outbound: Bool, proto: FlowProtocol?,
         addresses: [AddressMatcher]?, ports: PortSet?) {
        self.id = id
        self.action = action
        self.appPath = appPath
        self.foldedAppPath = appPath.map(PathMatch.fold)
        self.inbound = inbound
        self.outbound = outbound
        self.proto = proto
        self.addresses = addresses
        self.ports = ports
        self.coversLoopback = addresses?.contains(where: \.namesLoopback) ?? false
    }

    func matches(_ flow: FlowKey) -> Bool {
        switch flow.direction {
        case .inbound where !inbound: return false
        case .outbound where !outbound: return false
        default: break
        }
        if let proto, proto != flow.proto { return false }
        if let foldedAppPath {
            guard flow.foldedPaths.contains(where: { PathMatch.matches(rule: foldedAppPath, candidate: $0) }) else {
                return false
            }
        }
        if let remote = flow.remoteAddress, remote.isLoopback, !coversLoopback { return false }
        if let addresses {
            guard let remote = flow.remoteAddress, addresses.contains(where: { $0.contains(remote) }) else { return false }
        }
        if let ports {
            guard let port = flow.remotePort, ports.contains(port) else { return false }
        }
        return true
    }
}

/// Result of evaluating a flow against the table.
struct RuleDecision {
    let action: RuleAction
    /// Id of the deciding rule; nil when the default (allow) applied.
    let ruleId: String?
}

/// Errors that make a whole rules file unusable (the last good table is kept).
enum RuleLoadError: Error, CustomStringConvertible {
    case unreadable(String)
    case invalidJSON(String)
    case unsupportedSchema(Any?)
    case badShape(String)

    var description: String {
        switch self {
        case let .unreadable(m): return "unreadable: \(m)"
        case let .invalidJSON(m): return "invalid JSON: \(m)"
        case let .unsupportedSchema(v): return "unsupported schemaVersion \(String(describing: v))"
        case let .badShape(m): return "bad document shape: \(m)"
        }
    }
}

/// A rule that was present in the file but is not enforced, with the reason.
/// Reported to the daemon in the `filter.rules` event (§3.2) so the UI can show it.
struct RejectedRule: Equatable {
    /// The rule's `id`, or `#<index>` when it had none.
    let id: String
    let reason: String
}

/// Immutable snapshot of the active rules. Shared by reference between the
/// verdict path and the loader; never mutated after construction.
final class RuleTable: @unchecked Sendable {
    static let supportedSchemaVersion = 1

    /// `generation` from the file; -1 for the built-in empty table used before any file loaded.
    let generation: Int64
    let failOpen: Bool
    let blockRules: [CompiledRule]
    let allowRules: [CompiledRule]
    /// Rules that were skipped (invalid), with the reason. Disabled rules are not listed.
    let rejected: [RejectedRule]

    init(generation: Int64, failOpen: Bool, blockRules: [CompiledRule], allowRules: [CompiledRule],
         rejected: [RejectedRule]) {
        self.generation = generation
        self.failOpen = failOpen
        self.blockRules = blockRules
        self.allowRules = allowRules
        self.rejected = rejected
    }

    /// Table used before any rules file has loaded: allow everything (fail-open).
    static let empty = RuleTable(generation: -1, failOpen: true, blockRules: [], allowRules: [], rejected: [])

    var ruleCount: Int { blockRules.count + allowRules.count }

    /// Upper bound on the ids echoed in `filter.rules` (`ruleIds`): the daemon reads events as
    /// lines of at most 16 KiB, so a larger table reports no list ("unknown") instead.
    static let maxEchoedRuleIds = 200

    /// Ids of the enabled, compiled rules in force (`ruleIds` of `filter.rules`); nil above the cap.
    var enforcedRuleIds: [String]? {
        guard ruleCount <= RuleTable.maxEchoedRuleIds else { return nil }
        return (blockRules + allowRules).map { $0.id }
    }

    /// Human-readable problems with individual rules that were skipped (log lines).
    var warnings: [String] { rejected.map { "rule \($0.id): \($0.reason) (skipped)" } }

    /// Block wins; then allow; then default allow.
    func evaluate(_ flow: FlowKey) -> RuleDecision {
        if let rule = blockRules.first(where: { $0.matches(flow) }) {
            return RuleDecision(action: .block, ruleId: rule.id)
        }
        if let rule = allowRules.first(where: { $0.matches(flow) }) {
            return RuleDecision(action: .allow, ruleId: rule.id)
        }
        return RuleDecision(action: .allow, ruleId: nil)
    }

    // MARK: Parsing

    /// Parses a rules.json document. Throws only for document-level problems;
    /// individual invalid rules are skipped and listed in `rejected`.
    /// `resolvePath` canonicalises rule `appPath`s (realpath by default; tests inject their own).
    static func parse(_ data: Data, resolvePath: (String) -> String = PathMatch.resolve) throws -> RuleTable {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw RuleLoadError.invalidJSON(error.localizedDescription)
        }
        guard let root = object as? [String: Any] else { throw RuleLoadError.badShape("root is not an object") }
        guard let schema = int64(root["schemaVersion"]), schema == Int64(supportedSchemaVersion) else {
            throw RuleLoadError.unsupportedSchema(root["schemaVersion"])
        }
        let generation = int64(root["generation"]) ?? 0
        let failOpen = (root["failOpen"] as? Bool) ?? true
        let rawRules: [Any]
        switch root["rules"] {
        case nil, is NSNull: rawRules = []
        case let list as [Any]: rawRules = list
        default: throw RuleLoadError.badShape("rules is not an array")
        }

        var blocks: [CompiledRule] = []
        var allows: [CompiledRule] = []
        var rejected: [RejectedRule] = []
        for (index, raw) in rawRules.enumerated() {
            guard let dict = raw as? [String: Any] else {
                rejected.append(RejectedRule(id: "#\(index)", reason: "not an object"))
                continue
            }
            switch compile(dict, resolvePath: resolvePath) {
            case .success(nil):
                continue // disabled
            case let .success(rule?):
                if rule.action == .block { blocks.append(rule) } else { allows.append(rule) }
            case let .failure(problem):
                let id = (dict["id"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "#\(index)"
                rejected.append(RejectedRule(id: id, reason: problem.message))
            }
        }
        return RuleTable(generation: generation, failOpen: failOpen, blockRules: blocks, allowRules: allows,
                         rejected: rejected)
    }

    struct RuleProblem: Error { let message: String }

    /// Compiles one rule object. Returns `.success(nil)` for a disabled rule.
    static func compile(_ dict: [String: Any],
                        resolvePath: (String) -> String = PathMatch.resolve) -> Result<CompiledRule?, RuleProblem> {
        if let enabled = dict["enabled"] as? Bool, !enabled { return .success(nil) }

        let id = (dict["id"] as? String) ?? ""

        guard let actionText = (dict["action"] as? String)?.lowercased(),
              let action = RuleAction(rawValue: actionText) else {
            return .failure(RuleProblem(message: "missing/unknown action \(String(describing: dict["action"]))"))
        }

        // direction: outbound | inbound (also tolerates any/both, which the contract does not emit).
        let inbound: Bool, outbound: Bool
        switch (dict["direction"] as? String)?.lowercased() {
        case "outbound"?, "out"?: (inbound, outbound) = (false, true)
        case "inbound"?, "in"?: (inbound, outbound) = (true, false)
        case "any"?, "both"?, nil: (inbound, outbound) = (true, true)
        case let other: return .failure(RuleProblem(message: "unknown direction \(other ?? "")"))
        }

        let proto: FlowProtocol?
        switch (dict["protocol"] as? String)?.lowercased() {
        case nil, "any"?, ""?, "*"?: proto = nil
        case "tcp"?: proto = .tcp
        case "udp"?: proto = .udp
        case "icmp"?, "icmpv4"?, "icmpv6"?: proto = .icmp // socket filter rarely sees ICMP: effectively unfiltered
        case let other: return .failure(RuleProblem(message: "unknown protocol \(other ?? "")"))
        }

        // appPath: "" or "*" = any app; trailing slashes are ignored; symlinks resolved when
        // the path exists (so "/var/..." and "/private/var/..." compare equal).
        var appPath: String? = nil
        if let p = dict["appPath"] as? String {
            var trimmed = p.trimmingCharacters(in: .whitespaces)
            while trimmed.count > 1, trimmed.hasSuffix("/") { trimmed.removeLast() }
            if !trimmed.isEmpty, trimmed != "*" {
                guard trimmed.hasPrefix("/") else {
                    return .failure(RuleProblem(message: "appPath is not absolute: \(trimmed)"))
                }
                appPath = resolvePath(trimmed)
            }
        }

        // remoteAddresses: empty/absent or containing "*" = any.
        var addresses: [AddressMatcher]? = nil
        if let list = dict["remoteAddresses"] as? [Any], !list.isEmpty {
            var matchers: [AddressMatcher] = []
            var anyToken = false
            for entry in list {
                guard let text = (entry as? String)?.trimmingCharacters(in: .whitespaces) else { continue }
                if text == "*" || text.lowercased() == "any" { anyToken = true; break }
                if let m = AddressMatcher(text) { matchers.append(m) }
            }
            if !anyToken {
                // A rule whose every address is invalid must not silently widen to "any".
                guard !matchers.isEmpty else {
                    return .failure(RuleProblem(message: "no valid remoteAddresses in \(list)"))
                }
                addresses = matchers
            }
        } else if let single = dict["remoteAddresses"] as? String {
            let t = single.trimmingCharacters(in: .whitespaces)
            if !t.isEmpty, t != "*" {
                let matchers = t.split(separator: ",").compactMap { AddressMatcher(String($0)) }
                guard !matchers.isEmpty else { return .failure(RuleProblem(message: "invalid remoteAddresses \(t)")) }
                addresses = matchers
            }
        }

        // remotePorts: null/empty/"*"/"any" = any. Numbers and arrays are tolerated.
        var ports: PortSet? = nil
        var portText: String? = nil
        switch dict["remotePorts"] {
        case let s as String: portText = s
        case let n as NSNumber: portText = n.stringValue
        case let list as [Any]: portText = list.map { "\($0)" }.joined(separator: ",")
        default: break
        }
        if let t = portText?.trimmingCharacters(in: .whitespaces), !t.isEmpty, t != "*", t.lowercased() != "any" {
            guard let set = PortSet(t) else { return .failure(RuleProblem(message: "invalid remotePorts \(t)")) }
            ports = set
        }

        return .success(CompiledRule(id: id, action: action, appPath: appPath, inbound: inbound, outbound: outbound,
                                     proto: proto, addresses: addresses, ports: ports))
    }

    private static func int64(_ value: Any?) -> Int64? {
        switch value {
        case let n as NSNumber: return n.int64Value
        case let s as String: return Int64(s)
        default: return nil
        }
    }
}
