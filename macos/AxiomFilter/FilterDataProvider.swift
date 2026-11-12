// AxiomFilter — NEFilterDataProvider.
//
// Decides allow/drop for every new TCP/UDP socket flow (inbound and outbound)
// from the daemon-owned rule table, and streams flow.open / flow.stats /
// flow.close events to the daemon.
//
// Verdict path rules:
//   * no file or socket IO, no waiting: rule evaluation works on an immutable
//     snapshot, and events are handed to the EventSink queue asynchronously;
//   * payloads are never inspected: every verdict is final (allow or drop),
//     never filterData. Byte counts come from NEFilterReport statistics
//     (`shouldReport` + `statisticsReportFrequency`), which the system computes.
//
// Lifecycle: on stopFilter the process exits shortly after completing (the
// LuLu pattern) so that an upgraded extension can register its Mach service.
// macOS logs that exit as unexpected; it is intended (see macos/README.md).

import Foundation
import Network
import NetworkExtension
import os

final class FilterDataProvider: NEFilterDataProvider {
    private let log = Logger(subsystem: FilterLog.subsystem, category: "filter")
    private let rules = RuleStore()
    private lazy var events = EventSink { [rules] in
        .hello(ts: Date(), version: FilterDataProvider.version, generation: rules.snapshot().generation)
    }

    /// Review #14: `.medium` statistics reports arrive about once per second per live flow;
    /// forward at most one `flow.stats` per flow per `statsInterval` (the close report
    /// always carries the final counters).
    private static let statsInterval: TimeInterval = 2
    private let lastStats = OSAllocatedUnfairLock<[UUID: Date]>(initialState: [:])

    /// CFBundleShortVersionString of the extension bundle.
    static let version: String =
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "1.0.0"

    // MARK: - Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        log.notice("startFilter: version \(FilterDataProvider.version, privacy: .public)")

        // Rules first (synchronous initial load), so the first verdicts already use them.
        rules.onReload = { [weak self] table in
            guard let self else { return }
            // Tell the daemon which generation is now enforced, then what was rejected.
            self.events.send(.hello(ts: Date(), version: FilterDataProvider.version, generation: table.generation))
            self.events.send(.rules(ts: Date(), generation: table.generation, applied: table.ruleCount,
                                    rejected: table.rejected, error: nil, ruleIds: table.enforcedRuleIds))
        }
        rules.onRejectedFile = { [weak self] reason in
            guard let self else { return }
            let table = self.rules.snapshot()
            self.events.send(.rules(ts: Date(), generation: table.generation, applied: table.ruleCount,
                                    rejected: table.rejected, error: reason, ruleIds: table.enforcedRuleIds))
        }
        rules.start()
        events.start()

        apply(Self.makeSettings()) { [log] error in
            if let error {
                log.error("startFilter: applying settings failed: \(error.localizedDescription, privacy: .public)")
            } else {
                log.notice("startFilter: filter active")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.notice("stopFilter: reason \(reason.rawValue)")
        rules.stop()
        events.stop()
        completionHandler()

        // A system extension is expected to exit once its filter stops; lingering breaks the
        // Mach service registration of an upgraded version. The system relaunches us on demand.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [log] in
            log.notice("stopFilter: exiting")
            exit(0)
        }
    }

    /// Filter all TCP/UDP flows in both directions, plus outbound loopback.
    ///
    /// A rule with a nil remote network does not cover loopback, so outbound loopback
    /// gets its own rules: this attributes connections to local services (for example
    /// the daemon's DNS proxy on 127.0.0.1:53) to the client app. Inbound loopback is
    /// left out because it is the same connection seen from the server side.
    private static func makeSettings() -> NEFilterSettings {
        let filterRules = [
            networkRule("127.0.0.0", 8, .outbound),
            networkRule("::1", 128, .outbound),
            networkRule(nil, 0, .any),
        ].map { NEFilterRule(networkRule: $0, action: .filterData) }
        return NEFilterSettings(rules: filterRules, defaultAction: .allow)
    }

    /// Review #17: nw_endpoint-based initialiser on macOS 15+, NWHostEndpoint on 13/14.
    private static func networkRule(_ network: String?, _ prefix: Int, _ direction: NETrafficDirection) -> NENetworkRule {
        if #available(macOS 15.0, *) {
            let endpoint: Network.NWEndpoint? = network.map { .hostPort(host: Network.NWEndpoint.Host($0), port: 0) }
            return NENetworkRule(remoteNetworkEndpoint: endpoint, remotePrefix: prefix, localNetworkEndpoint: nil,
                                 localPrefix: 0, protocol: .any, direction: direction)
        }
        return legacyNetworkRule(network, prefix, direction)
    }

    // Marked deprecated itself so the deprecated initialiser inside does not warn under
    // -warnings-as-errors; only reached on macOS 13/14.
    @available(macOS, deprecated: 15.0)
    private static func legacyNetworkRule(_ network: String?, _ prefix: Int, _ direction: NETrafficDirection) -> NENetworkRule {
        let endpoint = network.map { NWHostEndpoint(hostname: $0, port: "0") }
        return NENetworkRule(remoteNetwork: endpoint, remotePrefix: prefix, localNetwork: nil,
                             localPrefix: 0, protocol: .any, direction: direction)
    }

    // MARK: - Verdicts

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }

        let info = FlowInspector.describe(socketFlow)
        let decision = rules.snapshot().evaluate(info.key)

        let verdict: NEFilterNewFlowVerdict
        switch decision.action {
        case .block:
            verdict = .drop()
            log.info("block pid=\(info.pid) \(info.path ?? "?", privacy: .public) -> \(info.remoteAddress ?? "?", privacy: .public):\(info.remotePort ?? 0) rule=\(decision.ruleId ?? "-", privacy: .public)")
        case .allow:
            verdict = .allow()
            // Byte counters, computed by the system (no payload access): periodic
            // .statistics reports plus a final .flowClosed report.
            verdict.shouldReport = true
            verdict.statisticsReportFrequency = .medium
        }

        let now = Date()
        events.send(.open(FlowRecord(
            id: flow.identifier,
            ts: now,
            pid: info.pid,
            path: info.path,
            direction: info.direction,
            proto: info.proto,
            localAddress: info.localAddress,
            localPort: info.localPort,
            remoteAddress: info.remoteAddress,
            remotePort: info.remotePort,
            remoteHost: info.remoteHost,
            verdict: decision.action,
            ruleId: decision.ruleId,
            responsiblePid: info.responsiblePid,
            responsiblePath: info.responsiblePath
        )))
        if decision.action == .block {
            // macOS sends no flowClosed report for dropped flows (verified on 15.8), so close
            // them here; otherwise the daemon would track them as open forever.
            events.send(.close(id: flow.identifier, ts: now, bytesIn: 0, bytesOut: 0))
        }
        return verdict
    }

    // MARK: - Reports (byte counts)

    override func handle(_ report: NEFilterReport) {
        guard let flow = report.flow else { return }
        let bytesIn = UInt64(report.bytesInboundCount)
        let bytesOut = UInt64(report.bytesOutboundCount)
        let now = Date()
        switch report.event {
        case .statistics:
            let forward = lastStats.withLock { map -> Bool in
                if let last = map[flow.identifier], now.timeIntervalSince(last) < Self.statsInterval { return false }
                map[flow.identifier] = now
                if map.count > 8192 { // safety net: forget flows whose close we never saw
                    let cutoff = now.addingTimeInterval(-60)
                    map = map.filter { $0.value > cutoff }
                }
                return true
            }
            if forward { events.send(.stats(id: flow.identifier, ts: now, bytesIn: bytesIn, bytesOut: bytesOut)) }
        case .flowClosed:
            lastStats.withLock { _ = $0.removeValue(forKey: flow.identifier) }
            events.send(.close(id: flow.identifier, ts: now, bytesIn: bytesIn, bytesOut: bytesOut))
        default:
            break // newFlow / dataDecision: flow.open is emitted from handleNewFlow
        }
    }
}
