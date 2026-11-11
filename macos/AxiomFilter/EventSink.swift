// AxiomFilter — flow event stream to the daemon.
//
// Contract (docs/MACOS_ARCHITECTURE.md §3.2): newline-delimited JSON over the
// Unix stream socket /var/run/axiom/filter.sock, where the daemon listens.
// The filter is the client:
//   * reconnects every 2 s while the daemon is down;
//   * never blocks a verdict: callers only enqueue onto a private serial queue,
//     and even that hop is bounded (review #14): at most `maxInflight` events may
//     be waiting for the sink queue; beyond that `send` drops the event and counts it;
//   * keeps a bounded in-memory backlog (`EventQueue`) and drops the oldest lines when full;
//   * sends `filter.hello` first on every new connection (and again after each
//     rules reload, followed by `filter.rules`); both carry the total `dropped` count.
//
// All socket IO is non-blocking and driven by dispatch sources on `queue`.
// EventQueue and the encoder have no NetworkExtension dependency so this file is
// compiled into the unit test runner (`build.sh test`).

import Darwin
import Foundation
import os

/// One event destined for the daemon. JSON is produced on the sink queue, not
/// on the verdict path.
enum FilterEvent {
    case open(FlowRecord)
    case stats(id: UUID, ts: Date, bytesIn: UInt64, bytesOut: UInt64)
    case close(id: UUID, ts: Date, bytesIn: UInt64, bytesOut: UInt64)
    case hello(ts: Date, version: String, generation: Int64)
    /// Outcome of a rules reload: `applied` rules enforced, `rejected` skipped.
    /// `error` is set (and the counts describe the table still in force) when the file
    /// as a whole was rejected.
    case rules(ts: Date, generation: Int64, applied: Int, rejected: [RejectedRule], error: String?)
}

/// Everything flow.open carries. Built on the verdict path from cheap values.
struct FlowRecord {
    let id: UUID
    let ts: Date
    let pid: Int32
    let path: String?
    let direction: FlowDirection
    let proto: FlowProtocol
    let localAddress: String?
    let localPort: Int?
    let remoteAddress: String?
    let remotePort: Int?
    let remoteHost: String?
    let verdict: RuleAction
    let ruleId: String?
    /// Responsible process (review #12) when it differs from `pid`/`path`; nil otherwise.
    var responsiblePid: Int32? = nil
    var responsiblePath: String? = nil
}

/// Bounded FIFO of encoded lines with drop-oldest semantics that never breaks a line
/// that is partially on the wire. Not thread-safe: owned by the sink queue (or a test).
final class EventQueue {
    let maxLines: Int
    let maxBytes: Int

    /// `lines[head...]` are unsent; `headOffset` bytes of `lines[head]` were already written.
    private(set) var lines: [Data] = []
    private(set) var head = 0
    private(set) var headOffset = 0
    private(set) var pendingBytes = 0
    /// Lines dropped because the queue was full.
    private(set) var dropped: UInt64 = 0

    init(maxLines: Int = 20_000, maxBytes: Int = 8 * 1024 * 1024) {
        self.maxLines = maxLines
        self.maxBytes = maxBytes
    }

    var pendingCount: Int { lines.count - head }
    var isEmpty: Bool { head >= lines.count }
    /// The line at the head and how much of it was already written.
    var current: (line: Data, offset: Int)? { isEmpty ? nil : (lines[head], headOffset) }

    func enqueue(_ line: Data, atFront: Bool = false) {
        if atFront {
            // Only used right after connecting, when nothing has been partially written.
            if head > 0 { head -= 1; lines[head] = line } else { lines.insert(line, at: 0) }
        } else {
            lines.append(line)
        }
        pendingBytes += line.count
        // The head line is protected while it is partially written, or when it is the hello
        // that was just inserted for a new connection (it must precede everything else).
        let protectHead = atFront || headOffset != 0
        while pendingCount > maxLines || pendingBytes > maxBytes {
            if !protectHead {
                // Drop the oldest line: O(1), just advance the head.
                pendingBytes -= lines[head].count
                lines[head] = Data()
                head += 1
            } else {
                // Drop the second-oldest instead by moving the protected line one slot forward
                // (a partially written line must be finished to keep framing).
                guard head + 1 < lines.count else { break }
                pendingBytes -= lines[head + 1].count
                lines[head + 1] = lines[head]
                lines[head] = Data()
                head += 1
            }
            dropped += 1
        }
        compact()
    }

    /// Records that `n` more bytes of the head line were written.
    func advance(by n: Int) {
        guard let cur = current else { return }
        headOffset = cur.offset + n
        if headOffset >= cur.line.count {
            pendingBytes -= cur.line.count
            lines[head] = Data() // release memory before compaction
            head += 1
            headOffset = 0
        }
    }

    /// A line cut by a lost connection is re-sent whole on the next one.
    func restartHeadLine() { headOffset = 0 }

    /// Reclaims the consumed prefix of `lines` occasionally (amortised O(1)).
    func compact() {
        if head == lines.count { lines.removeAll(keepingCapacity: true); head = 0; return }
        if head > 1024, head * 2 > lines.count {
            lines.removeFirst(head)
            head = 0
        }
    }
}

final class EventSink: @unchecked Sendable {
    static let defaultSocketPath = "/var/run/axiom/filter.sock"

    private let reconnectInterval: DispatchTimeInterval = .seconds(2)

    private let socketPath: String
    private let trustedPeerUid: uid_t
    private let queue = DispatchQueue(label: "com.axiom.firewall.filter.events", qos: .utility)
    private let log = Logger(subsystem: FilterLog.subsystem, category: "events")

    /// Supplies the current hello event (version + applied generation).
    private let helloProvider: () -> FilterEvent

    /// Review #14: events waiting for the sink queue (incremented before `queue.async`).
    private let inflight = OSAllocatedUnfairLock<Int>(initialState: 0)
    private let maxInflight: Int
    private let droppedInflight = OSAllocatedUnfairLock<UInt64>(initialState: 0)

    // State below is only touched on `queue`.
    private var fd: Int32 = -1
    private var connected = false
    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private var writeSourceActive = false
    private var reconnectTimer: DispatchSourceTimer?
    private var running = false
    private let backlog: EventQueue
    private var loggedDrops: UInt64 = 0

    private let timestampFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    init(socketPath: String = EventSink.defaultSocketPath, trustedPeerUid: uid_t = 0, maxInflight: Int = 4096,
         maxLines: Int = 20_000, maxBytes: Int = 8 * 1024 * 1024, helloProvider: @escaping () -> FilterEvent) {
        self.socketPath = socketPath
        self.trustedPeerUid = trustedPeerUid
        self.maxInflight = maxInflight
        self.backlog = EventQueue(maxLines: maxLines, maxBytes: maxBytes)
        self.helloProvider = helloProvider
    }

    // MARK: - Public API (any thread, never blocks)

    func start() {
        queue.async {
            guard !self.running else { return }
            self.running = true
            self.connect()
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + self.reconnectInterval, repeating: self.reconnectInterval,
                           leeway: .milliseconds(200))
            timer.setEventHandler { [weak self] in
                guard let self, self.running, self.fd < 0 else { return }
                self.connect()
            }
            timer.resume()
            self.reconnectTimer = timer
        }
    }

    /// Stops reconnecting and closes the socket. Unsent events are discarded.
    func stop() {
        queue.sync {
            running = false
            reconnectTimer?.cancel()
            reconnectTimer = nil
            // Best effort: push whatever the kernel buffer accepts right now.
            if connected { flush() }
            disconnect(reason: "stopping")
        }
    }

    /// Enqueues an event. Safe from the verdict path: one bounded async hop, no IO.
    /// Returns false when the event was dropped because too many are already in flight.
    @discardableResult
    func send(_ event: FilterEvent) -> Bool {
        let admitted = inflight.withLock { count -> Bool in
            guard count < maxInflight else { return false }
            count += 1
            return true
        }
        guard admitted else {
            droppedInflight.withLock { $0 += 1 }
            return false
        }
        queue.async {
            self.inflight.withLock { $0 -= 1 }
            guard let line = self.encode(event) else { return }
            self.backlog.enqueue(line)
            self.noteDrops()
            if self.connected { self.flush() }
        }
        return true
    }

    /// Total events dropped so far (backlog overflow + in-flight limit). Any thread.
    var droppedTotal: UInt64 {
        droppedInflight.withLock { $0 } + queue.sync { backlog.dropped }
    }

    // MARK: - Test hooks (no-ops in production use)

    /// Parks the sink queue until `gate` is signalled, so tests can fill the in-flight window.
    func testHoldQueue(until gate: DispatchSemaphore) { queue.async { gate.wait() } }
    /// Waits until everything queued so far has been processed.
    func testDrain() { queue.sync {} }
    /// Encodes one event the way it would go on the wire (one JSON line with '\n').
    func testEncode(_ event: FilterEvent) -> Data? { queue.sync { encode(event) } }

    // MARK: - Encoding

    private func encode(_ event: FilterEvent) -> Data? {
        let null = NSNull()
        let object: [String: Any]
        switch event {
        case let .open(r):
            object = [
                "type": "flow.open",
                "id": r.id.uuidString.lowercased(),
                "ts": timestampFormatter.string(from: r.ts),
                "pid": Int(r.pid),
                "path": r.path ?? null,
                "direction": r.direction.rawValue,
                "protocol": r.proto.rawValue,
                "localAddress": r.localAddress ?? null,
                "localPort": r.localPort ?? null,
                "remoteAddress": r.remoteAddress ?? null,
                "remotePort": r.remotePort ?? null,
                "remoteHost": r.remoteHost ?? null,
                "verdict": r.verdict.rawValue,
                "ruleId": r.ruleId ?? null,
                "responsiblePid": r.responsiblePid.map { Int($0) } ?? null,
                "responsiblePath": r.responsiblePath ?? null,
            ]
        case let .stats(id, ts, bytesIn, bytesOut):
            object = ["type": "flow.stats", "id": id.uuidString.lowercased(), "ts": timestampFormatter.string(from: ts),
                      "bytesIn": bytesIn, "bytesOut": bytesOut]
        case let .close(id, ts, bytesIn, bytesOut):
            object = ["type": "flow.close", "id": id.uuidString.lowercased(), "ts": timestampFormatter.string(from: ts),
                      "bytesIn": bytesIn, "bytesOut": bytesOut]
        case let .hello(ts, version, generation):
            object = ["type": "filter.hello", "ts": timestampFormatter.string(from: ts), "version": version,
                      "generation": generation, "dropped": totalDroppedOnQueue()]
        case let .rules(ts, generation, applied, rejected, error):
            object = ["type": "filter.rules", "ts": timestampFormatter.string(from: ts), "generation": generation,
                      "applied": applied,
                      "rejected": rejected.map { ["id": $0.id, "reason": $0.reason] },
                      "error": error ?? null, "dropped": totalDroppedOnQueue()]
        }
        guard var data = try? JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]) else {
            return nil
        }
        data.append(0x0a) // '\n'
        return data
    }

    /// `droppedTotal` for use on the sink queue (no queue.sync).
    private func totalDroppedOnQueue() -> UInt64 { droppedInflight.withLock { $0 } + backlog.dropped }

    private func noteDrops() {
        let total = totalDroppedOnQueue()
        if total > loggedDrops, (loggedDrops == 0 || total / 1000 > loggedDrops / 1000) {
            log.error("event queue full: dropped \(total) events so far (backlog \(self.backlog.dropped), in-flight limit \(self.droppedInflight.withLock { $0 }))")
            loggedDrops = total
        }
    }

    // MARK: - Connection management

    private func connect() {
        guard running, fd < 0 else { return }
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return }
        _ = fcntl(s, F_SETFD, FD_CLOEXEC)
        _ = fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
        var one: Int32 = 1
        _ = setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < capacity else { close(s); return }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
            raw[pathBytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0, errno != EINPROGRESS {
            // ENOENT / ECONNREFUSED while the daemon is down is normal: retry on the timer, quietly.
            close(s)
            return
        }
        fd = s
        installSources()
        if rc == 0 { didConnect() } else { resumeWriteSource() } // completes when writable
    }

    private func installSources() {
        let fd = self.fd
        // Read side: the daemon does not talk to us; reading only detects EOF/hang-up promptly.
        let r = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        r.setEventHandler { [weak self] in self?.drainReadable() }
        r.resume()
        readSource = r

        let w = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
        w.setEventHandler { [weak self] in
            guard let self else { return }
            if !self.connected {
                var err: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
                if err != 0 { self.disconnect(reason: "connect failed errno=\(err)"); return }
                self.didConnect()
            } else {
                self.flush()
            }
        }
        // Dispatch sources start suspended; the write source is resumed only while there is backlog.
        writeSource = w
        writeSourceActive = false
        // Keep the fd alive until both sources are cancelled.
        let closer = DispatchGroup()
        closer.enter(); closer.enter()
        r.setCancelHandler { closer.leave() }
        w.setCancelHandler { closer.leave() }
        closer.notify(queue: queue) { close(fd) }
    }

    private func didConnect() {
        // Only a root-owned listener may receive per-process flow data.
        var uid: uid_t = 0, gid: gid_t = 0
        if getpeereid(fd, &uid, &gid) != 0 || uid != trustedPeerUid {
            log.error("refusing filter socket peer with uid \(uid) (expected \(self.trustedPeerUid))")
            disconnect(reason: "untrusted peer")
            return
        }
        connected = true
        backlog.restartHeadLine() // a line cut by a previous connection is re-sent whole
        if let hello = encode(helloProvider()) { backlog.enqueue(hello, atFront: true) }
        log.notice("connected to daemon at \(self.socketPath, privacy: .public), \(self.backlog.pendingCount) events pending")
        flush()
    }

    private func disconnect(reason: String) {
        guard fd >= 0 else { return }
        if connected { log.notice("daemon connection closed: \(reason, privacy: .public)") }
        connected = false
        if let w = writeSource {
            if !writeSourceActive { w.resume() } // a suspended source cannot be cancelled cleanly
            w.cancel()
        }
        readSource?.cancel()
        writeSource = nil
        readSource = nil
        writeSourceActive = false
        fd = -1
        backlog.restartHeadLine()
    }

    private func drainReadable() {
        var buffer = [UInt8](repeating: 0, count: 512)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n > 0 { continue }
            if n == 0 { disconnect(reason: "EOF"); return }
            if errno == EAGAIN || errno == EINTR { return }
            disconnect(reason: "read errno=\(errno)")
            return
        }
    }

    // MARK: - Writing

    private func resumeWriteSource() {
        if let w = writeSource, !writeSourceActive { w.resume(); writeSourceActive = true }
    }

    private func suspendWriteSource() {
        if let w = writeSource, writeSourceActive { w.suspend(); writeSourceActive = false }
    }

    /// Writes as much backlog as the socket accepts without blocking.
    private func flush() {
        guard connected else { return }
        while let cur = backlog.current {
            let (line, offset) = cur
            let n = line.withUnsafeBytes { raw -> Int in
                write(fd, raw.baseAddress!.advanced(by: offset), line.count - offset)
            }
            if n > 0 {
                backlog.advance(by: n)
                continue
            }
            if n < 0, errno == EINTR { continue }
            if n < 0, errno == EAGAIN {
                resumeWriteSource() // wait for buffer space
                return
            }
            disconnect(reason: "write errno=\(errno)")
            return
        }
        suspendWriteSource()
        backlog.compact()
    }
}
