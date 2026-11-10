// AxiomFilter — flow event stream to the daemon.
//
// Contract (docs/MACOS_ARCHITECTURE.md §3.2): newline-delimited JSON over the
// Unix stream socket /var/run/axiom/filter.sock, where the daemon listens.
// The filter is the client:
//   * reconnects every 2 s while the daemon is down;
//   * never blocks a verdict: callers only enqueue onto a private serial queue;
//   * keeps a bounded in-memory queue and drops the oldest lines when full;
//   * sends `filter.hello` first on every new connection (and again after each
//     rules reload so the daemon learns the applied generation).
//
// All socket IO is non-blocking and driven by dispatch sources on `queue`.

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
}

final class EventSink: @unchecked Sendable {
    static let defaultSocketPath = "/var/run/axiom/filter.sock"

    /// Queue bounds: whichever is hit first triggers drop-oldest.
    private let maxLines = 20_000
    private let maxBytes = 8 * 1024 * 1024
    private let reconnectInterval: DispatchTimeInterval = .seconds(2)

    private let socketPath: String
    private let queue = DispatchQueue(label: "com.axiom.firewall.filter.events", qos: .utility)
    private let log = Logger(subsystem: FilterLog.subsystem, category: "events")

    /// Supplies the current hello event (version + applied generation).
    private let helloProvider: () -> FilterEvent

    // State below is only touched on `queue`.
    private var fd: Int32 = -1
    private var connected = false
    private var readSource: DispatchSourceRead?
    private var writeSource: DispatchSourceWrite?
    private var writeSourceActive = false
    private var reconnectTimer: DispatchSourceTimer?
    private var running = false

    /// Pending lines: `lines[head...]` are unsent; `headOffset` bytes of `lines[head]` were already written.
    private var lines: [Data] = []
    private var head = 0
    private var headOffset = 0
    private var pendingBytes = 0
    private var dropped: UInt64 = 0

    private let timestampFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    init(socketPath: String = EventSink.defaultSocketPath, helloProvider: @escaping () -> FilterEvent) {
        self.socketPath = socketPath
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

    /// Enqueues an event. Safe from the verdict path: one async hop, no IO.
    func send(_ event: FilterEvent) {
        queue.async {
            guard let line = self.encode(event) else { return }
            self.enqueue(line, atFront: false)
            if self.connected { self.flush() }
        }
    }

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
            ]
        case let .stats(id, ts, bytesIn, bytesOut):
            object = ["type": "flow.stats", "id": id.uuidString.lowercased(), "ts": timestampFormatter.string(from: ts),
                      "bytesIn": bytesIn, "bytesOut": bytesOut]
        case let .close(id, ts, bytesIn, bytesOut):
            object = ["type": "flow.close", "id": id.uuidString.lowercased(), "ts": timestampFormatter.string(from: ts),
                      "bytesIn": bytesIn, "bytesOut": bytesOut]
        case let .hello(ts, version, generation):
            object = ["type": "filter.hello", "ts": timestampFormatter.string(from: ts), "version": version,
                      "generation": generation]
        }
        guard var data = try? JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]) else {
            return nil
        }
        data.append(0x0a) // '\n'
        return data
    }

    // MARK: - Bounded queue

    private var pendingCount: Int { lines.count - head }

    private func enqueue(_ line: Data, atFront: Bool) {
        if atFront {
            // Only used right after connecting, when nothing has been partially written.
            if head > 0 { head -= 1; lines[head] = line } else { lines.insert(line, at: 0) }
        } else {
            lines.append(line)
        }
        pendingBytes += line.count
        while pendingCount > maxLines || pendingBytes > maxBytes {
            if headOffset == 0 {
                // Drop the oldest line: O(1), just advance the head.
                pendingBytes -= lines[head].count
                lines[head] = Data()
                head += 1
            } else {
                // The oldest line is partially on the wire and must be finished to keep framing:
                // drop the second-oldest instead by moving the partial line one slot forward.
                guard head + 1 < lines.count else { break }
                pendingBytes -= lines[head + 1].count
                lines[head + 1] = lines[head]
                lines[head] = Data()
                head += 1
            }
            dropped += 1
            if dropped == 1 || dropped % 1000 == 0 {
                log.error("event queue full: dropped \(self.dropped) oldest events so far")
            }
        }
        compact()
    }

    /// Reclaims the consumed prefix of `lines` occasionally (amortised O(1)).
    private func compact() {
        if head > 1024, head * 2 > lines.count {
            lines.removeFirst(head)
            head = 0
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
        if getpeereid(fd, &uid, &gid) != 0 || uid != 0 {
            log.error("refusing filter socket peer with uid \(uid) (expected root)")
            disconnect(reason: "untrusted peer")
            return
        }
        connected = true
        headOffset = 0 // a line cut by a previous connection is re-sent whole
        if let hello = encode(helloProvider()) { enqueue(hello, atFront: true) }
        log.notice("connected to daemon at \(self.socketPath, privacy: .public), \(self.pendingCount) events pending")
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
        headOffset = 0
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
        while head < lines.count {
            let line = lines[head]
            let n = line.withUnsafeBytes { raw -> Int in
                write(fd, raw.baseAddress!.advanced(by: headOffset), line.count - headOffset)
            }
            if n > 0 {
                headOffset += n
                if headOffset == line.count {
                    pendingBytes -= line.count
                    lines[head] = Data() // release memory before compaction
                    head += 1
                    headOffset = 0
                }
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
        compact()
        if head == lines.count { lines.removeAll(keepingCapacity: true); head = 0 }
    }
}
