// AxiomFilter unit tests (Tests/main.swift). Run with `macos/build.sh test` (no XCTest needed).
// Compiled together with AxiomFilter/{RuleTable,RuleStore,EventSink}.swift into a stand-alone
// executable: rule parsing/matching, loopback exemption, case-insensitive + realpath matching,
// responsible-path matching, rules file identity checks, the bounded event queue, the sink's
// in-flight limit, wire framing over a real Unix socket, the filter.rules event, and the
// shared fixtures in Tests/fixtures/rules-cases.json (also used by the .NET contract tests).

import Darwin
import Foundation

var failures = 0
var checks = 0

func check(_ condition: @autoclosure () -> Bool, _ message: String, line: Int = #line) {
    checks += 1
    if !condition() {
        failures += 1
        print("FAIL line \(line): \(message)")
    }
}

func table(_ json: String, resolvePath: (String) -> String = { $0 }) -> RuleTable {
    do { return try RuleTable.parse(Data(json.utf8), resolvePath: resolvePath) } catch {
        print("FAIL: parse threw \(error) for \(json)")
        exit(1)
    }
}

func flow(_ path: String? = "/usr/bin/curl", _ dir: FlowDirection = .outbound, _ proto: FlowProtocol = .tcp,
          _ ip: String? = "93.184.215.14", _ port: UInt16? = 443, responsible: String? = nil) -> FlowKey {
    FlowKey(appPath: path, direction: dir, proto: proto, remoteAddress: ip.flatMap(IPAddress.init), remotePort: port,
            responsiblePath: responsible)
}

func rule(_ fields: String) -> String {
    "{\"schemaVersion\":1,\"generation\":7,\"failOpen\":true,\"rules\":[\(fields)]}"
}

func json(_ data: Data?) -> [String: Any]? {
    data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
}

let tmpRoot = NSTemporaryDirectory() + "axiom-filter-tests-\(getpid())"
try? FileManager.default.removeItem(atPath: tmpRoot)
try! FileManager.default.createDirectory(atPath: tmpRoot, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(atPath: tmpRoot) }

// --- addresses --------------------------------------------------------------
check(IPAddress("::ffff:1.2.3.4") == IPAddress("1.2.3.4"), "v4-mapped normalises")
check(IPAddress("fe80::1%en0") == IPAddress("fe80::1"), "zone id stripped")
check(IPAddress("example.com") == nil, "hostname is not an IP")
check(AddressMatcher("10.0.0.0/8")!.contains(IPAddress("10.200.3.4")!), "cidr v4 contains")
check(!AddressMatcher("10.0.0.0/8")!.contains(IPAddress("11.0.0.1")!), "cidr v4 excludes")
check(AddressMatcher("10.1.2.3/8") == AddressMatcher("10.0.0.0/8"), "cidr host bits masked")
check(AddressMatcher("2001:db8::/32")!.contains(IPAddress("2001:db8:ffff::1")!), "cidr v6")
check(!AddressMatcher("2001:db8::/32")!.contains(IPAddress("10.0.0.1")!), "family mismatch never matches")
check(AddressMatcher("0.0.0.0/0")!.contains(IPAddress("8.8.8.8")!), "/0 matches all v4")
check(AddressMatcher("1.2.3.4-1.2.3.9")!.contains(IPAddress("1.2.3.9")!), "range inclusive")
check(!AddressMatcher("1.2.3.4-1.2.3.9")!.contains(IPAddress("1.2.3.10")!), "range excludes")
check(AddressMatcher("1.2.3.9-1.2.3.4") == nil, "reversed range rejected")
check(AddressMatcher("10.0.0.0/33") == nil, "bad prefix rejected")
check(AddressMatcher("::ffff:10.0.0.0/104")!.contains(IPAddress("10.9.9.9")!), "mapped cidr")
check(IPAddress("127.0.0.1")!.isLoopback && IPAddress("127.255.0.9")!.isLoopback && IPAddress("::1")!.isLoopback, "loopback detection")
check(!IPAddress("128.0.0.1")!.isLoopback && !IPAddress("::2")!.isLoopback && IPAddress("::ffff:127.0.0.1")!.isLoopback, "loopback negatives + mapped")
check(AddressMatcher("127.0.0.1")!.namesLoopback && AddressMatcher("127.0.0.0/8")!.namesLoopback && AddressMatcher("::1")!.namesLoopback, "matcher names loopback")
check(!AddressMatcher("0.0.0.0/0")!.namesLoopback && !AddressMatcher("::/0")!.namesLoopback && !AddressMatcher("10.0.0.0/8")!.namesLoopback, "catch-all does not name loopback")
check(AddressMatcher("127.0.0.1-127.0.0.9")!.namesLoopback, "range names loopback")

// --- ports ------------------------------------------------------------------
let ports = PortSet("80, 443,1000-2000")!
check(ports.contains(80) && ports.contains(443) && ports.contains(1500) && !ports.contains(2001), "port set")
check(PortSet("70000") == nil && PortSet("5-1") == nil && PortSet("a") == nil, "bad ports rejected")

// --- matching ---------------------------------------------------------------
var t = table(rule("""
{"id":"b1","appPath":"/usr/bin/curl","direction":"outbound","action":"block","protocol":"any",
 "remoteAddresses":["93.184.215.14"],"remotePorts":null,"enabled":true}
"""))
check(t.generation == 7 && t.blockRules.count == 1, "parsed")
check(t.evaluate(flow()).action == .block && t.evaluate(flow()).ruleId == "b1", "exact path + ip blocks")
check(t.evaluate(flow("/usr/bin/nc")).action == .allow, "other app allowed")
check(t.evaluate(flow("/usr/bin/curl", .inbound)).action == .allow, "inbound not covered by outbound rule")
check(t.evaluate(flow("/usr/bin/curl", .outbound, .tcp, "1.1.1.1")).ruleId == nil, "other ip default allow")
check(t.evaluate(flow(nil)).action == .allow, "unknown path does not match app rule")

t = table(rule("""
{"id":"bundle","appPath":"/Applications/Foo.app/","direction":"outbound","action":"block","remoteAddresses":[]}
"""))
check(t.evaluate(flow("/Applications/Foo.app/Contents/MacOS/Foo")).action == .block, "bundle prefix")
check(t.evaluate(flow("/Applications/Foo.app")).action == .block, "bundle exact")
check(t.evaluate(flow("/Applications/Foo.application/x")).action == .allow, "prefix needs path separator")

t = table(rule("""
{"id":"cidr","appPath":"*","direction":"outbound","action":"block","protocol":"tcp",
 "remoteAddresses":["10.0.0.0/8","2001:db8::/32"],"remotePorts":"80,1000-2000"}
"""))
check(t.evaluate(flow("/x", .outbound, .tcp, "10.1.1.1", 1500)).action == .block, "cidr + port range")
check(t.evaluate(flow("/x", .outbound, .tcp, "10.1.1.1", 443)).action == .allow, "port outside range")
check(t.evaluate(flow("/x", .outbound, .udp, "10.1.1.1", 80)).action == .allow, "protocol mismatch")
check(t.evaluate(flow("/x", .outbound, .tcp, "2001:db8::5", 80)).action == .block, "v6 cidr")
check(t.evaluate(flow("/x", .outbound, .tcp, nil, 80)).action == .allow, "no remote ip never matches address rule")

t = table(rule("""
{"id":"allow","appPath":"/usr/bin/curl","direction":"outbound","action":"allow"},
{"id":"block","appPath":"/usr/bin/curl","direction":"outbound","action":"block"}
"""))
check(t.evaluate(flow()).action == .block && t.evaluate(flow()).ruleId == "block", "block wins over allow")

t = table(rule("""
{"id":"allow","appPath":"/usr/bin/curl","direction":"outbound","action":"allow"},
{"id":"off","appPath":"/usr/bin/curl","direction":"outbound","action":"block","enabled":false}
"""))
check(t.evaluate(flow()).ruleId == "allow" && t.evaluate(flow()).action == .allow, "disabled rule ignored, allow reported")

t = table(rule("""
{"id":"in","appPath":"","direction":"inbound","action":"block","remotePorts":"22"}
"""))
check(t.evaluate(flow("/usr/sbin/sshd", .inbound, .tcp, "10.0.2.2", 22)).action == .block, "inbound rule")
check(t.evaluate(flow("/usr/sbin/sshd", .outbound, .tcp, "10.0.2.2", 22)).action == .allow, "inbound rule ignores outbound")

t = table(rule("""
{"id":"bad1","action":"block","remoteAddresses":["not-an-ip"]},
{"id":"bad2","action":"explode"},
{"id":"bad3","action":"block","remotePorts":"99999"},
{"action":"block","appPath":"relative/path"},
{"id":"ok","action":"block","remoteAddresses":["*"],"appPath":"/bin/x"}
"""))
check(t.blockRules.map(\.id) == ["ok"] && t.rejected.count == 4, "invalid rules skipped, never widened")
check(t.rejected.map(\.id) == ["bad1", "bad2", "bad3", "#3"], "rejected ids (index when missing): \(t.rejected.map(\.id))")
check(t.rejected[0].reason.contains("remoteAddresses") && t.rejected[1].reason.contains("action")
      && t.rejected[2].reason.contains("remotePorts") && t.rejected[3].reason.contains("absolute"), "rejected reasons")
check(t.warnings.count == 4 && t.warnings[0].hasPrefix("rule bad1:"), "warnings derived from rejected")

// --- loopback exemption (review #13) ---------------------------------------
t = table(rule("""
{"id":"block-curl","appPath":"/usr/bin/curl","direction":"outbound","action":"block"}
"""))
check(t.evaluate(flow("/usr/bin/curl", .outbound, .udp, "127.0.0.1", 53)).action == .allow, "app block does not cover loopback v4")
check(t.evaluate(flow("/usr/bin/curl", .outbound, .tcp, "::1", 8080)).action == .allow, "app block does not cover loopback v6")
check(t.evaluate(flow("/usr/bin/curl", .outbound, .tcp, "10.0.0.1", 80)).action == .block, "same rule still blocks non-loopback")
t = table(rule("""
{"id":"block-all","appPath":"*","direction":"outbound","action":"block","remoteAddresses":["0.0.0.0/0","::/0"]}
"""))
check(t.evaluate(flow("/x", .outbound, .tcp, "127.0.0.1", 80)).action == .allow, "catch-all cidr does not cover loopback")
check(t.evaluate(flow("/x", .outbound, .tcp, "1.1.1.1", 80)).action == .block, "catch-all cidr blocks the rest")
t = table(rule("""
{"id":"block-lo","appPath":"/usr/bin/curl","direction":"outbound","action":"block","remoteAddresses":["127.0.0.1"],"remotePorts":"53"}
"""))
check(t.evaluate(flow("/usr/bin/curl", .outbound, .udp, "127.0.0.1", 53)).action == .block, "explicit loopback address matches")
check(t.evaluate(flow("/usr/bin/curl", .outbound, .udp, "127.0.0.2", 53)).action == .allow, "explicit loopback address is exact")
t = table(rule("""
{"id":"block-lo8","appPath":"*","direction":"outbound","action":"block","remoteAddresses":["127.0.0.0/8","::1"]}
"""))
check(t.evaluate(flow("/x", .outbound, .tcp, "127.0.0.2", 53)).action == .block
      && t.evaluate(flow("/x", .outbound, .tcp, "::1", 53)).action == .block, "loopback cidr + ::1 match")
check(t.evaluate(flow("/x", .outbound, .tcp, "::ffff:127.0.0.1", 53)).action == .block, "mapped loopback normalised")

// --- case-insensitive, realpath and responsible-path matching (review #12) --
t = table(rule("""
{"id":"case","appPath":"/USERS/dev/Foo.app","direction":"outbound","action":"block"}
"""))
check(t.evaluate(flow("/Users/dev/Foo.app/Contents/MacOS/Foo")).action == .block, "case-insensitive bundle prefix")
check(t.evaluate(flow("/users/DEV/foo.APP")).action == .block, "case-insensitive exact")
check(t.evaluate(flow("/Users/dev/Foo.application/x")).action == .allow, "case folding keeps separator rule")
check(t.evaluate(flow("/usr/bin/curl", responsible: "/Users/dev/Foo.app/Contents/MacOS/Foo")).action == .block, "responsible path matches")
check(t.evaluate(flow("/usr/bin/curl", responsible: "/Applications/Other.app/Contents/MacOS/Other")).action == .allow, "unrelated responsible path")
t = table(rule("""
{"id":"owner","appPath":"/usr/bin/curl","direction":"outbound","action":"block"}
"""))
check(t.evaluate(flow("/usr/bin/curl", responsible: "/Applications/Term.app/Contents/MacOS/Term")).action == .block, "owner path still matches with a responsible app")
check(flow("/usr/bin/curl", responsible: "/usr/bin/curl").foldedPaths.count == 1, "identical responsible path deduped")

// realpath on rule load: a symlinked bundle dir and /var -> /private/var.
let realDir = tmpRoot + "/Real.app"
let linkDir = tmpRoot + "/Link.app"
try! FileManager.default.createDirectory(atPath: realDir, withIntermediateDirectories: true)
try! FileManager.default.createSymbolicLink(atPath: linkDir, withDestinationPath: realDir)
let realResolved = PathMatch.resolve(realDir)
check(PathMatch.resolve(linkDir) == realResolved, "realpath resolves symlink: \(PathMatch.resolve(linkDir)) vs \(realResolved)")
check(PathMatch.resolve("/nonexistent/Foo.app") == "/nonexistent/Foo.app", "realpath keeps a missing path")
t = table(rule("{\"id\":\"link\",\"appPath\":\"\(linkDir)\",\"direction\":\"outbound\",\"action\":\"block\"}"),
          resolvePath: PathMatch.resolve)
check(t.blockRules[0].appPath == realResolved, "rule path resolved on load: \(t.blockRules[0].appPath ?? "nil")")
check(t.evaluate(flow(realResolved + "/Contents/MacOS/Real")).action == .block, "symlinked rule path matches real path")
if tmpRoot.hasPrefix("/var/") {
    check(realResolved.hasPrefix("/private/var/"), "/var resolves to /private/var: \(realResolved)")
}
check(table(rule("{\"id\":\"d\",\"appPath\":\"/USR/BIN/CURL\",\"action\":\"block\"}"), resolvePath: PathMatch.resolve)
          .evaluate(flow("/usr/bin/curl")).action == .block, "upper-case existing path still matches (realpath keeps case on APFS)")

// --- document-level errors --------------------------------------------------
for bad in ["{", "[]", "{\"schemaVersion\":2,\"rules\":[]}", "{\"schemaVersion\":1,\"rules\":{}}"] {
    var threw = false
    do { _ = try RuleTable.parse(Data(bad.utf8)) } catch { threw = true }
    check(threw, "document rejected: \(bad)")
}
check(table("{\"schemaVersion\":1}").ruleCount == 0, "missing rules = empty table")
check(RuleTable.empty.evaluate(flow()).action == .allow, "empty table allows (fail-open)")

// --- rules file identity (review #11) --------------------------------------
let rulesDir = tmpRoot + "/filter"
try! FileManager.default.createDirectory(atPath: rulesDir, withIntermediateDirectories: true)
let rulesPath = rulesDir + "/rules.json"
func writeRules(_ text: String, mode: Int = 0o644) {
    let tmp = rulesPath + ".tmp"
    try! text.write(toFile: tmp, atomically: false, encoding: .utf8)
    chmod(tmp, mode_t(mode))
    rename(tmp, rulesPath)
}
func loadError(_ path: String, owner: uid_t) -> String? {
    do { _ = try RuleStore.loadFile(path, requiredOwner: owner); return nil } catch { return String(describing: error) }
}
let me = getuid()
writeRules(rule("{\"id\":\"f\",\"appPath\":\"/usr/bin/curl\",\"action\":\"block\"}"))
check(loadError(rulesPath, owner: me) == nil, "0644 file owned by the required uid loads")
check((try? RuleStore.loadFile(rulesPath, requiredOwner: me))?.blockRules.first?.id == "f", "loaded content")
if me != 0 {
    let e = loadError(rulesPath, owner: 0)
    check(e?.contains("owned by uid \(me), expected uid 0") == true, "file owned by non-root rejected: \(e ?? "nil")")
}
chmod(rulesPath, 0o666)
var e = loadError(rulesPath, owner: me)
check(e?.contains("world-writable") == true, "0666 rejected: \(e ?? "nil")")
chmod(rulesPath, 0o664)
e = loadError(rulesPath, owner: me)
check(e?.contains("world-writable") == true, "group-writable 0664 rejected: \(e ?? "nil")")
chmod(rulesPath, 0o600)
check(loadError(rulesPath, owner: me) == nil, "0600 accepted")
let linkPath = rulesDir + "/link.json"
symlink(rulesPath, linkPath)
e = loadError(linkPath, owner: me)
check(e?.contains("symlink") == true, "symlink rejected (O_NOFOLLOW): \(e ?? "nil")")
e = loadError(rulesDir, owner: me)
check(e != nil, "directory rejected: \(e ?? "nil")")
check(loadError(rulesDir + "/missing.json", owner: me)?.contains("open failed") == true, "missing file reports open failure")

// RuleStore keeps the last good table when the file identity turns bad, and reports it.
chmod(rulesPath, 0o644)
let store = RuleStore(directory: rulesDir, requiredOwner: me)
let reloaded = DispatchSemaphore(value: 0)
let rejectedFile = DispatchSemaphore(value: 0)
var lastReason = ""
store.start()
check(store.snapshot().blockRules.first?.id == "f", "store loaded synchronously at start")
store.onReload = { _ in reloaded.signal() }
store.onRejectedFile = { reason in lastReason = reason; rejectedFile.signal() }
writeRules("{\"schemaVersion\":1,\"generation\":8,\"rules\":[{\"id\":\"g\",\"appPath\":\"/usr/bin/curl\",\"action\":\"block\"},{\"id\":\"bad\",\"action\":\"nope\"}]}")
check(reloaded.wait(timeout: .now() + 3) == .success, "store reloads after a rename")
check(store.snapshot().generation == 8 && store.snapshot().rejected.map(\.id) == ["bad"], "reloaded table with rejected rule")
chmod(rulesPath, 0o666)
check(rejectedFile.wait(timeout: .now() + 3) == .success, "store reports a rejected file (chmod 666)")
check(lastReason.contains("world-writable") && store.snapshot().generation == 8, "last good table kept: \(lastReason)")
writeRules("{\"schemaVersion\":1,\"generation\":9,\"rules\":[]}", mode: 0o666)
check(rejectedFile.wait(timeout: .now() + 3) == .success && store.snapshot().generation == 8, "world-writable replacement still rejected")
writeRules("{\"schemaVersion\":1,\"generation\":10,\"rules\":[]}")
check(reloaded.wait(timeout: .now() + 3) == .success && store.snapshot().generation == 10, "good file accepted again")
store.stop()

// --- EventQueue: drop-oldest and framing (review #14) ----------------------
let q = EventQueue(maxLines: 3, maxBytes: 1000)
func line(_ s: String) -> Data { Data((s + "\n").utf8) }
q.enqueue(line("a")); q.enqueue(line("b")); q.enqueue(line("c"))
check(q.pendingCount == 3 && q.dropped == 0, "queue holds maxLines")
q.enqueue(line("d"))
check(q.pendingCount == 3 && q.dropped == 1 && q.current?.line == line("b"), "drop-oldest advances head")
q.advance(by: 1) // "b" partially written
q.enqueue(line("e"))
check(q.current?.line == line("b") && q.current?.offset == 1 && q.dropped == 2, "partial head line kept, second-oldest dropped")
q.advance(by: 1)
check(q.current?.line == line("d"), "head line completed -> next is d (c was dropped)")
q.advance(by: 2); q.advance(by: 2)
check(q.isEmpty && q.pendingBytes == 0, "queue drains to empty")
let qb = EventQueue(maxLines: 100, maxBytes: 10)
qb.enqueue(Data(repeating: 0x41, count: 6)); qb.enqueue(Data(repeating: 0x42, count: 6))
check(qb.pendingCount == 1 && qb.dropped == 1 && qb.pendingBytes == 6, "byte bound drops oldest")
let qf = EventQueue(maxLines: 2, maxBytes: 1000)
qf.enqueue(line("x")); qf.enqueue(line("y"))
qf.enqueue(line("hello"), atFront: true)
check(qf.current?.line == line("hello") && qf.dropped == 1, "front insert (hello) survives, oldest tail dropped")
let qc = EventQueue(maxLines: 5000, maxBytes: 1 << 20)
for i in 0..<3000 { qc.enqueue(line("\(i)")) }
for _ in 0..<2000 { qc.advance(by: qc.current!.line.count) }
qc.compact()
check(qc.pendingCount == 1000 && qc.current?.line == line("2000") && qc.lines.count < 3000, "compaction keeps order")

// --- EventSink: bounded in-flight hop + dropped counter ---------------------
let sink = EventSink(socketPath: tmpRoot + "/nosuch.sock", trustedPeerUid: me, maxInflight: 4) {
    .hello(ts: Date(), version: "t", generation: 1)
}
let gate = DispatchSemaphore(value: 0)
sink.testHoldQueue(until: gate)
var accepted = 0
for i in 0..<10 {
    if sink.send(.close(id: UUID(), ts: Date(), bytesIn: UInt64(i), bytesOut: 0)) { accepted += 1 }
}
check(accepted == 4, "in-flight limit admits exactly maxInflight events (\(accepted))")
gate.signal()
sink.testDrain()
check(sink.droppedTotal == 6, "dropped counter counts in-flight drops (\(sink.droppedTotal))")
check(sink.send(.close(id: UUID(), ts: Date(), bytesIn: 0, bytesOut: 0)), "sends admitted again after drain")
let hello = json(sink.testEncode(.hello(ts: Date(), version: "1.2.3", generation: 42)))
check(hello?["type"] as? String == "filter.hello" && hello?["generation"] as? Int == 42
      && hello?["dropped"] as? Int == 6 && hello?["version"] as? String == "1.2.3", "hello carries dropped: \(hello ?? [:])")

// filter.rules event JSON (review #6)
let rulesEvent = json(sink.testEncode(.rules(ts: Date(), generation: 9, applied: 2,
                                             rejected: [RejectedRule(id: "r1", reason: "unknown action x")], error: nil,
                                             ruleIds: ["a", "b"])))
check(rulesEvent?["type"] as? String == "filter.rules" && rulesEvent?["generation"] as? Int == 9
      && rulesEvent?["applied"] as? Int == 2 && rulesEvent?["error"] is NSNull && rulesEvent?["dropped"] as? Int == 6,
      "filter.rules fields: \(rulesEvent ?? [:])")
let rej = rulesEvent?["rejected"] as? [[String: Any]]
check(rej?.count == 1 && rej?[0]["id"] as? String == "r1" && rej?[0]["reason"] as? String == "unknown action x", "filter.rules rejected list")
check(rulesEvent?["ruleIds"] as? [String] == ["a", "b"], "filter.rules echoes enforced rule ids (review #2 MAC-1)")
let fileErr = json(sink.testEncode(.rules(ts: Date(), generation: 9, applied: 2, rejected: [], error: "unreadable: owned by uid 501",
                                          ruleIds: nil)))
check(fileErr?["error"] as? String == "unreadable: owned by uid 501", "filter.rules error field")
check(fileErr?["ruleIds"] == nil, "filter.rules omits ruleIds when unknown")
let openEvent = json(sink.testEncode(.open(FlowRecord(id: UUID(), ts: Date(), pid: 5, path: "/usr/bin/curl", direction: .outbound,
                                                   proto: .tcp, localAddress: nil, localPort: nil, remoteAddress: "1.2.3.4",
                                                   remotePort: 443, remoteHost: nil, verdict: .block, ruleId: "b",
                                                   responsiblePid: 4, responsiblePath: "/Applications/T.app/Contents/MacOS/T"))))
check(openEvent?["responsiblePid"] as? Int == 4 && openEvent?["responsiblePath"] as? String == "/Applications/T.app/Contents/MacOS/T"
      && openEvent?["verdict"] as? String == "block" && openEvent?["ruleId"] as? String == "b" && openEvent?["localAddress"] is NSNull,
      "flow.open carries responsible pid/path: \(openEvent ?? [:])")

// --- EventSink: framing over a real Unix socket -----------------------------
func listen(_ path: String) -> Int32 {
    let s = socket(AF_UNIX, SOCK_STREAM, 0)
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8)
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in raw.copyBytes(from: bytes); raw[bytes.count] = 0 }
    addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
    precondition(rc == 0, "bind failed errno=\(errno)")
    Darwin.listen(s, 2)
    return s
}
func readLines(_ fd: Int32, count: Int, timeout: TimeInterval) -> [String] {
    var buf = Data()
    let end = Date().addingTimeInterval(timeout)
    var chunk = [UInt8](repeating: 0, count: 4096)
    while Date() < end {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        if poll(&pfd, 1, 100) > 0 {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buf.append(chunk, count: n)
            if buf.filter({ $0 == 0x0a }).count >= count { break }
        }
    }
    return String(decoding: buf, as: UTF8.self).split(separator: "\n").map(String.init)
}
let sockPath = tmpRoot + "/f.sock"
let srv = listen(sockPath)
let wire = EventSink(socketPath: sockPath, trustedPeerUid: me) { .hello(ts: Date(), version: "w", generation: 3) }
let before = UUID()
wire.send(.close(id: before, ts: Date(), bytesIn: 1, bytesOut: 2)) // queued before the connection: delivered after hello
wire.start()
var pfd = pollfd(fd: srv, events: Int16(POLLIN), revents: 0)
check(poll(&pfd, 1, 3000) > 0, "sink connects to the listener")
let conn = accept(srv, nil, nil)
check(conn >= 0, "accepted")
wire.send(.stats(id: before, ts: Date(), bytesIn: 10, bytesOut: 20))
let lines = readLines(conn, count: 3, timeout: 3)
check(lines.count == 3, "three framed lines received (\(lines.count))")
let parsed = lines.compactMap { json(Data($0.utf8)) }
check(parsed.count == lines.count, "every line is one JSON object")
check(parsed.first?["type"] as? String == "filter.hello" && parsed.first?["generation"] as? Int == 3, "hello first")
check(Array(parsed.dropFirst()).map { $0["type"] as? String } == ["flow.close", "flow.stats"], "queued-before-connect event precedes later ones")
wire.stop()
close(conn); close(srv)

// untrusted peer: a listener owned by another uid is refused (here: expect uid 0 while we are not root)
if me != 0 {
    let srv2 = listen(tmpRoot + "/g.sock")
    let refusing = EventSink(socketPath: tmpRoot + "/g.sock", trustedPeerUid: 0) { .hello(ts: Date(), version: "w", generation: 3) }
    refusing.start()
    var p2 = pollfd(fd: srv2, events: Int16(POLLIN), revents: 0)
    if poll(&p2, 1, 3000) > 0 {
        let c2 = accept(srv2, nil, nil)
        check(readLines(c2, count: 1, timeout: 1).isEmpty, "nothing sent to an untrusted peer (connection closed)")
        close(c2)
    } else { check(false, "refusing sink never connected") }
    refusing.stop(); close(srv2)
}

// --- filter refresh policy (FilterRefreshPolicy.swift) ----------------------
// Any replaced extension/host is re-signed, so the saved NEFilterManager configuration no longer
// satisfies its code-signature requirement and must be re-created. `--reset-filter` forces it.
check(!filterRefreshRequired(explicitReset: false, replaced: false), "unchanged activation keeps the filter configuration")
check(filterRefreshRequired(explicitReset: true, replaced: false), "--reset-filter re-creates the configuration")
check(filterRefreshRequired(explicitReset: false, replaced: true), "a replaced extension re-creates the configuration")
check(filterRefreshRequired(explicitReset: true, replaced: true), "reset and replacement together still re-create")

// --- shared fixtures (Tests/fixtures/rules-cases.json) ----------------------
let fixturePath = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
    .appendingPathComponent("../../Tests/fixtures/rules-cases.json").standardized.path
let fixtureOverride = ProcessInfo.processInfo.environment["AXIOM_RULE_FIXTURES"]
if let data = FileManager.default.contents(atPath: fixtureOverride ?? fixturePath),
   let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
   let groups = root["groups"] as? [[String: Any]] {
    var fixtureCases = 0
    for group in groups {
        let name = group["name"] as? String ?? "?"
        let doc: [String: Any] = ["schemaVersion": 1, "generation": 1, "rules": group["rules"] ?? []]
        guard let docData = try? JSONSerialization.data(withJSONObject: doc),
              let gt = try? RuleTable.parse(docData, resolvePath: { $0 }) else {
            check(false, "fixture group \(name): document failed to parse"); continue
        }
        if let expectRejected = group["expectRejected"] as? [String] {
            check(gt.rejected.map(\.id) == expectRejected, "fixture \(name): rejected ids \(gt.rejected.map(\.id)) == \(expectRejected)")
        }
        for c in group["cases"] as? [[String: Any]] ?? [] {
            fixtureCases += 1
            let f = c["flow"] as? [String: Any] ?? [:]
            let key = FlowKey(appPath: f["appPath"] as? String,
                              direction: FlowDirection(rawValue: f["direction"] as? String ?? "outbound") ?? .outbound,
                              proto: FlowProtocol(rawValue: f["protocol"] as? String ?? "tcp") ?? .tcp,
                              remoteAddress: (f["remoteAddress"] as? String).flatMap(IPAddress.init),
                              remotePort: (f["remotePort"] as? Int).flatMap { UInt16(exactly: $0) },
                              responsiblePath: f["responsiblePath"] as? String)
            let expect = c["expect"] as? [String: Any] ?? [:]
            let d = gt.evaluate(key)
            let expectedRule = expect["ruleId"] as? String
            check(d.action.rawValue == expect["action"] as? String && d.ruleId == expectedRule,
                  "fixture \(name)/\(c["name"] as? String ?? "?"): got \(d.action.rawValue)/\(d.ruleId ?? "nil"), expected \(expect["action"] ?? "?")/\(expectedRule ?? "nil")")
        }
    }
    print("fixtures: \(groups.count) groups, \(fixtureCases) cases from \(fixtureOverride ?? fixturePath)")
} else {
    print("fixtures: none found at \(fixtureOverride ?? fixturePath) (skipped)")
}

print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
