// Rule table unit tests (Tests/main.swift). Run with `macos/build.sh test` (no XCTest needed).
// Compiled together with AxiomFilter/RuleTable.swift into a stand-alone executable.

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

func table(_ json: String) -> RuleTable {
    do { return try RuleTable.parse(Data(json.utf8)) } catch {
        print("FAIL: parse threw \(error) for \(json)")
        exit(1)
    }
}

func flow(_ path: String? = "/usr/bin/curl", _ dir: FlowDirection = .outbound, _ proto: FlowProtocol = .tcp,
          _ ip: String? = "93.184.215.14", _ port: UInt16? = 443) -> FlowKey {
    FlowKey(appPath: path, direction: dir, proto: proto, remoteAddress: ip.flatMap(IPAddress.init), remotePort: port)
}

func rule(_ fields: String) -> String {
    "{\"schemaVersion\":1,\"generation\":7,\"failOpen\":true,\"rules\":[\(fields)]}"
}

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
{"id":"ok","action":"block","remoteAddresses":["*"],"appPath":"/bin/x"}
"""))
check(t.blockRules.map(\.id) == ["ok"] && t.warnings.count == 3, "invalid rules skipped, never widened")

// --- document-level errors --------------------------------------------------
for bad in ["{", "[]", "{\"schemaVersion\":2,\"rules\":[]}", "{\"schemaVersion\":1,\"rules\":{}}"] {
    var threw = false
    do { _ = try RuleTable.parse(Data(bad.utf8)) } catch { threw = true }
    check(threw, "document rejected: \(bad)")
}
check(table("{\"schemaVersion\":1}").ruleCount == 0, "missing rules = empty table")
check(RuleTable.empty.evaluate(flow()).action == .allow, "empty table allows (fail-open)")

print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
