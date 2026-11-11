#!/usr/bin/env python3
"""End-to-end rule tests for an installed, enabled AxiomFilter.

Run as root on a test Mac while Tests/filter-listener.py records events. When the Axiom
daemon is installed it owns /var/run/axiom/filter.sock, so stop it first and restart it
afterwards:

    sudo launchctl bootout system/com.axiom.service
    sudo python3 filter-listener.py --out /tmp/flows.jsonl --seconds 300 &
    sudo python3 e2e-rules.py --events /tmp/flows.jsonl
    sudo launchctl bootstrap system /Library/LaunchDaemons/com.axiom.service.plist

Covers: exact/bundle/CIDR/port/direction rules, block-over-allow, invalid documents,
inbound, loopback exemption (review #13), rejected-rule reporting via filter.rules (#6),
rule-file identity (#11: non-root owner / world-writable rejected, last table kept),
case-insensitive path matching and responsible-process attribution (#12).

Writes /Library/Application Support/Axiom/filter/rules.json atomically
(temp + rename, like the daemon), waits for the filter.hello carrying the
new generation (the filter re-sends hello after every reload) to measure the
reload latency, then checks real traffic. Leaves an empty rule table behind.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time

RULES_DIR = "/Library/Application Support/Axiom/filter"
RULES = os.path.join(RULES_DIR, "rules.json")
HOST = "example.com"

ap = argparse.ArgumentParser()
ap.add_argument("--events", default="/tmp/flows.jsonl")
args = ap.parse_args()

results = []
generation = int(time.time())  # monotonic across runs


def report(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{': ' + detail if detail else ''}", flush=True)


def write_raw(text, mode=0o644):
    os.makedirs(RULES_DIR, exist_ok=True)
    tmp = RULES + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.rename(tmp, RULES)


def hello_after(gen, since, timeout=5.0):
    """Seconds until a filter.hello with `gen` arrived after `since`, or None."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            with open(args.events) as f:
                for line in f:
                    e = json.loads(line)
                    if e.get("type") == "filter.hello" and e.get("generation") == gen and e["_t"] >= since:
                        return e["_t"] - since
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    return None


def apply(rules, label):
    global generation
    generation += 1
    t0 = time.time()
    write_raw(json.dumps({"schemaVersion": 1, "generation": generation, "failOpen": True, "rules": rules}))
    latency = hello_after(generation, t0)
    report(f"reload gen {generation} ({label})", latency is not None and latency < 1.5,
           f"applied in {latency:.3f}s" if latency is not None else "no hello")
    return generation


def run(cmd, timeout=12):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip().replace("\n", " ")[:160]
    except subprocess.TimeoutExpired:
        return -1, "timeout"


def curl(url):
    rc, out = run(["/usr/bin/curl", "-sS", "-m", "6", "-o", "/dev/null", "-w", "%{http_code}", url])
    return rc == 0 and out.startswith(("2", "3")), f"rc={rc} {out}"


def nc(ip, port):
    rc, out = run(["/usr/bin/nc", "-z", "-G", "4", "-w", "4", ip, str(port)])
    return rc == 0, f"rc={rc} {out}"


PY_FETCH = "import urllib.request,sys; print(urllib.request.urlopen(sys.argv[1], timeout=6).status)"


def py(url):
    rc, out = run([sys.executable, "-c", PY_FETCH, url])
    return rc == 0 and out.startswith(("2", "3")), f"rc={rc} {out}"


def flows(path_sub, since):
    out = []
    with open(args.events) as f:
        for line in f:
            e = json.loads(line)
            if e.get("type") == "flow.open" and e["_t"] >= since and path_sub in (e.get("path") or ""):
                out.append(e)
    return out


def events(kind, since):
    out = []
    with open(args.events) as f:
        for line in f:
            e = json.loads(line)
            if e.get("type") == kind and e["_t"] >= since:
                out.append(e)
    return out


def rules_event(since, timeout=5.0, **match):
    """First filter.rules event after `since` whose fields equal `match`, or None."""
    end = time.time() + timeout
    while time.time() < end:
        for e in events("filter.rules", since):
            if all(e.get(k) == v for k, v in match.items()):
                return e
        time.sleep(0.05)
    return None


ips = sorted({a[4][0] for a in socket.getaddrinfo(HOST, 443, socket.AF_INET, socket.SOCK_STREAM)})
print(f"{HOST} -> {ips}")
# Real executable of this Python (the CLT python3 shim execs Python.app inside the framework).
py_path = subprocess.run(["ps", "-o", "comm=", "-p", str(os.getpid())], capture_output=True, text=True).stdout.strip()
py_bundle = py_path.split(".app/")[0] + ".app" if ".app/" in py_path else os.path.dirname(py_path)
print(f"python executable {py_path}; bundle {py_bundle}")

# 0. baseline
apply([], "empty")
report("baseline curl", *curl(f"https://{HOST}"))

# 1. exact path + IP block: curl blocked, other apps to the same IP allowed
t = time.time()
apply([{"id": "block-curl-example", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "block",
        "protocol": "any", "remoteAddresses": ips, "remotePorts": None, "enabled": True}], "curl->example IPs")
ok, d = curl(f"https://{HOST}")
report("curl to example.com blocked", not ok, d)
report("curl to apple.com still allowed", *curl("https://apple.com"))
report("nc -z to same IP:443 allowed", *nc(ips[0], 443))
report("python urllib to example.com allowed", *py(f"https://{HOST}"))
ev = [e for e in flows("/usr/bin/curl", t) if e["remoteAddress"] in ips]
report("flow.open verdict=block ruleId", any(e["verdict"] == "block" and e["ruleId"] == "block-curl-example" for e in ev),
       json.dumps(ev[-1]) if ev else "no event")

# 2. bundle-prefix rule
t = time.time()
apply([{"id": "block-python-bundle", "appPath": py_bundle, "direction": "outbound", "action": "block",
        "protocol": "tcp", "remoteAddresses": [], "remotePorts": "443", "enabled": True}], "bundle prefix")
ok, d = py(f"https://{HOST}")
report("python (inside bundle) blocked by bundle-prefix rule", not ok, d)
report("curl allowed", *curl(f"https://{HOST}"))
ev = flows(py_bundle, t)
report("python flow attributed to bundle path", any(e["verdict"] == "block" for e in ev),
       f"{ev[-1]['path']} verdict={ev[-1]['verdict']} rule={ev[-1]['ruleId']}" if ev else "no event")

# 3. CIDR + port range
cidrs = sorted({".".join(ip.split(".")[:2]) + ".0.0/16" for ip in ips})
apply([{"id": "block-cidr-ports", "appPath": "*", "direction": "outbound", "action": "block", "protocol": "tcp",
        "remoteAddresses": cidrs, "remotePorts": "440-450,8443", "enabled": True}], f"CIDR {cidrs} ports 440-450")
ok, d = curl(f"https://{HOST}")
report("https (443 in 440-450) to CIDR blocked", not ok, d)
report("http (80, outside range) to CIDR allowed", *curl(f"http://{HOST}"))
ok, d = nc(ips[0], 443)
report("nc to CIDR:443 blocked (any app)", not ok, d)

# 4. allow + block on the same match -> block; allow-only reports the allow rule
t = time.time()
apply([{"id": "allow-curl", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "allow",
        "remoteAddresses": ips},
       {"id": "block-curl", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "block",
        "remoteAddresses": ips}], "allow+block same match")
ok, d = curl(f"https://{HOST}")
report("allow+block -> blocked", not ok, d)
ev = [e for e in flows("/usr/bin/curl", t) if e["remoteAddress"] in ips]
report("deciding rule is the block rule", any(e["ruleId"] == "block-curl" for e in ev),
       ev[-1]["ruleId"] if ev else "no event")
t = time.time()
apply([{"id": "allow-curl", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "allow",
        "remoteAddresses": ips},
       {"id": "block-curl", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "block",
        "remoteAddresses": ips, "enabled": False}], "block disabled")
report("disabled block -> allowed", *curl(f"https://{HOST}"))
ev = [e for e in flows("/usr/bin/curl", t) if e["remoteAddress"] in ips]
report("allow verdict reports allow rule", any(e["verdict"] == "allow" and e["ruleId"] == "allow-curl" for e in ev),
       ev[-1]["ruleId"] if ev else "no event")

# 5. invalid JSON keeps the last good table
good = apply([{"id": "block-curl", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "block",
               "remoteAddresses": ips}], "block curl before invalid write")
t0 = time.time()
write_raw('{"schemaVersion": 1, "generation": 999999, "rules": [ {"id": broken')
time.sleep(1.5)
report("invalid JSON: no new generation applied", hello_after(999999, t0, timeout=0.5) is None)
ok, d = curl(f"https://{HOST}")
report("invalid JSON: last good table (block) still enforced", not ok, d)
write_raw('{"schemaVersion": 2, "generation": 999998, "rules": []}')
time.sleep(1.5)
ok, d = curl(f"https://{HOST}")
report("unsupported schemaVersion: last good table still enforced", not ok, d)

# 6. inbound: a local TCP listener, block inbound flows to it
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 18099))
srv.listen(8)
srv.settimeout(0.2)
local_ip = subprocess.run(["ipconfig", "getifaddr", "en0"], capture_output=True, text=True).stdout.strip() or "10.0.2.15"


def inbound_ok():
    # nc connects (outbound), our listener accepts (inbound); check data really flows.
    p = subprocess.Popen(["/usr/bin/nc", "-G", "3", "-w", "3", local_ip, "18099"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    got = ""
    try:
        end = time.time() + 4
        conn = None
        while time.time() < end and conn is None:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                pass
        if conn:
            conn.settimeout(2)
            p.stdin.write("ping\n"); p.stdin.flush()
            try:
                got = conn.recv(16).decode()
            except OSError as e:
                got = f"recv error {e}"
            conn.close()
    finally:
        p.stdin.close()
        p.wait(timeout=8)
    return got.startswith("ping"), f"server received {got!r}"


t = time.time()
apply([], "empty (inbound baseline)")
report("inbound baseline delivers data", *inbound_ok())
ev = [e for e in flows("", t) if e["direction"] == "inbound" and e.get("localPort") == 18099]
report("inbound flow.open seen", bool(ev), json.dumps(ev[-1]) if ev else "none")
t = time.time()
apply([{"id": "block-inbound-18099", "appPath": py_bundle, "direction": "inbound", "action": "block",
        "protocol": "tcp"}], "inbound block for python")
ok, d = inbound_ok()
report("inbound blocked", not ok, d)
ev = [e for e in flows("", t) if e["direction"] == "inbound" and e.get("localPort") == 18099]
report("inbound flow.open verdict=block", any(e["verdict"] == "block" for e in ev),
       json.dumps(ev[-1]) if ev else "none")
srv.close()

# 7. loopback exemption (review #13): "block curl" must not cut curl off from local services
lo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lo.bind(("127.0.0.1", 18098))
lo.listen(8)
lo.settimeout(0.2)


def lo_server_round():
    """Serve one HTTP request on the loopback listener while curl runs; returns curl's result."""
    p = subprocess.Popen(["/usr/bin/curl", "-sS", "-m", "4", "-o", "/dev/null", "-w", "%{http_code}",
                          "http://127.0.0.1:18098/"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    end = time.time() + 4
    while time.time() < end and p.poll() is None:
        try:
            c, _ = lo.accept()
        except socket.timeout:
            continue
        c.settimeout(2)
        try:
            c.recv(4096)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        c.close()
    out, _ = p.communicate(timeout=6)
    return out.strip() == "200", f"rc={p.returncode} {out.strip()[:80]}"


t = time.time()
apply([{"id": "block-curl-all", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "block"}], "block curl (no addresses)")
ok, d = curl(f"https://{HOST}")
report("loopback exemption: curl to example.com blocked", not ok, d)
report("loopback exemption: curl to 127.0.0.1 still allowed", *lo_server_round())
ev = [e for e in flows("/usr/bin/curl", t) if e.get("remoteAddress") == "127.0.0.1"]
report("loopback flow.open still emitted (verdict allow, no rule)", any(e["verdict"] == "allow" and e["ruleId"] is None for e in ev),
       json.dumps(ev[-1]) if ev else "no event")
t = time.time()
apply([{"id": "block-curl-lo", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "block",
        "remoteAddresses": ["127.0.0.1"], "remotePorts": "18098"}], "block curl -> 127.0.0.1:18098 explicitly")
ok, d = lo_server_round()
report("rule naming loopback blocks curl to 127.0.0.1", not ok, d)
ev = [e for e in flows("/usr/bin/curl", t) if e.get("remoteAddress") == "127.0.0.1"]
report("loopback block attributed to the rule", any(e["ruleId"] == "block-curl-lo" for e in ev), ev[-1]["ruleId"] if ev else "no event")
lo.close()

# 8. rejected rules are reported in filter.rules (review #6)
t = time.time()
gen = apply([{"id": "block-curl", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "block", "remoteAddresses": ips},
             {"id": "bad-action", "appPath": "/usr/bin/curl", "direction": "outbound", "action": "explode"},
             {"id": "bad-ports", "appPath": "*", "action": "block", "remotePorts": "99999"}], "one good + two bad rules")
re_ = rules_event(t, generation=gen)
report("filter.rules event for the generation", re_ is not None, json.dumps(re_) if re_ else "none")
if re_:
    rejected = {r["id"]: r["reason"] for r in re_.get("rejected", [])}
    report("filter.rules lists both rejected rules with reasons", set(rejected) == {"bad-action", "bad-ports"} and all(rejected.values()),
           json.dumps(rejected))
    report("filter.rules applied=1, error null, dropped counter present",
           re_.get("applied") == 1 and re_.get("error") is None and isinstance(re_.get("dropped"), int), json.dumps(re_))
    hello = [e for e in events("filter.hello", t) if e.get("generation") == gen]
    report("filter.rules follows the hello of the same generation", bool(hello) and re_["_t"] >= hello[0]["_t"], f"{len(hello)} hello(s)")
ok, d = curl(f"https://{HOST}")
report("good rule in the same file enforced", not ok, d)

# 9. rule file identity (review #11): wrong owner / world-writable -> rejected, last table kept
import pwd
try:
    other_uid = next(p.pw_uid for p in pwd.getpwall() if 500 < p.pw_uid < 1000 and p.pw_name not in ("nobody",))
except StopIteration:
    other_uid = 501
t = time.time()
os.chown(RULES, other_uid, 0)
re_ = rules_event(t, timeout=3)
report("file chowned to a non-root user is rejected (filter.rules error)", re_ is not None and "owned by uid" in (re_.get("error") or ""),
       json.dumps(re_) if re_ else "no filter.rules event")
ok, d = curl(f"https://{HOST}")
report("previous table (block curl) still enforced after chown", not ok, d)
os.chown(RULES, 0, 0)
t = time.time()
write_raw(json.dumps({"schemaVersion": 1, "generation": generation + 50, "failOpen": True, "rules": []}), mode=0o666)
re_ = rules_event(t, timeout=3)
report("world-writable (0666) root-owned file is rejected", re_ is not None and "world-writable" in (re_.get("error") or ""),
       json.dumps(re_) if re_ else "no filter.rules event")
ok, d = curl(f"https://{HOST}")
report("previous table still enforced after a 0666 replacement", not ok, d)
os.chmod(RULES, 0o644)
t0 = time.time()
latency = hello_after(generation + 50, t0, timeout=3)
report("chmod back to 0644 -> file accepted (new generation applied)", latency is not None, f"{latency}")
generation += 50
report("curl allowed after the empty table was accepted", *curl(f"https://{HOST}"))

# 10. case-insensitive path matching (review #12)
apply([{"id": "block-curl-upper", "appPath": "/USR/BIN/CURL", "direction": "outbound", "action": "block", "remoteAddresses": ips}],
      "upper-case appPath")
ok, d = curl(f"https://{HOST}")
report("rule with /USR/BIN/CURL blocks /usr/bin/curl", not ok, d)
apply([{"id": "block-bin-upper", "appPath": "/usr/BIN", "direction": "outbound", "action": "block", "remoteAddresses": ips}],
      "upper-case directory prefix")
ok, d = curl(f"https://{HOST}")
report("rule with /usr/BIN prefix blocks /usr/bin/curl", not ok, d)

# 11. responsible process attribution (review #12): curl started through `sh -c`
t = time.time()
apply([], "empty (responsible pid baseline)")
rc, out = run(["/bin/sh", "-c", f"/usr/bin/curl -sS -m 6 -o /dev/null -w '%{{http_code}}' https://{HOST}"])
ev = [e for e in flows("/usr/bin/curl", t) if e.get("remoteAddress") in ips]
resp = next((e for e in ev if e.get("responsiblePid")), None)
report("flow.open from `sh -c curl` carries responsiblePid/responsiblePath",
       resp is not None and resp["responsiblePid"] != resp["pid"] and bool(resp.get("responsiblePath")),
       json.dumps({k: resp.get(k) for k in ("pid", "path", "responsiblePid", "responsiblePath")}) if resp else (json.dumps(ev[-1]) if ev else "no event"))
if resp and resp.get("responsiblePath"):
    apply([{"id": "block-responsible", "appPath": resp["responsiblePath"], "direction": "outbound", "action": "block",
            "remoteAddresses": ips}], f"block responsible app {resp['responsiblePath']}")
    rc, out = run(["/bin/sh", "-c", f"/usr/bin/curl -sS -m 6 -o /dev/null -w '%{{http_code}}' https://{HOST}"])
    report("rule on the responsible app's path blocks curl started through sh -c", not (rc == 0 and out.startswith(("2", "3"))),
           f"rc={rc} {out}")

# cleanup
apply([], "empty (cleanup)")
report("curl allowed after cleanup", *curl(f"https://{HOST}"))
print(f"{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
