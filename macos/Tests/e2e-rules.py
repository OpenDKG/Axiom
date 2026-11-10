#!/usr/bin/env python3
"""End-to-end rule tests for an installed, enabled AxiomFilter.

Run as root on a test Mac while Tests/filter-listener.py records events:

    sudo python3 filter-listener.py --out /tmp/flows.jsonl --seconds 300 &
    sudo python3 e2e-rules.py --events /tmp/flows.jsonl

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


def write_raw(text):
    os.makedirs(RULES_DIR, exist_ok=True)
    tmp = RULES + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
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

# cleanup
apply([], "empty (cleanup)")
report("curl allowed after cleanup", *curl(f"https://{HOST}"))
print(f"{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
