#!/usr/bin/env python3
"""Shared helpers for the macOS security validation scripts (run on the VM as the admin user `dev`).

Every step prints `== <label>: <compact JSON>` so the output can be diffed and quoted.
IPC goes to /var/run/axiom/axiom.sock with the product's NDJSON envelope.
"""
import datetime, json, os, socket, subprocess, sys, time, uuid

SOCK = "/var/run/axiom/axiom.sock"
RULES = "/Library/Application Support/Axiom/filter/rules.json"
APP = "/Applications/Axiom.app"
AXIOMD = APP + "/Contents/Resources/service/axiomd"
SYSEXT = APP + "/Contents/MacOS/axiom-sysext"
PLIST = "/Library/LaunchDaemons/com.axiom.service.plist"
RID = "5ec0a000-0000-4000-8000-00000000{:04x}"


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def call(command, payload=None, timeout=60):
    env = {"version": 1, "id": str(uuid.uuid4()), "type": command,
           "requestedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if payload is not None:
        env["payload"] = payload
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(SOCK)
        s.sendall((json.dumps(env) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
    except OSError as e:
        return {"ok": False, "transportError": f"{type(e).__name__}: {e}"}
    line = buf.split(b"\n", 1)[0]
    return json.loads(line) if line else {"ok": False, "transportError": "EOF without reply"}


def show(label, obj):
    print(f"== [{now()}] {label}: {json.dumps(obj, separators=(',', ':'), default=str)}", flush=True)


def sh(label, cmd, timeout=120):
    """Run a shell command, print it and its output verbatim."""
    print(f"$ {cmd}", flush=True)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    out = (p.stdout + p.stderr).rstrip()
    if out:
        print(out, flush=True)
    show(label, {"rc": p.returncode})
    return p


def curl():
    p = subprocess.run(["/usr/bin/curl", "-s", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}",
                        "https://example.com"], capture_output=True, text=True)
    return {"rc": p.returncode, "http": p.stdout, "blocked": p.returncode != 0}


def caps():
    r = call("rules.query")
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("transportError")}
    q = r["result"]
    fe = (q["capability"] or {}).get("filterEnforcement") or {}
    return {"status": q["capability"].get("status"), "reason": q["capability"].get("reason"),
            "filter": {k: fe.get(k) for k in ("state", "connected", "publishedGeneration",
                                              "ackedGeneration", "appliedRuleCount",
                                              "rejectedRules", "fileError")},
            "rules": [{k: x.get(k) for k in ("managedRuleId", "state", "lastVerifiedUtc", "lastError")}
                      for x in q.get("rules", [])]}


def verify(rid):
    r = call("rule.verify", {"managedRuleId": rid})
    if not r.get("ok"):
        return r
    v = r["result"]
    return {k: v.get(k) for k in ("presentInOs", "matchesSpec", "effectiveAction",
                                  "enforcementVerified", "filterRejectionReason", "notes")}


def apply_block(rid, created_by):
    r = call("rule.apply", {"managedRuleId": rid, "appPath": "/usr/bin/curl", "direction": "outbound",
                            "action": "block", "createdBy": created_by})
    if r.get("ok"):
        x = r["result"]
        return {k: x.get(k) for k in ("success", "state", "errorCode", "verifiedUtc", "message")}
    return r


def remove(rid):
    r = call("rule.remove", {"managedRuleId": rid})
    if r.get("ok"):
        x = r["result"]
        return {k: x.get(k) for k in ("success", "state", "errorCode", "verifiedUtc", "message")}
    return r


def snap(label):
    """caps + curl in one line: the claim next to the observable behaviour."""
    show(label, {"rulesQuery": caps(), "curl": curl()})


def wait_for(pred, timeout=30, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


def header(title):
    print(f"# {title}", flush=True)
    sh("versions", f"sw_vers; csrutil status; defaults read {APP}/Contents/Info.plist CFBundleShortVersionString; "
                   f"defaults read {APP}/Contents/Info.plist CFBundleVersion; "
                   "systemextensionsctl list | grep -i 'axiom.*activated'; id -un")
