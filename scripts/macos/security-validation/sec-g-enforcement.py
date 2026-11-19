#!/usr/bin/env python3
"""(g) Access class of the enforcement.* IPC commands, per caller, with raw request/response lines.

Run three times on the Mac: as the user who installed Axiom, as a second standard user that is not
in `admin` (`sudo -n -u axtest2 python3 sec-g-enforcement.py`) and as root (`sudo -n python3 ...`).

Expected on macOS, where the daemon registers no EnforcementController:
  second user  -> `unauthorized` for enforcement.status / .receipts / .evaluate and for snapshot
  owner, root  -> `not_supported` for the three enforcement.* commands (the access check passed)
  everyone     -> serviceHealth ok (public; redacted for the second user)

Every request line is printed as sent. Every error reply is printed as received. A successful reply
to a private command (snapshot) is printed as id/ok/result keys/byte count only, so that no machine
activity lands in the evidence.
"""
import datetime, json, os, pwd, socket, uuid

SOCK = "/var/run/axiom/axiom.sock"
me = pwd.getpwuid(os.getuid()).pw_name
print(f"# (g) enforcement.* access as {me} (uid {os.getuid()}, groups {sorted(os.getgroups())})", flush=True)
CMDS = [
    ("enforcement.status", None),
    ("enforcement.receipts", None),
    ("enforcement.evaluate", {"reason": "sec-g access-class probe"}),
    ("snapshot", None),
    ("serviceHealth", None),
]
for cmd, payload in CMDS:
    env = {"version": 1, "id": str(uuid.uuid4()), "type": cmd,
           "requestedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if payload is not None:
        env["payload"] = payload
    req = json.dumps(env, separators=(",", ":"))
    print(">> " + req, flush=True)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect(SOCK)
        s.sendall((req + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
    except OSError as e:
        print(f"<< TRANSPORT ERROR {type(e).__name__}: {e}", flush=True)
        continue
    line = buf.split(b"\n", 1)[0].decode("utf-8", "replace")
    try:
        r = json.loads(line)
    except ValueError:
        r = None
    if isinstance(r, dict) and r.get("ok") and cmd == "snapshot":
        res = r.get("result")
        keys = sorted(res.keys()) if isinstance(res, dict) else type(res).__name__
        print("<< [private reply redacted] " + json.dumps(
            {"id": r.get("id"), "ok": True, "resultKeys": keys, "replyBytes": len(line)},
            separators=(",", ":")), flush=True)
    else:
        print("<< " + line, flush=True)
