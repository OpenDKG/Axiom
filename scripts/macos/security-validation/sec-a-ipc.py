#!/usr/bin/env python3
"""(a) Second standard user: private IPC reads are denied, public reads are redacted, writes denied.

Run twice: as the admin installer `dev` (contrast) and as the non-admin `axtest2`
(`sudo -n -u axtest2 python3 sec-a-ipc.py`). Prints per command: ok, error code/message and, for
successful replies, only the shape (keys, counts) so no machine activity lands in the evidence.
"""
import json, os, pwd
from seclib import call, show

me = pwd.getpwuid(os.getuid()).pw_name
print(f"# (a) IPC access as {me} (uid {os.getuid()}, groups {os.getgroups()})", flush=True)
CMDS = [
    ("snapshot", None), ("history.query", {"limit": 5}), ("diagnostics.export", None),
    ("rules.query", None), ("rule.verify", {"managedRuleId": "5ec0a000-0000-4000-8000-00000000000a"}),
    ("live.events", None), ("config.get", None),
    ("serviceHealth", None), ("capabilities", None),
    ("rule.apply", {"managedRuleId": "5ec0a000-0000-4000-8000-00000000000a", "appPath": "/usr/bin/curl",
                    "direction": "outbound", "action": "block", "createdBy": "sec-a"}),
]
for cmd, payload in CMDS:
    r = call(cmd, payload, timeout=20)
    if r.get("ok"):
        res = r.get("result")
        shape = sorted(res.keys()) if isinstance(res, dict) else type(res).__name__
        extra = {}
        if cmd == "serviceHealth":
            extra = {k: res.get(k) for k in ("status", "connectionCount", "processCount",
                                             "lastCaptureUtc", "limitations", "lastError")}
        if cmd == "rule.apply":
            extra = {k: res.get(k) for k in ("success", "state", "errorCode")}
        show(f"{cmd}", {"ok": True, "resultKeys": shape, **extra})
    else:
        err = r.get("error") or {}
        show(f"{cmd}", {"ok": False, "code": err.get("code") if isinstance(err, dict) else err,
                        "message": err.get("message") if isinstance(err, dict) else None,
                        "transport": r.get("transportError")})
