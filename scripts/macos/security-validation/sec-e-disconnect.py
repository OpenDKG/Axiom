#!/usr/bin/env python3
"""(e) Disconnect/reconnect: a disabled filter must never be reported as enforcing.

`axiom-sysext disable` drops the filter connection: capability degraded, connected false, rule not
verified, and curl reaches the network (which the daemon must not contradict). `axiom-sysext enable`
reconnects: the earlier ack is void until the new instance acks the current generation. A sampler
records rules.query every 200 ms around both transitions (file: /tmp/axsec/e-samples.ndjson).
"""
import json, threading, time
from seclib import *

header("(e) disconnect / reconnect")
rid = RID.format(0xe)
samples, stop = [], threading.Event()


def sampler():
    while not stop.is_set():
        c = caps()
        f = c.get("filter", {})
        samples.append({"t": now(), "state": f.get("state"), "connected": f.get("connected"),
                        "pub": f.get("publishedGeneration"), "ack": f.get("ackedGeneration"),
                        "rules": [r["state"] for r in c.get("rules", [])]})
        time.sleep(0.2)


snap("baseline")
show("rule.apply block /usr/bin/curl", apply_block(rid, "sec-e"))
time.sleep(2)
snap("connected (expect verified + curl blocked)")
th = threading.Thread(target=sampler, daemon=True); th.start()
sh("disable", f"'{SYSEXT}' disable")
wait_for(lambda: caps().get("filter", {}).get("connected") is False, 20)
time.sleep(1)
snap("disabled (expect degraded/not connected, rule not verified; curl 200 is consistent)")
show("rule.verify (disabled)", verify(rid))
sh("enable", f"'{SYSEXT}' enable")
ok = wait_for(lambda: caps().get("filter", {}).get("state") == "verified", 45)
show("reconnected verified within 45 s", bool(ok))
snap("after enable")
show("rule.verify (after enable)", verify(rid))
stop.set(); th.join()
with open("/tmp/axsec/e-samples.ndjson", "w") as fh:
    for s in samples:
        fh.write(json.dumps(s) + "\n")
# compress the sampler log to its transitions
prev = None
for s in samples:
    key = (s["state"], s["connected"], s["pub"], s["ack"], tuple(s["rules"]))
    if key != prev:
        show("sample transition", s)
        prev = key
show("rule.remove", remove(rid))
time.sleep(2)
snap("after remove (expect 0 rules, curl 200)")
