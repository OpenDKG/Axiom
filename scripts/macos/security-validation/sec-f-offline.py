#!/usr/bin/env python3
"""(f) Offline recovery removal: with the daemon stopped, `axiomd --recover-network --apply` has no
filter acknowledgement channel, so it must not report the captured rule as removed/verified.
Then start the daemon and run the IPC restore (the app's Settings > Restore network settings path),
which completes only after the filter acks.
"""
import os, time
from seclib import *

header("(f) offline recovery removal")
rid = RID.format(0xf)
SNAP = "/Library/Application Support/Axiom/network-recovery.txt"
BAK = "/Library/Application Support/Axiom/network-recovery.txt.sec-f-backup"
snap("baseline")
# The baseline is captured once and kept; set the existing one aside so the capture below records
# the test rule (it is put back at the end).
sh("set the existing baseline aside", f"sudo -n test -f '{SNAP}' && sudo -n mv '{SNAP}' '{BAK}'; sudo -n ls -l '{BAK}' 2>&1 | cut -c1-11")
show("rule.apply block /usr/bin/curl", apply_block(rid, "sec-f"))
time.sleep(2)
snap("rule verified (expect curl blocked)")
r = call("networkRecovery.capture")
show("networkRecovery.capture", r.get("result") if r.get("ok") else r)
sh("stop daemon", f"sudo -n launchctl bootout system '{PLIST}'; sleep 2; "
                  "sudo -n launchctl print system/com.axiom.service >/dev/null 2>&1 && echo still-loaded || echo not-loaded")
show("rules.query with the daemon stopped", caps())
sh("offline recovery (dry run)", f"sudo -n '{AXIOMD}' --recover-network", timeout=180)
sh("offline recovery --apply", f"sudo -n '{AXIOMD}' --recover-network --apply", timeout=300)
show("curl after offline recovery (filter keeps its last acknowledged table or reloads rules.json; neither is claimed)", curl())
sh("start daemon", f"sudo -n launchctl bootstrap system '{PLIST}'; sleep 1; "
                   "sudo -n launchctl print system/com.axiom.service | grep -E '^\\s*state'")
wait_for(lambda: os.path.exists(SOCK) and caps().get("filter", {}).get("state") == "verified", 60)
snap("daemon back (expect filter verified, recorded rule state shown honestly)")
r = call("networkRecovery.restore", timeout=180)
show("networkRecovery.restore (online)", r.get("result") if r.get("ok") else r)
time.sleep(2)
snap("after online restore (expect 0 rules, curl 200)")
left = [x["managedRuleId"] for x in caps().get("rules", [])]
if rid in left:
    show("cleanup rule.remove", remove(rid))
    snap("after cleanup")
sh("put the original baseline back", f"sudo -n test -f '{BAK}' && sudo -n mv -f '{BAK}' '{SNAP}'; sudo -n ls -l '{SNAP}' | cut -c1-11")
r = call("networkRecovery.capture")
show("networkRecovery.capture (expect alreadyCaptured, the original baseline)", r.get("result") if r.get("ok") else r)
