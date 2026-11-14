#!/usr/bin/env python3
"""(d) Stale generation: a rule published after the filter's last ack must stay Pending.

Fault: freeze the AxiomFilter process (`kill -STOP`) so its connection stays open but it cannot
acknowledge; apply a rule (daemon publishes generation N+1, ack stays at N). Expected: rule.apply
returns pending (not applied, no verifiedUtc), rules.query published > acked, rule.verify
enforcementVerified=false. Then `kill -CONT`: the filter acks N+1 and the rule turns verified.
"""
import subprocess, time
from seclib import *

header("(d) stale generation")
rid = RID.format(0xd)
pid = subprocess.run(["pgrep", "-f", "com.axiom.firewall.filter.systemextension/Contents/MacOS"],
                     capture_output=True, text=True).stdout.split()[0]
show("filter pid", pid)
snap("baseline")
sh("freeze filter", f"sudo -n kill -STOP {pid} && ps -o pid,stat,comm -p {pid}")
try:
    t = time.time()
    show("rule.apply while the filter cannot ack (expect pending)", apply_block(rid, "sec-d"))
    show("rule.apply duration s", round(time.time() - t, 1))
    show("rules.query (expect published > acked, rule pending)", caps())
    show("rule.verify (expect enforcementVerified false)", verify(rid))
finally:
    sh("thaw filter", f"sudo -n kill -CONT {pid} && ps -o pid,stat,comm -p {pid}")
wait_for(lambda: any(r["state"] == "applied" for r in caps().get("rules", [])), 30)
snap("after thaw (expect fresh ack: verified, rule applied, curl blocked)")
show("rule.verify (after ack)", verify(rid))
show("rule.remove", remove(rid))
time.sleep(2)
snap("after remove (expect 0 rules, curl 200)")
