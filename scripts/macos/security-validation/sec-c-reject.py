#!/usr/bin/env python3
"""(c) Filter rejection: a rules file the filter refuses must revoke Applied/Verified.

Fault: `sudo -n chmod 664` on rules.json (AxiomFilter refuses group/world-writable files) while a
verified block rule exists. Expected: capability degraded, rule not verified, rule.verify
enforcementVerified=false; after `chmod 644`: a fresh ack, verified again.
"""
import time
from seclib import *

header("(c) filter rejection")
rid = RID.format(0xc)
snap("baseline")
show("rule.apply block /usr/bin/curl", apply_block(rid, "sec-c"))
time.sleep(2)
snap("after apply (expect verified + curl blocked)")
show("rule.verify", verify(rid))
sh("chmod 664", f"sudo -n chmod 664 '{RULES}' && sudo -n stat -f '%Sp %Su:%Sg' '{RULES}'")
wait_for(lambda: caps().get("filter", {}).get("state") != "verified", 20)
time.sleep(1)
snap("rules file rejected (expect degraded, rule not verified; curl may still be blocked by the filter's previous table, which is not claimed)")
show("rule.verify (rejected)", verify(rid))
sh("chmod 644", f"sudo -n chmod 644 '{RULES}' && sudo -n stat -f '%Sp %Su:%Sg' '{RULES}'")
wait_for(lambda: caps().get("filter", {}).get("state") == "verified", 30)
snap("after restore (expect verified after a fresh ack)")
show("rule.verify (restored)", verify(rid))
show("rule.remove", remove(rid))
time.sleep(2)
snap("after remove (expect 0 rules, curl 200)")
