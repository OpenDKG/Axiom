# Privacy Shield VM test plan

These checks require disposable Windows 10/11 VMs. They are **not executed on the user's workstation**
and must not be run without explicit approval. Record the VM image, adapter type, DNS mode, VPN
product and result for every row.

## 1. Baseline and recovery

- Clean VM, no Axiom service running: service starts with Privacy Shield disabled and no port is
  opened.
- Save DNS with the UAC helper; enable the resolver on port 53; point one adapter at `127.0.0.1`.
- Resolve a known public name and an allowed private/corporate name.
- Restore DNS with the UAC helper and verify the original static/DHCP values are returned.
- Kill the service while the adapter points at loopback; confirm the documented recovery path and
  restore works.
- Uninstall with the adapter still pointed at loopback; verify uninstall/recovery instructions and
  that no background resolver remains.

## 2. Network lifecycle

- DHCP and static IPv4.
- IPv6-only and dual-stack adapters.
- Wi-Fi disconnect/reconnect, Ethernet unplug, sleep/wake, dock/undock.
- VPN split-DNS and full-tunnel DNS.
- Corporate DNS that only resolves internal names.
- Adapter change while the resolver is active.

Expected: visible `Error`/conflict status when the resolver cannot bind or upstream discovery fails;
no silent loss of the old DNS settings; restore succeeds.

## 3. Resolver behavior

- UDP and TCP queries, IPv4 and IPv6.
- Blocked domain returns NXDOMAIN; allowed domain returns the upstream answer.
- Truncated UDP response causes a TCP retry and succeeds.
- Oversized/malformed/truncated query is rejected without crashing the service.
- Upstream timeout, SERVFAIL and unreachable upstream produce a visible error, not a false success.
- Query ID, question and flags are preserved.
- Port 53 conflict with an existing resolver produces a clear error; a test-only high port works.
- DoH/DoT/DoQ and hardcoded IP traffic are detected/documented as bypass, not claimed blocked.

## 4. Rules and sources

- Basic/Balanced/Strict profiles select the expected categories.
- Allowlist wins over starter, custom and downloaded rules.
- Custom list import rejects malformed/oversized inputs and stays within IPC limits.
- Catalog update: successful HTTPS source, 404/timeout, oversized response, malformed content,
  duplicate domains, and interrupted update.
- Successful update atomically replaces the previous file; failed update leaves the previous rules
  active and shows the source error.
- Restart service offline and confirm the last verified local rules load.

## 5. Performance

Measure with a representative 300k-domain ruleset:

- resolver ready after service start;
- cache-hit and upstream latency p95 (no guarantee; record actual);
- idle CPU and working set;
- update duration for a 500k-line list;
- no full-list scan per query (profile or instrument the lookup path).

## 6. Privacy and access

- No DNS query text is written to SQLite/JSON by default.
- Counters reset on restart.
- Another Windows user cannot read the per-user settings/rules files.
- No DNS history is sent to MCP, Blackbox, DKG or an AI provider.
- Settings and rules survive upgrade but are removed/retained according to the uninstall policy.

## Current status

The code-level tests cover policy normalization, DNS parsing, UDP blocking, UDP forwarding, TCP
blocking, source download/parse and atomic rule-store round trips. The VM matrix above remains a
release gate for the `Active`/automatic-adapter path.
