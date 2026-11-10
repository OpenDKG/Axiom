# Privacy Shield (local DNS filtering)

Privacy Shield is an optional, **default-disabled** local DNS policy module. It runs inside the
existing `Axiom.Service` process and listens only on loopback. It does not change Windows DNS
settings, the hosts file, firewall rules, agent configuration or certificates.

## What is implemented

- A deterministic local DNS policy engine with:
  - Basic, Balanced and Strict profiles;
  - telemetry, ads, tracking, analytics, malware and custom categories;
  - exact and parent-suffix matching;
  - allowlist precedence over profile and custom block rules;
  - plain-domain, hosts-file, DNSMasq and wildcard list parsing;
  - IDN normalization and invalid-domain rejection.
- A small starter set of manually reviewed telemetry/advertising/tracking domains. This is not a
  third-party blocklist and is not presented as complete protection.
- A loopback DNS proxy that:
  - accepts UDP and TCP DNS queries on `127.0.0.1` and, when available, `::1`;
  - returns NXDOMAIN for blocked questions before contacting an upstream;
  - forwards allowed UDP queries over UDP and TCP queries over TCP, with bounded timeouts;
  - keeps in-memory query/allowed/blocked/error counters and top blocked domains only.
- A Privacy Shield page with profile/category controls, custom allow/block lists, local list import,
  verified source catalog, resolver status, **live statistics (2-second refresh while selected)** and
  explicit UAC DNS integration.
- A bounded local **blocked-query history** (last 1,000 entries) containing the blocked domain,
  category, timestamp and, when Windows exposes it, the requesting application name/path. It is
  stored in the service account's local profile
  (`%LOCALAPPDATA%\Axiom\privacy-shield-blocked.jsonl` as seen by that account), never includes
  allowed queries, and has a clear action. It is deliberately not shared machine-wide because it is
  the only DNS data kept. This is the one deliberate DNS history exception; it is local and
  user-clearable. Recent blocks are refreshed every 2 seconds and can be **Allowed** or **Blocked**
  directly from the row. Allow adds the domain to the custom allowlist; Block removes it from the
  allowlist and adds it to the custom blocklist.
- Application attribution is best-effort: Axiom maps the loopback UDP/TCP source port to the owning
  PID through the Windows owner tables. Protected or already-exited processes may show
  `unknown app`.
- A catalog of **five HTTPS-only, license-labelled** sources (HaGeZi Multi PRO, OISD Big,
  WindowsSpyBlocker, The Block List Project Ads and Tracking). A source update downloads with a
  20 MB/45 s bound, parses and normalizes domains, then atomically replaces the previous ruleset only
  if every selected source succeeds. The previous rules file is retained. The local cap is 500,000
  unique domains, and every selected source keeps a reserved share so a large list cannot starve a
  smaller telemetry list such as WindowsSpyBlocker.
- Licenses: HaGeZi and OISD are GPL-3.0, WindowsSpyBlocker is MIT, and the two Block List Project
  lists are Unlicense. Axiom downloads them from the upstream URL at runtime and does not bundle the
  list bytes; no separate approval is required beyond the license and attribution terms. Upstream
  terms must be rechecked before adding or redistributing a list. See
  [third-party notices](../THIRD_PARTY_NOTICES.md).
- Settings and the compiled ruleset live in `%ProgramData%\Axiom\privacy-shield.json` and
  `privacy-shield-rules.json` when the installed service runs them, so the state survives service
  reinstalls and is not hidden in the LocalSystem profile. A portable/interactive run keeps
  `%LOCALAPPDATA%\Axiom\`; existing service data is copied to ProgramData once on first start.
  Settings contain no DNS query history; the separate bounded blocked-query history described above
  is the only DNS history.

## DNS-only boundary

Privacy Shield is **not a VPN, proxy or network gateway**. It filters DNS name resolution:

1. The optional UAC helper changes the selected adapter's DNS server to `127.0.0.1` after explicit
   elevation approval. The service itself never changes adapter DNS silently.
2. Applications send DNS questions to the Windows resolver, which now reaches Axiom on port 53.
3. Axiom returns NXDOMAIN for blocked names and forwards allowed questions to the upstream.
4. Applications still connect directly to the returned destination IPs; their TCP/UDP traffic does
   not pass through Axiom.

If adapter DNS is not pointed at the resolver, normal Windows DNS bypasses Privacy Shield entirely
and the counters remain zero. The page states this explicitly: when the resolver is running but no
adapter DNS points at `127.0.0.1`, **Resolver statistics** explains that nothing uses the resolver
and points to the UAC helper. Once an adapter points at it, the adapter row shows
`127.0.0.1 · Privacy Shield` and the hint disappears as soon as the first query arrives.
Manual queries to `127.0.0.1` still work for testing, but they do not prove that system-wide
traffic is filtered.

### Browser secure DNS (DoH)

A browser switched to its own DNS-over-HTTPS provider stops asking Windows, so even a correctly
pointed adapter sees none of its queries. The page reads the Chrome and Edge
`User Data\<profile>\Preferences` files and Firefox `Profiles\<profile>\prefs.js`, and shows a
warning when a profile uses secure DNS (`dns_over_https.mode` `secure`, or `automatic` with a
custom template) or Firefox `network.trr.mode` 2 or 3. The warning names the browser and profile
and where to turn secure DNS off.

This is detection only; no browser setting is changed and nothing is written to the profile. It
does not read Windows system DoH: that applies to a configured public DNS server, and an adapter
pointed at `127.0.0.1` has no DoH template.

## What is not implemented

- A WFP callout driver, hosts-file editing or LAN-wide resolver.
- DNS-over-HTTPS, DNS-over-TLS or DNS-over-QUIC interception.
- Full per-process attribution for every query: Axiom resolves the loopback source port through the
  Windows owner tables for **blocked** queries only. Protected or already-exited processes may show
  `unknown app`.
- Automatic adapter DNS changes by the service itself. A separate explicit UAC helper can save and
  change one selected adapter; it never elevates silently.

## Manual use

1. Start Axiom in service mode (`Axiom.Desktop.exe --service` or the bundled service).
2. Open **Privacy Shield**, choose a profile and optional custom rules, then click **Apply settings**.
3. Start the resolver on port **53**. Port 53 is required for normal Windows DNS; another port is
   useful only for local testing.
4. Before changing adapter DNS, note the existing DNS servers so they can be restored.
5. Use **Set adapter DNS (UAC)** on the Privacy Shield page. Windows shows its elevation prompt;
   Axiom saves the current values and points only the selected adapter at `127.0.0.1`/`::1`.
   Alternatively, use the explicit script:
   `.\scripts\privacy-shield-dns.ps1 -Action Save`
   `.\scripts\privacy-shield-dns.ps1 -Action Enable -InterfaceAlias "Ethernet"`
6. If the network requires corporate or VPN DNS, put that resolver in **Upstream DNS** instead of
   relying on automatic system discovery.
7. Use **Restore saved DNS (UAC)** or `.\scripts\privacy-shield-dns.ps1 -Action Restore` immediately
   if resolution fails.

The helper requires administrator approval for each action and is never invoked automatically by
the service.

If Windows DNS is already pointed at `127.0.0.1`, the service cannot discover the old upstream.
Privacy Shield then uses a conservative public fallback (`1.1.1.1`/`9.9.9.9`) and reports it; set
the correct upstream explicitly on managed or corporate networks.

Recommended explicit upstreams (plain DNS, one IP or `IP:port`; DoH/DoT are not supported):

- `1.1.1.1` or `1.0.0.1` — Cloudflare; verified working with this resolver.
- `9.9.9.9` or `149.112.112.112` — Quad9.
- `94.140.14.14` or `94.140.15.15` — AdGuard DNS.

Use the DNS server provided by your VPN, corporate network or router when one is required. Leaving
the field empty keeps the current Windows DNS servers. After enabling the resolver, verify with
`Resolve-DnsName example.com -Server 127.0.0.1`; a blocked catalogued domain should return
“DNS name does not exist”.

## Safety and recovery

- A **complete installation** enables Privacy Shield once, during setup, with the Balanced profile
  and all five sources selected. A **partial installation** leaves it off. Updates and later starts
  never enable it by themselves, and no mode changes adapter DNS silently.
- Stopping the resolver leaves the Windows adapter pointing at a non-responsive loopback address
  if the user manually configured it. Restore the adapter DNS or set a real upstream before
  stopping the resolver.
- The service never modifies DNS adapter state, so a crash or uninstall cannot silently rewrite it.
  Recovery is the same manual adapter setting.
- No DNS payload is uploaded, sold or sent to AI/DKG/Blackbox services.
- Query counters reset when the resolver restarts.

## Limitations

DNS filtering is not complete traffic filtering. It does not block hardcoded IPs, application DNS
resolvers, DoH/DoT/DoQ, VPN tunnels or answers cached before activation. A blocked query is not proof
that a completed connection was prevented. Domain sharing between telemetry and legitimate services
can cause false positives; use allow rules and verify Windows Update, Defender, certificate
revocation, activation and enterprise connectivity after enabling a strict profile.

## Verification

- `PrivacyShieldPolicyTests` cover normalization, list parsing, allow precedence and profile rules.
- `DnsProxyTests` cover query parsing, NXDOMAIN construction and blocked-query forwarding behavior.
- The Windows DNS adapter is not modified by any test or by this module.
