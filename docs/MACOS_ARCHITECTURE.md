# Axiom for macOS — architecture

Status: in development on branch `buba/macos`
Target: macOS 13 Ventura and later, Apple silicon (arm64) and Intel (x64)

This document is the contract between the macOS components. Windows behaviour is unchanged.

## 1. Components

```text
/Applications/Axiom.app
  Contents/MacOS/Axiom                         Avalonia desktop app (Axiom.Desktop.Avalonia.MacOS), runs as the user
  Contents/Resources/service/axiomd            Axiom.Service published for macOS, runs as root via launchd
  Contents/Library/SystemExtensions/
    com.axiom.firewall.filter.systemextension  Swift NEFilterDataProvider (AxiomFilter), runs as root, managed by macOS
/Library/LaunchDaemons/com.axiom.service.plist launchd job for axiomd
/Library/Application Support/Axiom/            machine data (database, shield, privacy, filter state)
~/Library/Application Support/Axiom/           per-user UI settings
```

| Windows piece | macOS piece |
|---|---|
| Windows service `Axiom.Service` | launchd daemon `axiomd` (same `Axiom.Service` project, `net10.0` target) |
| Named pipe with SID ACL | Same .NET `NamedPipeServerStream`, which is a Unix domain socket on macOS, at `/var/run/axiom/axiom.sock`. The daemon checks the peer uid with `getpeereid`. |
| Windows Firewall rules owned by Axiom | Rule table enforced by the AxiomFilter system extension |
| IP Helper connection table + ESTATS bytes | Flow events and byte reports from AxiomFilter; libproc socket enumeration as fallback |
| DNS proxy on 127.0.0.1:53 + adapter DNS rewrite | Same `DnsProxyServer` on 127.0.0.1:53 + `networksetup -setdnsservers` per network service, restored on stop (fail-safe identical in spirit) |
| Process identity (path, signer, Store package) | Path from `proc_pidpath`, signer from code signature (`codesign`/Security), bundle id from `Info.plist` |
| DPAPI secrets | Keychain (desktop host) |
| MSIX / Setup | `Axiom.app` + installer `.pkg`, `scripts/macos/*` |

## 2. Platform data roots

`Axiom.Contracts.AxiomPaths` decides roots:

- machine data: Windows `%ProgramData%\Axiom`; macOS `/Library/Application Support/Axiom`; Linux `/var/lib/axiom`
- user data: `Environment.SpecialFolder.LocalApplicationData/Axiom` (macOS: `~/Library/Application Support/Axiom`)
- `AXIOM_DATA_DIR` overrides as today.

`Environment.UserInteractive` is always true on Unix, so service-mode detection on macOS uses `AXIOM_SERVICE=1` (set in the launchd plist) or `geteuid()==0`.

## 3. Filter extension ⇄ daemon contract

### 3.1 Rules (daemon → filter)

The daemon owns the rule list and writes it atomically (write temp + rename) to

`/Library/Application Support/Axiom/filter/rules.json` (root:wheel 0644)

```json
{
  "schemaVersion": 1,
  "generation": 42,
  "failOpen": true,
  "rules": [
    {
      "id": "0f8b5c1e-...-guid",
      "appPath": "/Applications/Foo.app",
      "direction": "outbound",
      "action": "block",
      "protocol": "any",
      "remoteAddresses": ["1.2.3.4", "10.0.0.0/8"],
      "remotePorts": "80,443,1000-2000",
      "enabled": true
    }
  ]
}
```

- `direction`: `outbound` | `inbound`. `action`: `block` | `allow`. `protocol`: `any` | `tcp` | `udp` | `icmp` (matched as not-filtered for now).
- `appPath` matches the flow's process executable path exactly, or any executable inside it when `appPath` is a directory/bundle (prefix + `/`). Empty `appPath` or `*` means any app.
- `remoteAddresses` empty = any. Entries are IPs or CIDRs; the token `*` = any.
- `remotePorts` null/empty = any.
- Semantics match Windows Firewall: an enabled matching **block** rule wins over any allow rule; with no match, traffic is allowed (default allow, as Windows default outbound).
- The filter watches the file (DispatchSource on the directory) and reloads within 1 s. If the file is missing or invalid the filter keeps the last good table (or allows everything at first start: fail-open).

### 3.2 Flow events (filter → daemon)

The daemon listens on a Unix stream socket `/var/run/axiom/filter.sock` (root:wheel 0600). The filter connects as a client, reconnects every 2 s when the daemon is down, and never blocks a verdict on the socket (bounded in-memory queue, drop oldest).

Newline-delimited JSON, one object per line:

```json
{"type":"flow.open","id":"<uuid>","ts":"2026-11-10T10:13:18.756Z","pid":1194,"path":"/usr/bin/curl","direction":"outbound","protocol":"tcp","localAddress":"10.0.2.15","localPort":53122,"remoteAddress":"17.253.144.10","remotePort":443,"remoteHost":"apple.com","verdict":"allow","ruleId":null}
{"type":"flow.stats","id":"<uuid>","ts":"...","bytesIn":1234,"bytesOut":567}
{"type":"flow.close","id":"<uuid>","ts":"...","bytesIn":1234,"bytesOut":567}
{"type":"filter.hello","ts":"...","version":"1.0.0","generation":42}
```

`remoteHost` is the hostname the app connected by, when macOS supplies it (also on DNS flows to port 53). Verdicts: `allow` | `block`.

### 3.3 Filter lifecycle

The desktop app installs/activates the system extension (OSSystemExtensionRequest) and enables the NEFilterManager configuration through a small Swift helper executable embedded in the app: `Axiom.app/Contents/MacOS/axiom-sysext` (`activate` | `deactivate` | `status`, JSON on stdout). The .NET app runs it as a child process.

## 4. Build and packaging

- .NET: `dotnet publish -r osx-arm64|osx-x64 --self-contained` for `Axiom.Desktop.Avalonia.MacOS` and `Axiom.Service` (builds on Linux).
- Swift: `macos/AxiomFilter` built with Xcode Command Line Tools (`macos/build.sh`), on a Mac or the macOS CI runner.
- `scripts/macos/package-app.sh` assembles `Axiom.app`, signs (Developer ID when `AXIOM_SIGN_IDENTITY` is set, ad hoc otherwise), and builds `Axiom.pkg`.
- Release signing/notarization needs an Apple Developer Program team with the Network Extension capability. Development builds run ad hoc signed on a Mac with SIP disabled and `systemextensionsctl developer on`.
