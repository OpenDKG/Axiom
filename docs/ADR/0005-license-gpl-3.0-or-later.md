# ADR 0005 — GPL-3.0-or-later and the open-source distribution model

- **Status:** accepted
- **Date:** 2026-11-03
- **Milestone:** licensing baseline
- **Builds on:** ADR 0001–0004, Handoff V2 §Q

## Context

Handoff V2 requires a **true open-source project, completely free**, with no paid features,
advertising, tracking or mandatory account. V2 proposes GPL-3.0-or-later for the desktop and service,
with separate MIT/Apache-2.0 packages for optional integrations. The `Netrigil` repository is
private and the owner approved the license.

Until now the project had no chosen license; the README said "license not selected". That blocked
public distribution and made contribution terms unclear.

## Decisions

### 1. GPL-3.0-or-later for desktop, service and core libraries

All production projects (`Contracts`, `Core`, `Infrastructure.Windows`, `Persistence`, `Service`,
`UI`, `Desktop`) and the tests are GPL-3.0-or-later. Derivatives must remain open source; users keep
the freedom to use, modify and redistribute. Commercial distribution and paid support remain allowed.

### 2. SPDX identifier in every source file

`SPDX-License-Identifier: GPL-3.0-or-later` in `.cs` and `.xaml` files; `LICENSE`, `NOTICE` and
`THIRD_PARTY_NOTICES.md` at the root. The license is visible per file, not only in the README.

### 3. Separate MIT/Apache-2.0 packages for integrations

`integrations/agent-security-memory` and similar modules may be permissive, but must not contain
GPL-only code and must keep their own notice files. This allows DKG registry ecosystems without
mixing license regimes.

### 4. DCO instead of a CLA

Contributions are accepted with `Signed-off-by` (Developer Certificate of Origin), without copyright
assignment. This avoids a CLA that discourages part of the open-source community.

### 5. Generated third-party license inventory

`THIRD_PARTY_NOTICES.md` is generated from `packages.lock.json` and nuspec metadata. All dependencies
are MIT or Apache-2.0; no GPL/AGPL third-party code is included. The .NET runtime in the
self-contained build is MIT.

## Consequences

Positive:

- A clear, verifiable license and a path to a public release.
- GPL prevents closed derivatives while allowing commercial distribution and support.
- Permissive integrations remain usable by other ecosystems.
- DCO and SPDX reduce legal uncertainty around contributions.

Negative / risks:

- Distributing a binary requires making the corresponding source available.
- GPL code cannot be copied into MIT/Apache modules; discipline is required when refactoring.
- Some companies avoid GPL; this is an accepted consequence of the choice.
- External feed licenses (VT, Blackbox, DKG, GeoIP) still require separate review.
- This is not legal advice; a legal review is required before the first public release.

## Alternatives considered

| Alternative | Why not |
|---|---|
| MIT/Apache-2.0 | Allows closed derivatives; V2 requires copyleft and true open source |
| AGPL-3.0 | Intended for hosted services; a desktop tool does not need network copyleft |
| Dual license (GPL + commercial) | No commercial publisher or need at this stage |
| No license (all rights reserved) | Not open source; blocks contributions and distribution |
| GPL-2.0 | Apache-2.0 dependencies are incompatible with GPLv2 |

## Follow-up decisions

- Legal review before the first public release.
- Signed-release and source-tarball rules (FND-009).
- License policy for the GeoIP database and threat feeds (FND-010/012).
