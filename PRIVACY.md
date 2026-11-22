# Axiom Privacy Policy

**Effective date:** 2026-11-22
**Website policy:** https://opendkg.org/privacy/
**Contact:** contact@opendkg.org

## 1. Summary

Axiom is a local-first network monitor, firewall policy manager, and AI coding agent protection console affiliated with the OpenDKG open-source initiative.

- **No telemetry or user accounts:** OpenDKG and Axiom do not collect usage analytics, crash telemetry, advertising identifiers, or account profiles.
- **Local storage by default:** Network history (`axiom.db`), local settings, firewall baselines, and non-sensitive hook metadata (`agent-evidence.jsonl`) remain on your device and can be deleted at any time.
- **Optional external features:** Outbound connections happen only for user-enabled features or release checks described below.

## 2. Optional and User-Controlled Network Features

Core local monitoring operates without sending telemetry. Outbound network connections occur only for the following features:

1. **Blackbox and OriginTrail DKG Threat Sharing (Consented / Toggleable)**
   - During Complete installation, First-Run setup, or via toggles in Agent Protection and Blackbox Configure, you choose whether Blackbox automatic community threat sharing or manual indicator reporting is enabled.
   - Shared sightings contain sanitized indicators and structured threat metadata; local custom rules and local credentials are excluded.
   - Public CC0 OriginTrail DKG replicas may keep published sightings even after retraction.
   - Turning automatic sharing off keeps local Blackbox guard blocking active without publishing sightings.

2. **Release Update Checks (Toggleable)**
   - When enabled (*Settings -> Updates -> Check for updates*), Axiom queries GitHub Releases (`https://api.github.com/repos/OpenDKG/Axiom/releases/latest`) on startup, every 6 hours, or when you click *Check for updates now*.
   - No installation ID or hardware identifier is sent; GitHub receives standard HTTP transport metadata and the `Axiom/<version>` User-Agent header.

3. **Privacy Shield DNS (Opt-in / Complete Install)**
   - When enabled, allowed DNS queries are forwarded to the upstream resolver you choose (such as Cloudflare DNS-over-HTTPS `1.1.1.1` or a custom resolver), and enabled public blocklists are downloaded when refreshed.

4. **Opt-in External Integrations (Off by Default)**
   - **VirusTotal (`VT Check`):** Submits only the SHA-256 hash of a file you explicitly select using your own API key; files are never uploaded.
   - **Community Feed:** Downloads indicator hashes only from the HTTPS feed URL you enable.
   - **AI Analyst:** Uses local Ollama by default; an external provider receives only the prompt and redacted summary you choose to submit.

## 3. Third-Party Services

Optional third-party components and services (including Umanitek Blackbox, OriginTrail DKG nodes, GitHub, Cloudflare, VirusTotal, and external DNS or model providers you configure) operate under their own privacy policies and terms.

## 4. Regional Disclosures (EU, Switzerland, and United States)

### European Union and EEA (GDPR)

- **Legal bases:** Under Art. 6(1) GDPR, optional Blackbox/DKG threat sharing and opt-in integrations rely on your **consent** (Art. 6(1)(a)), which you may withdraw anytime in Axiom settings. Responding to inquiries sent to `contact@opendkg.org` relies on **legitimate interests** (Art. 6(1)(f)).
- **Rights:** Where OpenDKG holds personal data (for example, correspondence sent to `contact@opendkg.org`), you may request access, rectification, erasure, restriction, portability, or lodge a complaint with your local EU/EEA supervisory authority. Local data on your device stays under your control.

### Switzerland (revFADP / nDSG)

- Under Art. 19 of the Swiss Federal Act on Data Protection (revFADP), note that GitHub, Cloudflare, decentralized DKG peers, and optional third-party providers operate infrastructure outside Switzerland (including the EU and United States).
- You may request access to or deletion of correspondence held by OpenDKG and may contact the Swiss Federal Data Protection and Information Commissioner (FDPIC / EDÖB).

### United States (CCPA/CPRA and Federal Transparency)

- OpenDKG and Axiom do **not** sell personal information, do **not** share personal information for cross-context behavioral advertising, and do **not** track users across third-party apps or websites.
- California and other US residents may contact `contact@opendkg.org` to request access to or deletion of correspondence held by OpenDKG.

## 5. Contact

- **Email:** contact@opendkg.org
- **Web privacy policy:** https://opendkg.org/privacy/
- **Issues:** https://github.com/OpenDKG/Axiom/issues (avoid posting personal data or private paths; see [SECURITY.md](SECURITY.md))
