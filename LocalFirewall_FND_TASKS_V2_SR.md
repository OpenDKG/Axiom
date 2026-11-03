# LOCALFIREWALL — FND TICKETS V2.0 (operativni vodič za DeepSeek V4.1 Flash)

**Autoritet:** `LocalFirewall_HANDOFF_V2_SR.md`; ovaj dokument je detaljna fazna razrada. Radni naziv `LocalFirewall`. Ovo nisu potvrđene implementirane funkcije. **Samo jedan ticket po prolazu.** Status svakog ticketa se određuje na osnovu stvarnog koda i testova, a ne prethodne poruke agenta.

## Univerzalni format rada za svaki ticket

**Ulaz:** postojeći repo + master handoff + ovaj dokument + korisnički odobren `FND-xxx`. 

**Algoritam:** (1) `git status` i pregled projekta; (2) proveri da prethodni neophodni ticket-i zaista imaju kod i testove; (3) napiši plan do 8 konkretnih radnji; (4) preuzmi maksimalno 1 funkcionalnu celinu; (5) implementiraj minimalne interfejse; (6) testiraj; (7) dostavi izveštaj, ne radi sledeći ticket. Ako postoje drugi nedovršeni PR-ovi, ne briši tuđi kod i ne radi rebase/merge bez korisnikove naredbe.

**Obavezni output:** `FILES CHANGED`, `FUNCTIONALITY`, `MOCKS/STUBS`, `BUILD`, `TESTS`, `WINDOWS MANUAL VERIFICATION`, `SECURITY`, `PERFORMANCE`, `KNOWN RISKS`, `NEXT TICKET`, `ROLLBACK`. Ako nema SDK-a, nema Windows OS-a ili nema admin VM-a: označiti `NOT RUN`, ne izmišljati rezultate. Koristi dokumentovane linkove iz mastera i pinned paketne verzije.

## CORE — izvršavati redom

### FND-001 — Repository & functional demo WPF shell (POČETI OVDE)
**Prereqs:** nijedan; ukoliko ima koda, pregledaj stanje i nastavi bez prepisivanja. 
**Scope:** `LocalFirewall.sln`; `Contracts`, `Core`, `Infrastructure.Windows`, `Persistence`, `Service`, `UI` i prvi `Core.Tests` skeleton; `Nullable=enable`, analyzers, locked packages, `.gitignore`, global SDK requirement, dokumentacija. Pravi WPF MVVM shell sa stranama `Overview`, `Connections`, `Applications`, `Events`, `Firewall`, `Files`, `Security`, `Settings`; navigacija mora raditi; originalan UI. Barem dva mock grafikona (up/down) i reproduktivni generator **označen DEMO DATA**, marker događaja na vremenskoj liniji, tabla sa app/remote/country placeholder/status. Mock može imati virtualizovanu tabelu. Dodaj izričit status `No system monitoring / No firewall control`.
**NE:** nema Windows Service instalacije; nema stvarnog sniffinga; nema admin prava; nema firewall pravila; nema network lookups; nema DKG, VT, Blackbox; nema instaler ili kernel koda.
**DoD:** aplikacija se pokreće, navigacija radi, UI skalira, demo se ne predstavlja kao realnost; `dotnet restore/build/test` na Windows runner-u; CI za build + tests; `README`, `docs/ARCHITECTURE`, `SECURITY_MODEL`, `TEST_MATRIX` i `docs/ADR/0001-native-stack.md`. Screenshot ili opis koraka za ručnu vizuelnu proveru. Nula izmena firewall rule set-a.

### FND-002 — Read-only Windows TCP/UDP + app attribution
**Prereq:** 001.
**Scope:** IP Helper `GetExtendedTcpTable`, `GetExtendedUdpTable`, IPv4/v6; DTO za connections; testirani 64-bit P/Invoke; PID+startTime; path/signature metadata samo gde pouzdano; 1–2s refresh cancellable; UI prikazuje stvarne podatke sa source badge, a mock isključen u live modu.
**NE:** bez ETW byte attribution, firewall write, admin services, DKG.
**DoD:** kontrolisani TCP IPv4/v6 i UDP test procesi se vide; PID i endpoint potvrđeni; UDP remote `unknown` ako se ne može dokazati; poll-only edge-case objašnjen; service nije potreban za read-only dev test ako OS dozvoljava.

### FND-003 — Windows Service + secure Named Pipe IPC
**Prereq:** 002.
**Scope:** Windows Worker Service samo u izolovanoj VM; least privilege review; Named Pipe ACL + SID binding + request validation + authentication; read-only commands i reconnect; WPF unprivileged; health/status + staleness.
**NE:** bez privilegovanog `rule.write` endpointa, bez otvorenog TCP/HTTP porta, bez PowerShell izvršavanja.
**DoD:** jedan autorizovan UI klijent dobija podatke; neovlašćeni korisnik nema pristup; restart servisa/UI uspešno reconnect; poruka duža od limita odbijena; nema generičkog execute endpointa; servis nije instaliran na produkcionoj mašini.

### FND-004 — ETW traffic estimate + realtime graphs
**Prereq:** 003.
**Scope:** namenski ETW collector u Windows adapteru; testirati verziju provider/event field; bounded channel; 1s buckets; up/down stats i per-app attribution; event-loss/quality; stabilno zatvaranje kolektora; real charts i timeline. Izmeriti `bytes` semantiku. Nema packet payload.
**DoD:** kontrolisani TCP/UDP transfer proizvodi grafičke promene bez uvećavanja brojača dupliranjem; unknown i VPN su označeni kao partial; 1000 kratkih konekcija i overload ne dovode do OOM; monitor update ≤1–4 Hz.

### FND-005 — SQLite history, retention, export
**Prereq:** 004.
**Scope:** SQLite WAL, migrations, prepared SQL, indexed normalized events, timed buckets, apps/flows, settings, query paged, CSV/JSON, retention, diagnostics. UI history filtriranje.
**DoD:** 24h synthetic data replay u testu; podaci opstaju reboot-u i restart-u; retention smanjuje bazu; timezone/long counters konzistentni; database corruption/locked handled, bez upisivanja sirovih payload-a.

### FND-006 — Real OS firewall click-to-block (PRVA WRITE FAZA)
**Prereq:** 005; Windows VM sa snapshotom, eksplicitno korisničko odobrenje.
**Scope:** `INetFwPolicy2` / `INetFwRule` COM, `IFirewallPolicyAdapter`; samo own rule prefix/UUID; outbound i inbound app-scope; audit; pending/apply/read-back/reconcile; rollback; UI confirmation; drugi program ostaje netaknut.
**NE:** global policy default deny, BFE disable, automatika svih connection blockova, shell komande.
**DoD:** test app može da se poveže pre block-a, ne može nakon pravilnog scope block-a (test mreže), a druga app može; UI exit/reboot ne briše rule; unblock uklanja isključivo own rule; external block conflict prikazan; verified != unconditional guaranteed. Log dokaz OS rule-a i rollback.

### FND-007 — Alerts, WFP blocked-event evidence, notifications
**Prereq:** 006.
**Scope:** New app / first destination / rule applied/failed; WFP net-event subscription uz feature-check; ako nije dostupno, fallback 5157 samo uz informisani pristanak za audit; dedup, severity, quiet hours, grouped timeline.
**DoD:** kontrolisani block event reprodukovan i pravilno atributiran ili označen unknown; nema notification storm; 5156/5152 global audit ne uključuje se podrazumevano.

### FND-008 — Scope rules, profiles, import/export
**Prereq:** 007.
**Scope:** rule schema: profiles, protocol, ports, CIDR i manual switching; pregled external rules read-only; portable own-rule import/export uz validaciju; konflikt/reconcile. Automatic switching samo ako je posebno autorizovan i testiran.
**DoD:** test nekoliko IP/port/profile kombinacija u VM; konfliktnom scope-u prikazuje reason; import ne dira external OS rules, rollback radi; nema general default-deny.

### FND-009 — Installer, service security hardening, recovery, QA
**Prereq:** 008.
**Scope:** WiX installer (license audit), uninstall remove only own rules, service recovery, `localfirewall-cli status/list-owned/disable-owned` (privilegovano), signed release proces, SBOM, dependency scan, 24h soak, startup/upgrade/reboot/sleep. Nema skrivenih mrežnih zahteva.
**DoD:** clean install i upgrade u VM, uninstall ne utiče na Windows/tuđe rule setove; reproducible CI; integracioni matrix; rollback i recovery čak kad UI nedostupan; performance izveštaj.

### FND-010 — GeoIP, DNS hints, event graphs & UX completion
**Prereq:** 009.
**Scope:** offline GeoIP DB sa licencom i datumom, zastave i `unknown`; DNS observations (probabilistic, DoH caveat); originalan grafikon sa event markers/specific app filter/zoom; theme/keyboard/screen-reader, localized labels; UI 10k row virtualized; perf optimizacije.
**NE:** IP=hostname claims, remote geolocation lookups default, heavy Electron or static wallpaper UI, global default-deny.
**DoD:** offline, UI swift; flag maps to OS remote IP only if confidence; 10k historic events bez freeze; graph marker click daje stvarni event; meren CPU/RAM/GPU; source status upozorenja jasna.

## ADD-ONS — jedna funkcija po ticketu, svaka van hot path-a

### FND-015 — File Tracker + local reputation (preporučeni prvi addon)
**Prereq:** stabilan core >=009. 
**Scope:** korisnik bira Downloads/desktop; FSW debounce/overflow, bounded queue i SHA-256 streaming; size gates, signature metadata, cache; kontrolisana opcija postojećeg Defender skeniranja uz proveru dostupnosti/licence. Display provenance/time. 
**DoD:** novi EXE detektovan; hash tačan; duplicate debounced; 5GB file ne zaleđuje disk/UI; locked file, fake signer, Defender disabled -> jasni statusi; bez upload-a, bez automatskog brisanja/karantina.

### FND-016 — External reputation provider gate / VirusTotal
**Prereq:** 015 i pregled VT dozvoljene upotrebe.
**Scope:** prvo implementiraj samo manual `Copy SHA-256` / `Open VirusTotal website` i neutralni `IReputationProvider` contract. Ako postoji dokaz o dozvoljenoj integraciji, odvojeni opt-in personal key adapter: hash-only lookup, limit 4/min i 500/dan, 429 backoff, local cache, no auto-file upload, never exposed keys, permission review.
**DoD:** bez legal approval-a nema VT API poziva u distribuibilnoj aplikaciji; offline Standard radi bez VT; unknown vs no detection jasno; test policy gate i rate limiter.

### FND-011 — Umanitek Blackbox compatibility (zadržan stari ID)
**Prereq:** stable 009; 010 opcioni; Blackbox doc/release pin.
**Scope:** `IBlackboxAdapter` health, capability detection, read-only redacted findings and imported signed indicators only putem dokumentovanih API-ja. Ako nema javnog interfejsa, spec i stub sa `Unsupported` i dokaz, ne scrape internal DB. No auto-install, no Hermes/OpenClaw subprocess in Standard.
**DoD:** kada Blackbox nije instaliran, 0 njegovih procesa; kada jeste, korisnik opt-in vidi samo realne evente; audit vs block status tačan; upstream regression/mock tests, provenance, no false partnership.

### FND-012 — OriginTrail DKG V10 adapter + signed bundles (zadržan stari ID)
**Prereq:** 009 i threat schema; verified API on pinned release.
**Scope:** `IDkgAdapter` public HTTP/CLI/MCP capability detection; local node samo Advanced; trusted signed bundle pipeline kao Standard feed; expiries, revocation, no per-connection RPC; consent. Prvo Base Sepolia testnet (ako je aktivan/podržan u pinovanoj verziji), bez token uplata bez naredbe.
**DoD:** validan potpis prihvaćen; tampered/expired/revoked odbijen; DKG ugašen = normalan lokalni firewall; sekreti i IP istorija nisu prosleđeni; postoji integracioni test sa real DKG (ako nema okruženja `NOT RUN`).

### FND-013 — Agent Security Research Memory (zadržan stari ID; grant kandidat)
**Prereq:** 012 adapter može biti izolovan u posebnom paketu; DKG V10 doc i lokalni test node.
**Scope:** samostalni agent-compatible MIT/Apache-2.0 paket (licence audit); dva agenta vode research task o javnom sumnjivom paketu/domainu; WM zapis, SWM peer collaboration i evidence/contradiction; jasno poštovati DKG project hierarchy/curator; UAL references; export result compatible with core threat schema.
**DoD:** REAL end-to-end agent -> WM -> SWM -> read -> report, test na real DKG; cold-start dokumentacija, reproducible demo, pinned version/release, declared egress and write authorities, no secrets sharing, SPDX/maintainer; ne prijavljivati grant kao dobijen.

### FND-014 — Optional TRAC publishing / grants / rewards (zadržan stari ID)
**Prereq:** 013 i korisnikova eksplicitna odluka o budžetu i mreži.
**Scope:** opciona VM publishing pipeline **samo verified evidence**, publish budget, idempotency, keys locally protected, gas fee preview, manual author approval, revocation/correction record. Contributor reward system izvan scope-a osim ako korisnik zatraži; osnovni firewall ne koristi TRAC.
**DoD:** prvo testnet; bez on-chain mainnet troška bez nove naredbe; ugrađen fee cap i approval; nema on-chain PII, URL tokena, seed fraza; verified provenance i status corrections.

### FND-017 — Wallet protection browser extension R&D
**Prereq:** 009; proof of signed transaction visibility and consent, no seed/keys. 
**Scope:** samostalni browser extension koji može (uz minimalne dozvole) da ispituje phishing/dangerous approvals i redaktovane wallet connect dApp indikatore; ne oslanjaj se na TCP-only visibility i ne tvrdi da vidi enkriptovan calldata bez extension/official wallet API. Trader Shield pokriva agent-only path ako vendor installed.
**DoD:** nema seed/private key capture, nema transaction signing, jasno permission UI, cross-browser security test; zero runtime impact kada extension nije instaliran.

### FND-018 — Optional Community reports, moderation and anti-abuse
**Prereq:** 012, `threat_evidence` model, opt-in privacy threat assessment.
**Scope:** redacted reports only with consent; no raw IP history/paths/file contents; verified publisher signature, reputation, anti-spam, dispute, expiry and correction/retraction, no automatic OS blocking from community. DKG SWM when supported vs signed bundle fallback.
**DoD:** false report cannot block popular benign site; revocation propagates to offline cache; deletion local; report provenance and consent recorded; no mandatory account/wallet for Standard users.

## Prioriteti i gotovost

**Prva faza za coding agenta:** `FND-001`. Ne počinjati sa DKG, VT ili wallet modulom jer se time krije odsustvo pravog monitora/firewalla. 
**Prvo korisno lokalno izdanje:** FND-001–006 (sa označenim kvalitetom telemetrije). 
**Stabilan public MVP:** FND-001–010 + bezbednosni audit + reproducible installer. 
**Dodatni moduli:** 015 → 016 opcionalno, 011 → 012 → 013 → 014; 017/018 odvojeno. 
**DoD svake faze** je minimum, ne zamena za standardnu code review i licence/security audit.
