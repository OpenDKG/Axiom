# LOCALFIREWALL — MASTER HANDOFF V2.0
## Nezavisan, besplatan, modularan Windows firewall + security monitor + opcioni OriginTrail/Blackbox sloj

**Datum:** 3. novembar 2026.  
**Jezik:** objašnjenja SR; nazivi tipova, interfejsa, API-ja i koda EN.  
**Radni naziv:** `LocalFirewall` (nije konačan brend).  
**Status:** specifikacija za razvoj, NE tvrdnja da je implementacija gotova.  
**Prioritet:** stvarna funkcionalnost > bezbednost > niska potrošnja > jednostavan UI > opciona integracija.  
**Autorstvo i cilj:** nezavisan, besplatan, modularan, javno dostupan open-source projekat; bez plaćenih korisničkih funkcija, reklama, praćenja korisnika ili obaveznog naloga. Finansiranje samo dobrovoljnim donacijama/grantovima/sponzorstvima bez uticaja na sigurnosne odluke.

> **OVAJ DOKUMENT JE AUTORITATIVAN ZA V2.** Ako postoji `LocalFirewall_HANDOFF_V1_SR.md`, tretiraj ga kao arhivsku tehničku referencu; V2 ima prednost u slučaju konflikta. Proveri postojeće stanje koda pre bilo kakvog menjanja. Nijedna dosadašnja specifikacija nije dokaz da repo, servis ili firewall već postoje.

---

# A. PRAVILA ZA DEEPSEEK V4.1 FLASH — PROČITATI PRVO

1. **Radi SAMO jedan ticket `FND-xxx` u jednom prolazu.** Za prvi prolaz obavezno `FND-001`, osim ako postojeći kod i testovi nedvosmisleno dokazuju da je već gotov. Nema automatskog prelaska u sledeću fazu.
2. **Ne pretvaraj demo u lažnu funkcionalnost.** Svaki mock grafikon ili događaj označiti `DEMO DATA`. Ne prikazivati `Protected`, `Blocked`, `Virus scanned`, `Connected to DKG` ili `Realtime monitoring` dok odgovarajući adapter nije pokrenut i proverljiv.
3. **Sistemsku zaštitu ne ugrožavati radi eksperimenta.** Bez menjanja Windows Firewall pravila, globalnih profila, servisa, startup stavki ili audit politike u FND-001–005. Prva pravila samo u izolovanoj Windows VM, tek u FND-006.
4. **Nema custom kernel/NDIS drivera u MVP-u.** Iskoristiti Windows Defender Firewall + WFP/COM i ETW/IP Helper. Ne gasiti Microsoft Defender Firewall, BFE, antivirus, VPN niti postojeće filtere.
5. **Ne kopirati tuđi UI, zaštićeni identitet, kod ili GPL projekat bez provere licence.** Referentni repozitorijumi služe za učenje; svaki preuzeti kod mora imati preciznu evidenciju licence i atribuciju.
6. **Ne pogađaj Win32 strukture i P/Invoke potpise.** Pre kodiranja pročitaj tačnu Microsoft dokumentaciju, ABI i podržani OS; napravi mali integracioni test. Ako web nije dostupan, zabeleži `UNVERIFIED_API`, implementiraj samo izolovan interfejs ili bezbedan skeleton.
7. **Ne obećavaj 100% sigurnost, antiviruse ili precizno merenje bajtova.** Svaki rezultat ima izvor, kvalitet i granice. `unknown` je bolji od izmišljenog statusa.
8. **Ne slati fajlove, URL-ove, IP logove, komande agenata, seed fraze, ključeve, putanje korisnika i sl. eksterno bez izričitog, granularnog pristanka i zakonitog osnova.** Osnovni režim radi offline.
9. **Nema direktnih shell komandi iz UI-ja u privilegovani servis.** Lokalni Named Pipe sa strogim ACL, tipizovanim ugovorom, proverom user SID i granicama zahteva.
10. **Po završetku svake faze obavezno**: promenjeni fajlovi; šta stvarno radi; šta je mock; restore/build/test komande sa stvarnim rezultatima; neuspešni testovi; bezbednosni rizici; koraci za ručnu proveru; rollback; naredni ticket. Bez automatskog merge-a i bez lažnog “test passed”.

**Prekid rada:** ako je uslov faze nemoguć bez admin prava, Windows VM, SDK-a ili dokumentacije, ne improvizuj nebezbedan workaround. Stani, iznesi blokadu i isporuči bezbedni deo zadatka.

---

# B. PROIZVOD — ŠTA KORISNIK DOBIJA

Korisnik vidi jednu **native Windows aplikaciju jednostavniju za korišćenje od tipičnog administratorskog firewalla**. Ona prikazuje koje aplikacije pristupaju mreži; kada, koliko približno uploaduju/downloaduju; IP, port, verovatnu zemlju servera, relevantni događaj na grafikonu; da li postoje proverljiva blokiranja ili upozorenja. Može da blokira/odblokira sopstvena pravila, vidi istoriju, lokalno pregleda sumnjive fajlove i opcionalno uključi dodatne izvore inteligencije i agent zaštitu.

## B1. Tri režima u istoj aplikaciji

| Režim | Podrazumevano | Obavezne komponente | Svrha |
|---|---|---|---|
| `Standard` | DA | UI + mali Windows Service + Windows native API + lokalni SQLite | Monitor i firewall, bez naloga, DKG, walleta, slanja telemetrije. |
| `Community` | NE | Standard + opcioni adapter za potpisane threat feedove + opt-in prijave | Lokalna zaštita ostaje nezavisna; prijave se šalju samo uz saglasnost. |
| `Advanced/DKG` | NE | Standard + poseban DKG/Blackbox proces ili eksterni instalirani runtime | Istraživanje, direktna DKG sinhronizacija, agenti; korisnik može potpuno da deinstalira ovaj modul. |

**Nijedan DKG čvor, Docker, Java, Node.js, Python, LLM ili GPU nije preduslov za Standard.** Korisnik koji nikad ne uključi dodatke ne sme imati njihove background procese. Ako source feed nije dostupan, Standard nastavlja da funkcioniše offline sa poslednjim bezbedno verifikovanim cache-om.

## B2. MVP (release v1)

- Pregled TCP/UDP IPv4/IPv6 po procesima tamo gde Windows pruža pouzdane podatke.
- Upload/download grafikoni na nivou aplikacije/sistema sa tačno objašnjenom metrikom i kvalitetom merenja.
- Vremenska linija događaja: new app, new destination, connection, suspicious reputation, block attempt, rule applied, rule error, file event.
- Jednostavna dugmad za per-app outbound/inbound block/unblock preko **Windows Firewall** sistema, sa OS read-back proverom i bez brisanja tuđih pravila.
- Lokalni SQLite, pretraga, ograničeno zadržavanje podataka i CSV/JSON export.
- Dark/light, originalan UI, pristupačnost, tabelarna virtualizacija, tray i nenametljiva upozorenja.
- Offline GeoIP zastavice kao enrichment uz legalno licenciranu bazu; za VPN/CDN/proxy prikazati neizvesnost.
- Auto-update **nije** preduslov za prvu lokalnu verziju. Javna ažuriranja tek posle signed-release i rollback modela.

## B3. Ne-ciljevi i granice

- Nije zamena za Microsoft Defender/antivirus/EDR; nema tvrdnje da je računar “100% safe”.
- Nema TLS MITM, instaliranja root CA sertifikata, dekriptovanja HTTPS, sistemskog snimanja sadržaja tastature ili screenshotova.
- Nema oslanjanja na DKG ili eksterne upite pri donošenju OS firewall odluka.
- Ne obećavati trenutnu **pre-first-packet** autorizaciju: običan COM firewall rule + događaj nakon pokušaja to ne garantuje.
- Nema globalnog “block all outbound”, “disable internet” ili lockdown režima u MVP-u.
- Nema automatskog karantina/brisanja fajlova, osim eventualno kasnije sa strogo testiranim Defender integracijama.
- Nema hosting/enterprise central management modula u osnovnom planu; korisnik ne želi usluge održavanja firmama.

---

# C. PLATFORMA I TEHNOLOGIJE

**Primarni release target:** Windows 11 x64 koji je podržan i ažuriran. **Best-effort:** Windows 10 x64, uz jasnu napomenu o stanju OS podrške. Konkretna mašina može koristiti Windows 10 Pro 21H2/build 19044, koji nema redovne sigurnosne ispravke; ne implicirati da je podržan samo zato što aplikacija uspe da se pokrene. Proveriti TFM/OS zahteve za `.NET 10` i WPF na ciljnoj mašini; objaviti incompatibility warning umesto lažne kompatibilnosti.

| Oblast | Predlog |
|---|---|
| Jezik | C# (nullable enabled), .NET 10 LTS, Windows-targeted |
| UI | WPF + MVVM (`CommunityToolkit.Mvvm` nakon provere licence) |
| Grafikoni | ScottPlot WPF (ili benchmarkovana alternativa sa dozvoljenom licencom) |
| Servis | .NET Worker Windows Service, zaseban proces od UI-ja |
| Firewall | COM `INetFwPolicy2` / `INetFwRule`; Windows Firewall kao enforcement |
| Network inventory | `GetExtendedTcpTable`, `GetExtendedUdpTable`, IPv4/IPv6 |
| Mrežni događaji | ETW + dokazana semantika event polja; WFP net-event kao izvor block evidencije |
| Lokalni IPC | Named Pipes, lokalni ACL, client SID autorizacija |
| Storage | SQLite WAL, migracije, batch-write, indeksi, retention |
| Installer | WiX MSI tek posle stabilnog servisa (proveriti licencu) |
| Testovi | xUnit / NUnit, fake adapters, Windows integration VM, soak/perf |
| OriginTrail | odvojeni adapter preko dokumentovanog DKG V10 HTTP/CLI/MCP interfejsa |
| Blackbox | odvojen adapter preko dokumentovanog/validiranog interfejsa; bez internog DB scraping-a |
| File scan | lokalni SHA-256, Authenticode, opciono postojeći Microsoft Defender sken |
| Security intelligence | provider-neutral signed local bundle, bez mrežnog dependency-ja u hot path-u |

**Zašto ne Electron?** U pozadinskom security utility-ju WPF smanjuje runtime footprint. UI se može zatvoriti; servis nastavlja rad.

## C1. Repository skeleton (izdvojeni moduli, bez prevelikog monolita)

```text
LocalFirewall/
  README.md
  LICENSE
  NOTICE
  TRADEMARKS.md
  SECURITY.md
  CONTRIBUTING.md
  FUNDING.yml                # ili .github/FUNDING.yml
  global.json
  Directory.Build.props
  Directory.Packages.props
  LocalFirewall.sln
  src/
    LocalFirewall.Contracts/
    LocalFirewall.Core/
    LocalFirewall.Infrastructure.Windows/
      IpHelper/
      Etw/
      WfpEvents/
      FirewallCom/
      ProcessIdentity/
      GeoIp/
    LocalFirewall.Persistence/
    LocalFirewall.Service/
    LocalFirewall.UI/
    LocalFirewall.Installer/            # kasnija faza
    LocalFirewall.FileReputation/       # kasnija faza
    LocalFirewall.ThreatIntelligence/   # kasnija faza
    LocalFirewall.BlackboxAdapter/      # kasnija faza
    LocalFirewall.DkgAdapter/           # kasnija faza
  integrations/
    agent-security-memory/             # zaseban, nezavisan licencni/build paket za grant
    wallet-browser-extension/          # istraživanje tek posle osnovnog proizvoda
  tests/
    LocalFirewall.Core.Tests/
    LocalFirewall.Persistence.Tests/
    LocalFirewall.IPC.SecurityTests/
    LocalFirewall.Windows.IntegrationTests/
    LocalFirewall.PerformanceTests/
    LocalFirewall.E2E.Tests/
  docs/
    ARCHITECTURE.md
    SECURITY_MODEL.md
    PRIVACY_MODEL.md
    API_CONTRACTS.md
    TRAFFIC_METRICS.md
    THREAT_INTELLIGENCE.md
    LICENSING.md
    DKG_INTEGRATION.md
    FIREWALL_RECOVERY.md
    PERFORMANCE_BUDGET.md
    TEST_MATRIX.md
    ADR/
  scripts/
    dev-install.ps1
    dev-uninstall.ps1
    verify-firewall.ps1
  .github/workflows/
    ci.yml
    security.yml
    release.yml
```

`UI` sme zavisiti samo od `Contracts` i UI-only komponenti. `Core` nema Windows API, network fetch, SQLite ni WPF. `Infrastructure.Windows` izoluje OS API-je. `Service` jedini ima privilegije za firewall izmene. Bez circular references. `DkgAdapter` i `BlackboxAdapter` mogu biti potpuno odsutni bez greške.

---

# D. ARHITEKTURA, GRANICE PROCESA I TOKOVI

```text
[Unprivileged per-user WPF UI]                 [Optional separate modules]
    charts / country flags / controls            Blackbox | DKG | wallet extension
             | local Named Pipe                    |  signed normalized events
             v                                     v
[Windows Service — minimal privileged boundary] -> [Threat feed cache / adapter boundary]
  command validation / identity / auth
  IP Helper + ETW normalizers
  bounded event queue -> aggregator -> SQLite
  rules coordinator -> Windows Firewall COM
  block evidence reader -> WFP net events / audit opt-in
             |
             v
      Windows network stack and firewall engine
```

**Ne pokušavati** postaviti Blackbox, DKG ili VirusTotal na put svake mrežne konekcije. Windows odmah primenjuje lokalna OS pravila; dodatni moduli naknadno obogaćuju informacije i osvežavaju lokalne, potpisane pakete.

## D1. Normalizovan Event Contract

Svi događaji imaju: `eventId`, `sequence`, `occurredAtUtc`, `observedAtUtc`, `type`, `appId?`, `processInstanceId?`, `flowId?`, `ip/port/protocol?`, `source`, `confidence`, `evidenceRefs[]`, `qualityFlags[]`, `severity`, `actionStatus`, `metadata` (redaktovano). Definisati stabilne enum vrednosti i `schemaVersion`.

Primer (konceptualan; bez tvrđenja da OS automatski isporučuje sva polja):

```json
{
  "schemaVersion": 1,
  "eventId": "9f96dd70-4a58-4a9a-bc95-582ed2517e96",
  "sequence": 10244,
  "occurredAtUtc": "2026-11-03T12:14:05Z",
  "type": "connection.blocked",
  "appId": "app:computed-local-id",
  "flowId": null,
  "remote": { "ip": "203.0.113.25", "port": 443, "protocol": "tcp" },
  "country": { "iso2": null, "quality": "unknown", "databaseDateUtc": null },
  "source": "wfp-event",
  "confidence": "medium",
  "qualityFlags": ["process-attribution-unverified"],
  "severity": "info",
  "actionStatus": "observed",
  "evidenceRefs": []
}
```

**Nikad ne poistovećivati** `observed blocked event`, `owned block rule installed`, `rule verified` i `full traffic actually blocked`. To su različiti statusi. Primena pravila traži OS read-back i test mrežnog ponašanja.

## D2. UI-Service IPC ugovor

Envelope ima `version`, `requestId`, `type`, `timestampUtc`, `payload`, `expectedRevision?`. Dozvoljene komande:
- read-only: `system.capabilities`, `service.health`, `snapshot.get`, `events.subscribe`, `history.query`, `apps.query`, `rules.query`, `config.get`, `diagnostics.export`
- privilegovane: `rule.upsert`, `rule.remove`, `rule.verify`, `config.update` uz eksplicitna ovlašćenja i audit.

**Bez** `runCommand`, `executeShell`, `loadPlugin`, `evalScript`, proizvoljnog putanja DLL-a ili “generic admin action” RPC-a. Maksimalna veličina poruke npr. 256 KiB, strogo tipizovana serijalizacija, timeout, cancellation, rate limiting, monotonični cursor za reconnect, validacija putanja, portova, CIDR-a, korisničkog SID-a i stanja servisa. Remote pipe klijenti odbijeni. Ispitati multi-user switching i impersonation.

---

# E. NETWORK ENGINE — TAČNOST PRE LEPIH BROJEVA

## E1. Process identity

`PID` nije stabilan identitet. Čuvati `(pid, processStartUtc, session/bootId)` za instancu; `(canonical exe path + verified signer + hash-if-available)` za identitet aplikacije. Hash asinkrono i uz limit IO; promena binary fajla je događaj. Ako OS ne da putanju ili servis koristi `svchost.exe`, status `unknown/shared host`, ne lažni servis. Store/UWP i system processes posebni edge cases.

## E2. Socket inventory + traffic

- `GetExtendedTcpTable` i `GetExtendedUdpTable`, obe IP porodice, two-call buffer, bezbedne dužine struktura, endianness, scope id.
- IPv4/IPv6, TCP/UDP/QUIC; UDP owner tables ne daju nužno udaljeni endpoint, `unknown` kada se ne može dokazati.
- Snapshot 1–2 s propušta kratke konekcije. ETW dopunjuje evente; ne tvrditi punu pokrivenost.
- ETW polja broja bajtova verificirati na testu. Upload/download je procena iz izvora koji se dokumentuje; može odstupati kod VPN, retransmisije, HTTP proxy, WSL, Hyper-V, loopback ili offload-a.
- Merenje saobraćaja ne sme da postane paketni sniffer po defaultu. Nikad ne skladištiti sadržaj paketa.

## E3. Dokazi o blokiranju

Preferirati WFP net-event subscription kada je podržano, uz precizna prava i provereno podešavanje; fallback Security Event 5157 ako je audit eksplicitno omogućen. Ne uključivati globalno bučno auditiranje bez saglasnosti. Ako dokaz nije dostupan, `Rule installed; enforcement not independently observed`, a ne `100% Blocked`.

## E4. DNS i GeoIP

- IP endpoint iz OS je primarni dokaz; `hostname` je opažen ili heuristički povezan podatak, uz confidence. DoH, TLS ECH, VPN, DNS cache i CDN mogu sakriti stvarnu destinaciju.
- GeoIP: lokalna, licencirana baza, osvežavanje opt-in/transparentno; prikazati datum baze i `country unknown` kada nema podataka.
- Zemlja servera nije dokaz lokacije firme/osobe. Country flag u tabeli i događaju je ilustrativna informacija, bez rangiranja prema nacionalnosti.
- Bez pasivnog pozivanja javnog GeoIP API-ja za svaku konekciju.

---

# F. FIREWALL RULE ENGINE — NAJVIŠI RIZIK

## F1. Pravila

Definiši čist interfejs `IFirewallPolicyAdapter` u Core; COM implementacija u Windows adapteru. Puna `RuleSpec` struktura: `managedRuleId`, `appPath`, `direction`, `action`, `profile`, `protocol`, `remoteAddress/CIDR`, `local/remotePort`, `enabled`, `schemaVersion`.

Vlastita Windows pravila imaju determinističko ime `LocalFirewall::{GUID}::{direction}`. **Nikad ne brisati Windows pravila drugih proizvoda.**

Transakcija:
```text
validate user+scope
 -> save desired=pending + audit
 -> OS COM apply
 -> read-back fields and policy eligibility
 -> verify test network behavior (integration test)
 -> desired/actual reconciliation
 -> publish result
```

Ako OS apply uspe, ali read-back ne uspe: prikazati `UNVERIFIED`, pokušati bezbedan rollback samo sopstvenog rule-a. Pri `unblock`, ukloniti sopstveni block; ako postoji drugi `block`/GPO, UI prikazuje `Blocked by other policy`. Ne može se garantovati da pojedinačno `allow` pravilo nadjačava spoljašnji `block`.

## F2. Pravila ponašanja

- Prvi javni režim `Observe` (bez promene pravila).
- Sledeći `Click-to-block` (opciono i eksplicitno aktiviran).
- `New app alert` upozorava nakon opažene aktivnosti, ne zaustavlja obavezno prvi paket.
- `Ask before connection` i outbound default deny samo kasniji R&D uz VM i offline rollback; posebno upozorenje i ručno odobrenje.
- Uvek sačuvati prethodno stanje za pravila koja **naša** aplikacija menja. Uninstall uklanja samo vlastita.
- Ne dirati globalna default inbound/outbound podešavanja, DNS, Windows Update, time sync ili local LLM loopback automatski.

---

# G. UX: ORIGINALAN, JEDNOSTAVAN, GRAFIKONI I ZASTAVE

## G1. Navigacija

`Overview | Connections | Applications | Events | Firewall | Files | Security | Settings`

U FND-001 kartice `Files` i `Security` mogu biti feature-gated/disabled s jasnim `Coming later`, ne lažni prikaz skeniranja. Napredni korisnik dobija expandable `Technical details`; početnik ne mora učiti WFP/DKG.

## G2. Overview

- Dve linije na glavnom grafikonu: download/upload; 5m / 1h / 24h / 7d / custom.
- Zum, pan, crosshair, tooltip; agregacija 1s/1m/1h u zavisnosti od zoom-a.
- Vertikalne oznake događaja na pravom vremenu: first seen app, first destination, blocked, suspicious, file, rule changed, agent alert.
- Filter legendom na tip događaja i aplikaciju; klik na marker otvara kontekst: proces + IP + flag + izvor + vreme + kvalitet informacije + radnje.
- Top apps i recent events bez previše kartica; suptilne boje, lako čitljiv dizajn.
- `Service: running/offline`, `Monitoring: active/partial`, `Firewall control: unavailable/ready`, `Feed: cached/offline`, odvojeno. Ne jedna nepouzdana zelena oznaka `Protected`.

## G3. Connections / Applications

Virtualizovane tabele sa kolonama `App`, `PID`, `Protocol`, `Remote IP`, `Port`, `Observed domain?`, `Country flag`, `Upload`, `Download`, `First/last seen`, `Status`. Sort, filter, search, row expand; 500 procesa/10k+ redova ne sme blokirati UI.

Context actions: `View details`, `Copy IP`, `Open file location`, `Block app`, `Unblock own rule`, `View history`, `Check reputation` ako lokalno dostupno. Pri blokiranju prikazati confirmation, scope i OS rezultat.

## G4. Events/History

Jedinstveni timeline sa opcijama `All`, `Network`, `Blocked`, `Files`, `Agents`, `System`. Event severity nije isto što i confidence. Opozvani ili zastareli threat nalaz mora imati promenu statusa. Incident grupisanje/dedupe; maksimum popup frekvencija i silent mode. CSV/JSON export opt-in.

## G5. Files/Security

`Files`: samo praćeni fajlovi, putanja (lokalno), hash, signer, prvi/poslednji pregled, izvor rezultata i status. `Security`: kontrolisana lista lokalnih/remote threat sources; dobro objašnjenje zašto je nešto označeno, tip nalaza i njegov rok važenja; opcioni Blackbox/DKG status. Nikad “safe” kao apsolutna tvrdnja.

**Accessibility:** kontrast, keyboard navigation, screen-reader label, ikonica + tekst umesto samo boje/zastave, skaliranje 100–200%, responsive resizable WPF.

---

# H. PERFORMANSE: IZMERITI, NE IZMIŠLJATI

**Budžeti su ciljevi, ne garantovana potrošnja:**

| Metrika | Cilj |
|---|---|
| Servis u mirovanju (Standard, običan host) | prosečan total CPU oko <1%; merenje 10 min |
| Servis RAM (typical), preporučena inicijalna granica | <150–200 MB PSS/working set; precizirati metodologiju |
| UI RAM dok je otvoren | cilj ispod 200 MB dodatno, bez ugrađenog browser runtime-a |
| UI | oko 30+ fps pri normalnom pomeranju; može manje na starom GPU/CPU |
| Grafikon | render najviše 1–4 Hz, a ne po ETW događaju |
| SQLite | batch writes svakih 1–5s ili kad buffer dostigne prag |
| Event queue | bounded; metrika drop/loss; degradacija vidljiva u UI |
| No-UI Standard mode | nema WPF/GPU procesa; servis nastavlja monitoring |
| DKG/Blackbox off | nema njihovih procesa, mrežnih upita, RAM/cpu potrošnje |
| 24h soak | bez rastućih leak-ova i bez gubitka prethodno primenjenih pravila |

Mehanizmi: bounded `Channel<T>`; lightweight normalized struct; event aggregation; throttled charts; UI virtualization; background IO; SQLite WAL; lazy signer/hash; local GeoIP cache; disk quota/retention; cancel/backoff sa jitter-om; lazy plugin startup. Kada queue overflow, umesto tihog gubitka prikazati `Partial data (lost events=N)`.

**Perf scenariji:** idle 10min, stream download/upload, 1000 kratkih TCP konekcija, UDP/QUIC, reboot, sleep/resume, VPN/WSL, servis bez UI-ja, otvoren GUI 8h, 24h soak, starija dual-Xeon/4-GPU stanica dok lokalni LLM radi. Nijedna procena bez logova merenja.

---

# I. LOKALNA BAZA I RETENCIJA

SQLite tabele (minimum):
- `apps`, `process_instances`, `flows`
- `network_events` (normalizovani metadata događaji)
- `traffic_buckets` (1s/1m/1h/1d)
- `dns_observations` (opciono + confidence)
- `firewall_rules` (owned + external read-only reference)
- `rule_audit`
- `alerts`
- `file_observations` (FND-015)
- `threat_indicators`, `threat_sources`, `threat_evidence`, `feed_versions`, `revocations` (kasnije)
- `agent_events` (kasnije; samo redaktovani metadata)
- `settings`, `schema_migrations`, `diagnostics`.

Svi timestamp-i UTC u storage-u. 64-bit brojači. Parametrizovani SQL. Indexi po `occurredAt`, `appId`, `flowId`, `remoteIp`, `sha256`, `severity`. WAL, integrity check, migration rollback strategy, backup/repair.

**Predlozi default retenicije:** događaji i individual flows do 30 dana, 1s buckets do 24h, 1m 30 dana, 1h 12 meseci, 1d po korisničkom izboru. Soft disk cap 1–2 GB i jasno obaveštenje; bez beskonačnih logova; mogućnost `Delete all local history`. Ispraviti kapacitete testovima (zavise od prometa).

Nema skladištenja punih fajlova, TLS payloada, seed fraza, wallet adresa korisnika, tokena, pasvorda ili agent promptova.

---

# J. FILE TRACKER + REPUTACIJA (OPCIONI MODUL, POSLE MVP-a)

## J1. Slučajevi i ograničenja

V1 File Tracker prati **samo odabrane direktorijume**, npr. Downloads i opcioni Desktop, a ne svaki fajl na celom disku. `FileSystemWatcher` je event hint, ne potpuna garancija; overflow se beleži, radi se ograničen reconciliation. Korisnik određuje scope, pa može isključiti module.

Tok:
```text
new/changed file event -> settle/debounce 2–5s -> local metadata
 -> size/type limits -> background SHA-256 stream with cancellation
 -> Authenticode signer verify (if PE)
 -> local cache/verified threat bundle
 -> optional existing Microsoft Defender scan via documented API/tool
 -> result provenance + uncertainty + alert
```

Nijedan hash ne sme da se računa za ogromne fajlove pod visokim opterećenjem bez budžeta: max parallel 1/2, backoff, I/O budget; preskočiti system/temp/locked files i jasno objasniti `skipped`.

**Nema automatskog “malware” na osnovu nepoznatog hash-a ili jednog AV flag-a.** Ne brisati, ne karantinisati, ne ubijati proces po heuristici; korisnik i postojeći OS antivirus odlučuju. Rezultat `unknown`, `not found`, `warning`, `confirmed by source`, `scan unavailable`; izvor + vreme obavezni.

## J2. VirusTotal — STROGO

Zvanični VT Public API: **4 zahteva/min**, **500 zahteva/dan**, zabranjena komercijalna upotreba i zabranjeno korišćenje kao zamena za antivirusni proizvod. Pre distribucije integracije zatražiti potvrdu da je **konkretna upotreba** dozvoljena. Sama open-source licenca, privatni korisnički ključ i odsustvo naplate nisu automatski izuzeće.

**Zato u javnom default buildu: nema automatskog slanja fajlova, URL-ova, hash-eva ili IP-ova VirusTotal-u.** Kao bezbedan fallback ponuditi korisnički poziv `Open VirusTotal website` ili kopiranje SHA-256. Ako dobijemo dozvolu/licencu, odvojen provider adapter može da radi isključivo uz opt-in, korisnički key iz Windows DPAPI/Credential Manager, manual hash-only lookup, queue limiter, 429 backoff, cache i bez auto-upload-a. Key nikad u repo/logovima ili zajedničkom serveru. Treba prikazati vreme i broj/vrstu detekcija uz upozorenje za false positives. VirusTotal nije presuda.

Za manual upload fajla potrebna je posebna, eksplicitna saglasnost i prikaz rizika otkrivanja sadržaja, ali ova funkcija nije deo primarnog planiranog izdanja.

---

# K. THREAT INTELLIGENCE I POVERENJE

`Indicator` tipovi: `domain`, `IP/CIDR`, `file SHA-256`, `package+version`, `agent skill/MCP tool ID`, `wallet drainer indicator`, `command pattern` (safe/normalized). Nije dozvoljeno da se iz mrežnog IP-ja izvodi “domain reputation” kao sigurna činjenica.

Svaki nalaz sadrži: `indicatorType`, `normalizedValue`, `publisherId`, `sourceUri`, `sourceVersion`, `observedAt`, `expiresAt`, `evidenceDigest`, `verificationMethod`, `signatureState`, `confidence`, `status`, `revokedAt?`, `policyAction`, `lastReviewedAt`.

Tri nivoa:
- `COMMUNITY`: prijavljeno, **nikada automatski block**.
- `REVIEWED`: dodatni dokazi, bez obaveznog automatskog block-a.
- `VERIFIED`: potpisano od prihvaćenog izdavača, sa odgovarajućim politikama, opozivima i rokom važenja; nikad ne tumačiti “potpisano” kao apsolutno istinito.

Automatska OS blokiranja na osnovu feedova su **isključena podrazumevano** čak i za VERIFIED, dok ne postoje anti-false-positive, rollback, safety allowlists i testovi. Signed feed: canonical serializer, pinned publisher keys, monotonic `version`, replay protection, expiry, tamper detection, revocation, update fallback. Ne izvršavati kod iz feedova. Ne slepo spajati oprečne nalaze; provenance uvek korisniku dostupan.

---

# L. UMANITEK BLACKBOX — KOMPATIBILNOST, NE REIMPLEMENTACIJA

Blackbox je prvenstveno **zaštita AI agenata pre izvršenja akcija**. Nije OS-level Windows firewall. Podržane hostove i Community Graph status proveriti na **tačno pinovanom commit-u/release-u**; javne README varijante mogu opisivati različito stanje. Ne tvrdimo da imamo njegov blocking dok funkcionalni E2E test ne prođe.

Naša integracija:
1. `IBlackboxAdapter`: `GetCapabilities`, `GetHealth`, `ImportApprovedIndicators`, `ReadRedactedFindings`, `SubscribeEvents` (samo ako javni interfejs to podržava).
2. Nikad ne čitati internu SQLite/DKG bazu ili Python privatne module bez ugovora o kompatibilnosti.
3. Ako je Blackbox već instaliran, **detektovati** podržano izdanje i tražiti pristanak da prikažemo njegove nalaze; ne preuzimati kontrolu nad njegovim podešavanjima.
4. U Standard režimu ne pokretati Hermes, OpenClaw, Python, Node, Docker ili DKG.
5. Kada ga nema: `Blackbox not installed`, bez greške i bez lažnih zaštita.
6. Za akcije agenata koje ne pokriva vendor i koje bi agent mogao da presretne, praviti naš **dokumentovan host adapter** samo posle sigurnosne provere, ne univerzalnu pretpostavku da su svi AI agenti zaštićeni.
7. **Blackbox fail-open** ne sme biti prikazan kao savršena garancija zabrane. Naš UI jasno navodi razliku `audit` vs `block` i preostali rizik.

**Važno:** Blackbox je pod MIT licencom, ali to ne daje automatski pravo da objavljujemo/redistribuiramo tuđe threat feedove bez provere njihovih uslova. Nema lažnog službenog partnerstva.

---

# M. ORIGINTRAIL DKG V10 — OPCIONO I ODVOJENO

**Standard** koristi potpisane, male offline threat bundles (potpisani release manifest + podaci) koje održava projekat. Nije potreban lokalni DKG node. Ako infrastruktura za generisanje bundle-a ne postoji, koristi se prazan ili poslednji verifikovani paket; **nikada nepouzdan javni JSON kao automatska block lista**.

**Advanced** opcionalno koristi postojeći ili posebno instalirani lokalni Edge Node, preko javnog DKG API-ja/CLI/MCP (dokumentacija verzije se proverava pre implementacije).

Tok:
```text
Verified DKG knowledge + accepted signed publishers
        -> audited export/normalization -> signed bundle
        -> download (opt-in/update) -> signature/expiry/revocation check
        -> local immutable snapshot -> firewall threat engine
```

**Do not make `connect()` network request in per-flow firewall check.** DKG je van hot path-a. Ako DKG ne radi, firewall i dalje radi.

Privatna konekciona istorija ostaje lokalna. Sharing je **isključen podrazumevano**; tek po pristanku konkretna anonimna/pravilno redaktovana prijava može da pređe u Shared Memory. Privatni ključevi, seed fraze, file content, lične putanje, agent promptovi, skriveni tokeni i sirovi logovi nikad ne ulaze u DKG. Ne tvrditi “anonimno” bez formalne analize identifikatora/reporting walleta. Objavljivanje u Verifiable Memory je selektivno i troši sredstva; bez objave automatski, bez korisničkog wallet zahteva za Standard.

Terminologija za grant: `Project`, `Working Memory`, `Shared Memory`, `Context Graph`, `Integration`, `Curator`, `Entity`, `Knowledge Asset`, `SHARE`, `PUBLISH`, `UAL`. Ne uvoditi zamenske nazive.

---

# N. AGENT SECURITY RESEARCH MEMORY — POSEBAN GRANT KANDIDAT

Istraživački paket koji radi **samostalno**, čak i ako LocalFirewall desktop još ne postoji. Podrazumevano read-only; omogućava 2+ AI agenata da sarađuju na proveri sumnjivih paketa/domena:
1. Agent A primi dozvoljeno, neosetljivo javno pitanje (“da li je npm paket X@ver sumnjiv?”) i napravi radni zapis u **Working Memory**.
2. Agent B čita, iznosi nezavisan dokaz/kontradokaz, deli rezultat kroz **Shared Memory** samo po odgovarajućem projektu i ovlašćenjima.
3. Oba zapisa referenciraju izvor/evidence, datum, indikator, kvalitet; zajednički status je `unverified/reviewed` dok curator/izdavač to ne potvrdi.
4. Agent pruža čitljiv izveštaj sa proverljivim DKG referencama (UAL gde primenjivo) i objašnjenjem pogrešnih pozitivnih nalaza.
5. Pripremi šemu za buduće promovisanjem u **Verifiable Memory** ali NE tvrditi da je objavljeno na chain-u kada nije.

**Grant zahtevi:** zvanični DKG V10 prvi krug cilja Working/Shared Memory × LLM-Wiki/Autoresearch, ne samo Windows firewall. Paket u posebnom repozitorijumu/nezavisnom delu sa jasnom OSI licencom pogodnom za integracioni registry (razmotriti MIT/Apache-2.0), pinovanim tag/commit, bez postinstall skripti bez odobrenja, deklarisanim egress/permissions, E2E testom protiv pravog lokalnog DKG V10 čvora, reproduktivnim demo-om i održavanjem. Ne podnositi konkurs dok uslovi nisu ponovo provereni. Nagrade do 10k TRAC nisu zagarantovane.

**Razlika prema Blackbox-u:** ovaj paket je agent-native *collaborative research memory*, a ne samo dupliranje postojećeg action guard-a. Ne predstavljati podudarnost kao inovaciju bez dokazivog workflow-a.

---

# O. CRYPTO / WALLET PROTECTION — KASNIJI MODUL

Blackbox Trader Shield već obrađuje određene **agentske** pretnje vezane za novčanike. Naš firewall može pratiti mrežne konekcije procesa, ali **ne može iz enkriptovanog TCP toka automatski saznati da je korisnik potpisao rizičnu transakciju**.

Ako se kasnije razvije browser dodatak, on eksplicitno i minimalno traži dozvole za odabrane sajtove/wallet API događaje, bez pristupa seed frazama, privatnim ključevima ili potpunom browsing history-u. Lokalni engine može dobiti samo već redaktovane indikatore. Nikakvo automatsko potpisivanje, odobravanje ili blokiranje transakcija bez odobrenog UX/threat modela. Ovo je odvojena faza i ne sme da uveća Standard footprint.

---

# P. SECURITY, PRIVACY I SOFTWARE SUPPLY CHAIN

1. Service može početi s administrativnim privilegijama u VM, ali cilj je minimalni required privilege; servisni binarni fajlovi u `%ProgramFiles%`, podaci u `%ProgramData%` sa ACL.
2. UI bez admin privilegija; stroga provera pipe klijenta, korisnika, zahteva i dužine poruke; never trust data from UI/network feeds.
3. Threat model: neprivilegovani lokalni maliciozni program, kompromitovan dependency, feed poisoning, tampering, DLL search order, updater hijack, IPC abuse, ETW resource DoS, PID reuse, path spoofing, fake signed feed, ransomware-changing executable. Lokalni administrator van realne granice odbrane.
4. Update/release: reproducible build kad izvodljivo; SBOM, checksums, code signing, pinned dependencies, dependency scanning, verified release origin, release rollback. Nikada ne download-and-execute skripte ili binarne pakete bez verifikacije.
5. Baza i logovi: redaction; dijagnostički export uz pregled; nema automatske telemetrije i analytics servera. Sačuvaj tajne u Windows Credential Manager/DPAPI, nikad config JSON plaintext.
6. Auto-start, updater, firewall write i cloud adapter kao zasebno dopuštene sposobnosti; default minimum.
7. Bilo koji UI bag ne sme oboriti Windows firewall; servis bug ne sme menjati postojeća ne-naša pravila.
8. Ne instalirati code-hook ili browser ekstenziju automatski; eksplicitno informisan izbor korisnika.

---

# Q. OPEN SOURCE, AUTORSTVO, LICENCE, DONACIJE

**Odluka:** projekat ostaje pravi open source i potpuno besplatan. Nema klauzula koje zabranjuju komercijalno korišćenje; takva zabrana bi bila nespojiva sa OSI otvorenim kodom. Nije moguće GPL licencom sprečiti legalnu naplatu instalacije/održavanja od strane trećih lica.

**Predlog za nezavisno pravno/licencno proveravanje pre release-a:**
- Desktop + servis: GPL-3.0-or-later (ili druga kompatibilna copyleft licenca).
- Eventualni hostovani/community servis: AGPL-3.0-or-later samo ako stvarno postoji; ne uvoditi ga bez potrebe.
- `integrations/agent-security-memory`: nezavisan MIT/Apache-2.0 paket za DKG registry kada ne sadrži kopirani GPL-only kod; licence submodula držati jasno izdvojeno.
- `NOTICE`, `THIRD_PARTY_NOTICES`, SPDX licence, evidencija doprinosa; copyright autora ne uklanjati.
- `TRADEMARKS.md` zaštita naziva i logotipa; potpisani official builds, pravila za neovlašćeno predstavljanje.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, DCO ili jasne pravila za doprinose.
- `FUNDING.yml`, GitHub Sponsors/donacije opcioni prikaz, javne adrese tek kada autor obezbedi svoje; ne hardkodirati izmišljene wallet adrese. Nema plaćene zaštite ili donacije u zamenu za “safe” verdict.

Licencne implikacije kombinovanja GPL i permissive modula treba proveriti **pre** uvoza koda. Izbor licence nije zamena za pravni savet.

---

# R. IZVOĐENJE — STROGI TICKETS I ZAVISNOSTI

Za implementaciju koristi zaseban dokument `LocalFirewall_FND_TASKS_V2_SR.md` kao operativni vodič. **Početak isključivo FND-001.**

**Core putanja (obavezna):**
`FND-001` repo/UI skeleton -> `002` read-only process/socket inventory -> `003` service/IPC -> `004` ETW metrics -> `005` SQLite -> `006` real OS block -> `007` alerts/block evidence -> `008` rules/profiles -> `009` installer/hardening -> `010` GeoIP/DNS/timeline/perf polish.

**Opcioni moduli posle dokazano stabilnog Core-a:**
- `FND-015` file tracker + lokalna reputacija (+ testovi)
- `FND-016` provider-neutral VT/manual hash lookup gate
- `FND-011` Blackbox compatibility
- `FND-012` OriginTrail DKG/verified bundles
- `FND-013` separate Agent Security Research Memory
- `FND-014` optional TRAC/Verifiable Memory budget/publishing
- `FND-017` wallet browser integration R&D
- `FND-018` community reports/privacy/anti-abuse

**Napomena:** brojevi FND-011–014 zadržavaju prethodno dogovoreno značenje, a FND-015+ su dodatne faze; redosled kodiranja ne mora biti numerički ako zadovoljava zavisnosti i korisnik odobri ticket.

---

# S. DEFINICIJA USPEHA + QA MATRIX

**MVP ne prolazi dok:**
- stvaran Windows proces i endpoint nisu prikazani u kontrolisanom TCP/UDP testu;
- pravilo kreirano kroz UI nije realno, izolovano i povratno verifikovano u Windows Firewall-u (FND-006);
- UI pri padu servisa ne pokaže stanje `Service offline`;
- IPC nije ograničen SID/ACL i ne može se trivijalno zloupotrebiti;
- grafikon nije zasnovan na stvarnim ili jasno označenim demo podacima, sa tačnom definicijom vrednosti;
- uninstall ne uklanja isključivo vlastita pravila;
- postoji makar osnovna izolovana E2E test matrica i izmerena resource potrošnja.

QA scenariji (u Windows VM osim posebno navedenog):
1. IPv4 TCP outbound i inbound; IPv6 TCP; UDP datagram + QUIC; loopback.
2. 1.000 kratkih konekcija, PID reuse, unknown executable, protected process, `svchost.exe`.
3. HTTP lokalni LLM server, VPN/tunel, WSL/Hyper-V, sleep/resume, promena mrežnog adaptera.
4. Click block test.exe; drugi program nije pogođen; unblock samo own rule; external GPO conflict.
5. Rušenje UI-ja, rušenje/restart servisa, reboot, corruption SQLite/WAL, disk full, log quota.
6. Unauthorized named-pipe client; malformed messages, spoofed path, CIDR IPv6 parser, fuzz, request flood.
7. WFP net event missing / Windows audit disabled; neizmišljena `unknown` evidencija.
8. GeoIP DB stale/missing; bez externih IP lookups; zastave nisu pogrešna geolokacija.
9. FileSystemWatcher overflow, giant file, locked file, false positive, Defender disabled.
10. Threat bundle tampered/expired/revoked; stale source; malicious community report ne pokreće auto-block.
11. DKG offline, Blackbox not installed, malformed feed, wrong signing key: Standard i dalje radi.
12. UI virtualizacija 10k+ redova, 24h soak, resource test sa aktivnim lokalnim AI workload-om.

**Acceptance report po fazi:**
```text
PHASE: FND-###
SCOPE DONE:
FILES CHANGED:
CONFIG/DEPENDENCIES:
SECURITY IMPACT:
TEST COMMANDS + REAL OUTPUT:
NOT RUN + REASON:
RESOURCE MEASUREMENTS (if applicable):
KNOWN LIMITATIONS:
MANUAL CHECK:
ROLLBACK:
READY FOR NEXT PHASE? YES/NO
```

---

# T. IZVORI KOJE AGENT MORA DA PROVERI PRE ODGOVARAJUĆE FAZE

*Microsoft / Windows*
- https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2
- https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
- https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview
- https://learn.microsoft.com/en-us/windows/win32/fwp/using-windows-filtering-platform
- https://learn.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-getextendedtcptable
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/dotnet/core/install/windows
- https://learn.microsoft.com/en-us/dotnet/core/releases-and-support

*OriginTrail/Blackbox*
- https://github.com/OriginTrail/dkg
- https://github.com/OriginTrail/dkg/blob/main/docs/active-now/dkg-v10-bounty.md
- https://github.com/umanitek/agent-blackbox
- https://github.com/umanitek/agent-blackbox/blob/main/plugins/blackbox/README.md

*VirusTotal*
- https://docs.virustotal.com/reference/public-vs-premium-api
- https://docs.virustotal.com/reference/getting-started
- https://docs.virustotal.com/reference/file-info

*Referentni proizvodi, NE automatski kod za import*
- https://github.com/henrypp/simplewall
- https://github.com/tnodir/fort
- https://github.com/safing/portmaster
- https://github.com/Webtonix/netsentinel
- https://github.com/ScottPlot/ScottPlot
- https://opensource.org/osd

**Dokumentacija i uslovi eksternih projekata mogu se promeniti.** Beležiti datum provere i commit/release koji je agent koristio. Ne tvrditi da je nešto potvrđeno ako su korišćeni samo primeri ili lokalni mockovi.

---

# U. KONAČNA NAREDBA ZA PRVI KORAK

**Implementiraj samo `FND-001`.** Proveri repo pre pisanja; napravi buildable `LocalFirewall.sln`, Core/Contracts/Windows adapter skeleton, WPF shell i realno funkcionalnu navigaciju, originalan prikaz sa dva demo grafikona i virtualizovanom tabelom uz stalan vidljiv `DEMO DATA` status, minimalne unit testove i CI. Nema admin prava, Windows Service instalacije, firewall COM write poziva, eksternih upita, DKG/Blackbox/VT modula niti kernel drivera u ovoj fazi. Ne prelazi u `FND-002` bez nove eksplicitne naredbe.
