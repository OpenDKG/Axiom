# LOCALFIREWALL — TEHNIČKI HANDOFF V1.0

**Datum:** 1. novembar 2026.  
**Tip:** Lokalna Windows desktop aplikacija + Windows Service  
**Jezik dokumentacije:** srpski; nazivi API-ja, identifikatori i kod na engleskom  
**Status:** projektna specifikacija za implementaciju; NIJE potvrda da je program već napravljen  
**Prioritet:** pouzdano blokiranje, tačno označena telemetrija, bezbednost OS-a, jednostavno održavanje  
**Radno ime:** LocalFirewall (promenljivo)

---

## 0. EXECUTIVE DECISION — PROČITATI PRVO

Napraviti **Windows lokalni per-application firewall i network monitor** sa funkcionalnošću sličnom GlassWire-u, ali sa sopstvenim kodom, neutralnim vizuelnim identitetom, bez kopiranja njegovog interfejsa ili brenda.

**Izabrana strategija:**

1. Za v1 blokiranje koristiti **Windows Firewall with Advanced Security** (Windows Defender Firewall) preko dokumentovanog COM API-ja `INetFwPolicy2` + `INetFwRule`; opciono kroz odvojeni adapter `NetSecurity` PowerShell za dijagnostički prototip, ne shell komande iz UI-ja.
2. Za praćenje živih TCP/UDP konekcija i vlasničkih PID-ova koristiti IP Helper (`GetExtendedTcpTable`, `GetExtendedUdpTable`) i **ETW** za događaje i približnu potrošnju bajtova po procesu. Sam snapshot konekcija NIJE dovoljan za istoriju ni za precizno merenje bajtova.
3. Za blokirane konekcije prvo pokušati **WFP net-event subscription** i/ili kontrolisano WFP Security auditing (naročito 5157), uz testiranje dostupnosti, troška i privilegija. Ne omogućavati globalno bučno auditing ponašanje bez korisničkog pristanka.
4. Razdvojiti neprivilegovani UI od privilegovanog Windows Service-a. Komunikacija preko *lokalnih* Named Pipes uz eksplicitnu ACL i proveru identiteta/ovlašćenja.
5. Za istoriju koristiti SQLite i agregaciju događaja; nikada ne čuvati sav promet kao pakete po defaultu.
6. **Ne pisati kernel-mode callout driver za v1.** Microsoft preporučuje user-mode management kada ugrađena WFP filtracija rešava zahtev.
7. „Ask to Connect“ bez kernela ima posebno ograničenje: lako je prikazati obaveštenje *nakon* viđenog pokušaja, ali nije garantovano zaustavljanje prve konekcije do korisničkog odgovora. Za strogi režim koristiti unapred blokiranu aplikaciju / default deny i čekanje na ponovno povezivanje, ili posebno projektovati napredni WFP enforcement.
8. Ne menjati globalnu Windows Firewall politiku u v1 i ne isključivati Microsoft Defender Firewall.

**Ciljna platforma:** Windows 11 x64 za podržano produkciono okruženje; testirati Windows 10 x64 kao best-effort. Na konkretnoj radnoj stanici Windows 10 Pro 21H2 nema podržane bezbednosne ispravke od 13. juna 2023. Microsoft trenutno navodi .NET 10 podršku za Windows 10 LTSC/Enterprise, NE za obični Windows 10 Pro 21H2. Dakle, binarno pokretanje u tom okruženju nije isto što i Microsoft-ova formalna podrška. Planirati nadogradnju OS-a ili poseban ograničen kompatibilni build sa jasno navedenim rizikom.

**Osnovni princip:** *System firewall is the enforcement authority; this app is policy manager + observer*. Prikaz „BLOCKED“ moguć je tek nakon uspešnog upisa i verifikacije pravila. Ako agent nije siguran šta OS primenjuje, UI mora pokazati „UNKNOWN/DEGRADED“, ne „PROTECTED“.

---

## 1. CILJ, OPSEG I NE-CILJEVI

### 1.1 Korisnički ciljevi

- Jednim pogledom videti koje aplikacije trenutno komuniciraju sa internetom.
- Videti outbound/inbound konekcije, protokol, lokalni/udaljeni IP i port, PID, proces/putanju, mrežni adapter i vreme.
- Videti *procenu* brzine i potrošnje po procesu, po mogućnosti po udaljenom IP-u; izdvojiti upload i download.
- Klikom blokirati ili odblokirati aplikaciju, selektivno inbound/outbound, opciono IP/port/mrežni profil.
- Dobiti obaveštenje kada potpuno nova aplikacija započne mrežnu aktivnost ili se aplikacija promeni.
- Pretraživati lokalnu istoriju i izvoziti CSV/JSON.
- Kreirati profile pravila Home / Public / Work / Gaming i ručno ih aktivirati; automatski aktivirati tek nakon dokazanog stabilnog ponašanja.
- Sačuvati privatnost: bez naloga, cloud baze, prodaje podataka i nepotrebnih upita ka spoljnim servisima.

### 1.2 Van opsega v1

- Antivirus, EDR, detekcija malvera sa garantovanim ishodom.
- TLS dekripcija, MITM, pregled HTTPS sadržaja, root certifikati.
- Prava domen-based enforcement pravila za DoH/QUIC bez posebnog DNS/proxy sloja.
- Kontrola ostalih uređaja u LAN-u; meri se samo host na kojem je instalirano.
- Stroga „allow before the first outgoing packet“ interakcija bez zasebno dokazanog enforcement rešenja.
- Automatizovano menjanje globalne Windows sigurnosne politike.
- Garantovano apsolutno precizno per-app brojanje svih bajtova preko svih VPN/tunel/virtualizovanih adaptera.

### 1.3 Nefunkcionalni ciljevi (budžeti koje treba izmeriti)

- UI tečan sa >500 procesa i >10.000 istorijskih redova kroz virtualizaciju.
- Idle servis okvirno <1% ukupnog CPU-a; cilj memorija servisa <150–200 MB pri uobičajenom saobraćaju. To su projektni ciljevi, NE izmerene vrednosti.
- UI ažuriranje agregata na približno 1 sekundu; servis ne sme raditi upis u bazu za svaki paket/događaj.
- Stabilan test najmanje 24 h običnog rada i stres test sa velikim brojem kratkotrajnih konekcija.
- Servis mora preživeti zatvaranje UI-ja i oporaviti se nakon restartovanja.
- Uninstall mora ukloniti SAMO sopstvena firewall pravila; bez `netsh advfirewall reset`.

---

## 2. REFERENTNE IMPLEMENTACIJE I LICENCE

**GlassWire** — funkcionalna referenca, ne preuzimati brending/dizajn/kod. Njegov vodič potvrđuje upravljanje ugrađenim Windows Firewall-om, grafikone, istoriju, bidirectional blocking, profile, alert-e i Ask to Connect. [Official user guide](https://www.glasswire.com/userguide/).

**simplewall (GPL-3.0)** — referenca za samostalnu WFP policy konfiguraciju i logovanje. Ima posebni WFP sloj i NE predstavlja Windows Firewall COM UI. Ispitati kao arhitekturni uzor, NE kopirati GPL kod u projekat zatvorenog izvora bez poštovanja licence. [Repo](https://github.com/henrypp/simplewall).

**Portmaster (GPL-3.0)** — referenca za per-app network privacy pravila, DNS politike i UX. [Repo](https://github.com/safing/portmaster).

**ScottPlot (MIT)** — kandidat za WPF grafikone, [Repo](https://github.com/ScottPlot/ScottPlot). **Microsoft Diagnostics TraceEvent / PerfView** — referenca za ETW obradu i Kernel TraceEventParser, [izvorni parser](https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs).

Pre instalacije svakog NuGet paketa pinovati verziju i proveriti LICENSE, transitive zavisnosti, sigurnosne savete i kompatibilnost. Ne pretpostavljati da je ceo projekat permissive samo zato što je jedan paket MIT.

---

## 3. PREPORUČENI STACK

| Sloj | Izbor | Razlog |
|---|---|---|
| UI | C# + WPF, .NET 10 (Windows target) | zrela Windows integracija, MVVM, lakši rad za lokalne coding modele |
| Windows Service | C# .NET 10 Worker + `Microsoft.Extensions.Hosting.WindowsServices` | upravljanje životnim ciklusom i servisni rad |
| MVVM | CommunityToolkit.Mvvm (licencu proveriti/pinovati) | mali broj zavisnosti |
| Monitor TCP/UDP | P/Invoke IP Helper API | PID-ovi i aktuelni soketi, IPv4 i IPv6 |
| Network events/counters | Microsoft.Diagnostics.Tracing.TraceEvent + ETW kernel networking | send/receive/connect/close telemetrija, uz merenje gubitaka |
| Policy enforcement | COM `INetFwPolicy2` / `INetFwRule` | pravi Windows firewall, bez drajvera |
| WFP evidence | `FwpmNetEventSubscribe*` / opcioni Security Event 5157 | blokirane konekcije; feature detection |
| Storage | SQLite, `Microsoft.Data.Sqlite` | offline, lokalno, indeksiranje i SQL agregacije |
| Grafikoni | ScottPlot WPF | performantno iscrtavanje istorije, MIT |
| IPC | Named Pipes, binarni/JSON typed message protocol | bez HTTP porta, uz jaku ACL |
| Installer | WiX Toolset MSI (licencu proveriti) | instalacija servisa, repair, rollback |
| Testovi | xUnit / NUnit + integration tests u Windows VM | stabilnost i reproduktivnost |

**Ne preporučujem Electron** za prvu verziju: nepotreban Chromium runtime i veći napadni/potrošni otisak za lokalni native security utility. Rust + Tauri je alternativni put, ali C# smanjuje integracioni rizik i otežavanje agentima, naročito za Windows COM/ETW.

---

## 4. PRECIZNA ARHITEKTURA

```text
┌───────────────────────────────────────────────┐
│ LocalFirewall.UI  (per-user, non-admin)       │
│ WPF, MVVM, charts, tray, notifications         │
└───────────────────┬───────────────────────────┘
                    │ named pipe (local only, ACL)
┌───────────────────▼───────────────────────────┐
│ LocalFirewall.Service  (Windows Service)     │
│  CommandValidator | PolicyCoordinator       │
│  ConnectionTracker | TrafficAggregator      │
│  EtwCollector | ProcessIdentityResolver     │
│  FirewallAdapter | AlertEngine              │
│  LocalStore | Diagnostics | ProfileManager   │
└───────┬───────────┬───────────┬───────────────┘
        │           │           │
   IP Helper/ETW  COM/WFP      SQLite
        │           │           │
      Windows OS network and filtering stack
```

**Obavezna pravila zavisnosti:**

- `UI` zavisi samo od `Contracts`, nikada od `Win32Interop`, `Service` ili SQLite fajla direktno.
- `Core` (`Domain`) bez WPF, COM i P/Invoke; može da se testira na bilo kojoj platformi.
- `Infrastructure.Windows` sadrži sve Win32, WFP, ETW i COM adaptere.
- `Service` orkestrira i jedini sme da kreira/ukloni Windows firewall pravila.
- Ne izlagati otvoreni localhost REST API; Named Pipe sa eksplicitnom lokalnom sigurnošću.
- UI ne radi kao administrator nakon instalacije. Osnovna konfiguracija servisa privilegovana; minimizovati prava i dokumentovati zašto su potrebna.

### 4.1 Tok događaja

1. ETW šalje mrežni događaj (send/receive/connect/close) u ograničeni `Channel<RawNetworkEvent>`.
2. Normalizator formira `FlowKey`: `(IP version, protocol, local IP, local port, remote IP, remote port, process instance)`.
3. Resolver mapira PID + `processStartTime` + executable path u trajni identitet aplikacije; čuva `unknown` kad nije moguće pouzdano mapiranje.
4. Agregator broji byte delte i connection transitions. U slučaju izgubljenih ETW događaja prijavljuje `dataQuality=partial`.
5. Writer grupno zapisuje agregate na ~1–5 sekundi i sirove konekcione događaje kontrolisano.
6. UI dobija delte u ritmu ~1s; pri reconnect-u učitava snapshot + cursor i obrađuje event stream idempotentno.
7. `SetRuleCommand` ide kroz auth/validation, snimanje željenog stanja, Windows firewall primenu i read-back verifikaciju. Tek potom UI prelazi na `applied`.

### 4.2 Odvajanje identiteta procesa i aplikacije

PID sam po sebi NIJE stabilan. Windows ponovo koristi PID-ove, exe na istoj putanji može da bude zamenjen, a više procesa može deliti isti EXE. Koristiti:

- `ProcessInstanceKey = PID + startTime`, uz opcionalni boot/session ID.
- `AppIdentity = normalized executable full path + signer metadata + optional sha256`; pravila Windows Firewall su primarno vezana za **putanju**, ne za hash.
- Process metadata dohvatati preko minimalno potrebnih `OpenProcess`/`QueryFullProcessImageName` prava; ako pristup nije moguć, ne prikazivati izmišljenu putanju.
- Hash računati asinkrono pri prvom viđenju/promeni fajla, sa ograničenjem CPU i broja paralelnih poslova; potpis proveravati putem Windows API-ja sa oprezom prema mrežnom opozivu sertifikata (privatnost).
- Sistemsku komponentu poput `svchost.exe` ne poistovećivati automatski sa tačno određenim Windows servisom; servis-level attribution tek nakon dodatnog dokaza.

---

## 5. NETWORK OBSERVABILITY — TEHNIČKI ZAHTEVI

### 5.1 Trenutne konekcije (P0)

**IP Helper**:

- `GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL)`
- `GetExtendedTcpTable(AF_INET6, TCP_TABLE_OWNER_PID_ALL)`
- `GetExtendedUdpTable(AF_INET, UDP_TABLE_OWNER_PID)`
- `GetExtendedUdpTable(AF_INET6, UDP_TABLE_OWNER_PID)`

Implementirati *two-call buffer allocation*, proveru dužina i `DWORD` overflow, 64-bit struct layout, endian konverziju portova, IPv6 scope IDs, OS error codes. Za UDP vlasničke tabele **ne tvrditi da nude tačan remote endpoint svih datagrama**: dopuniti ETW/WFP. Polovanje svakih 1–2 s prikazuje aktivne sokete, ali će propuštati kratkotrajne konekcije.

### 5.2 ETW (P1, obavezno za promet po aplikaciji)

Koristiti primer iz `Microsoft.Diagnostics.Tracing.TraceEvent` / `KernelTraceEventParser`. Proveriti u realnoj Windows VM da postoje/tačno rade TCP i UDP send/recv događaji, da li je PID vlasnik toka, polja broja bajtova, event loss, broj ETW sesija i sudar imena sesija. Implementirati posebni ETW collector sa cancellation/recovery.

- Ne sabirati `bytes` iz različitih događaja bez dokaza njihove semantike (payload vs transport vs link bytes); ne predstavljati procenu kao merenje na žici.
- Ne duplirati tokove kod retransmisije; eksplicitno definisati metodologiju i `metricDefinition`.
- Brojati upload/download odvojeno, u `long`/`ulong`, agregirati po seconds / minutes / hours / days.
- `unknown pid`, `lost events`, `VPN`, `proxy`, `loopback`, `WSL`, `Hyper-V` obeležiti kao ogranicenja.
- `netstat -abno`, Resource Monitor i Windows Performance Monitor koristiti kao pomoćnu proveru, ne kao apsolutni oracle.

### 5.3 DNS/host (P2)

- IP je stvarni udaljeni endpoint iz konekcije. DNS hostname je **opažena ili heuristički povezana informacija**, nikad dokaz da je taj host jedini cilj.
- DNS Client ETW / OS resolver događaje koristiti tek nakon provere payload-a i PID korelacije. Sa DoH, aplikacionim rezolverima, shared cache, CDN-om i više hostova na jednoj IP adresi hostname može ostati `unknown`.
- Reverse DNS automatski isključen zbog privatnosti i pozadinskih zahteva; može biti opcionalan korisnički zahtev.
- IP country je opciono lokalno učitana GeoIP baza uz zasebno proverenu licencu i izvor; „country“ je procena registracije IP, ne fizička geolokacija osobe.

### 5.4 Evidence blokiranja (P1/P2)

- Proveriti `FwpmNetEventSubscribe1` (Win8+) sa pravilnim verzijama struktura, API pravima i konfigurisanim WFP događajima.
- Fallback: **Audit Filtering Platform Connection failure**, event 5157; dokumentovati da policy audit opcija menja ponašanje Windows logova i može povećati overhead.
- Ne omogućavati `5152` packet-level audit ni `5156` success audit globalno po defaultu (veliki event volume).
- „Blocked by this app rule“ samo kada je povezan relevantan RuleId/filter origin ili verifikovana korelacija; inače „Blocked (source unknown)“.

---

## 6. FIREWALL ENFORCEMENT — NEGOZIJABILNA PRAVILA

### 6.1 MVP adapter

Definisati `IFirewallPolicyAdapter`:

```csharp
public interface IFirewallPolicyAdapter
{
    Task<FirewallCapabilityReport> GetCapabilitiesAsync(CancellationToken ct);
    Task<IReadOnlyList<ManagedRule>> ListOwnedRulesAsync(CancellationToken ct);
    Task<RuleApplyResult> UpsertOwnedRuleAsync(RuleSpec spec, CancellationToken ct);
    Task<RuleApplyResult> RemoveOwnedRuleAsync(Guid managedRuleId, CancellationToken ct);
    Task<EffectiveRuleReport> VerifyAsync(Guid managedRuleId, CancellationToken ct);
}
```

`RuleSpec` obavezno uključuje: `ManagedRuleId`, `AppPath` (ili eksplicitno odabrani drugi scope), `Direction` inbound/outbound, `Action` allow/block, `Profiles`, `Protocol`, `RemoteAddresses`, `RemotePorts`, `Enabled`, `Description`, `CreatedBy`, `SchemaVersion`.

Implementacija preko COM `INetFwPolicy2`/`INetFwRule` sa STA/MTA COM životnim ciklusom ispravno odvojenim od threadpool-a. Ne postavljati direktno SQL/IO/UI thread kroz COM zahtev. Ime kreiranih pravila prefiksirati npr. `LocalFirewall::{UUID}::{OUT}`; identitet u bazi i OS-u mora biti deterministički. Nikad ne koristiti wildcard brisanje Windows pravila drugih programa.

**Definicija uspeha:** COM/Windows potvrda + ponovni read-back svih ključnih polja + adekvatan aktivni profil + probni mrežni zahtev; čisto prisustvo pravila nije dokaz da je konekcija blokirana usled GPO pravila, izuzetaka ili drugog filtera.

### 6.2 Conflict resolution

- Windows ima podrazumevano **block inbound / allow outbound**, ali se može promeniti.
- Eksplicitno block pravilo ima prednost nad uobičajenim allow pravilom; postoje posebni slučajevi `Allow if Secure` / block override. Ne obećavati da obični `allow` može nadjačati drugi `block`.
- Prilikom „Unblock“ ukloniti/disable **samo sopstveni block**. Ako drugi firewall rule i dalje blokira, prikazati `Blocked by external policy`.
- Slučaj ApplicationName = exe path, shared executables, Store/UWP aplikacije, Windows servisni kontekst i rename EXE su posebni cases; prvo potvrditi ponašanje u testovima.
- Posle Windows Firewall promena od strane druge aplikacije, uraditi re-scan i prikazati konflikte; ne gaziti tuđe postavke.

### 6.3 Sklopljeni modovi

**Observe (default):** samo monitoring, ništa ne blokira.

**Click-to-block:** Windows Firewall default-i ostaju; korisnik ručno blokira app/scope/direction. Ovo je stvarni MVP.

**Alert on new application:** notify na prvu opaženu konekciju; ne tvrditi da je ta prva konekcija zaustavljena.

**Ask on blocked attempt (experimental):** prethodno blokirana aplikacija pokuša pristup; na osnovu WFP event-a UI nudi Allow, Block, Allow 15 min. Za uspeh je potrebna *nova konekcija aplikacije* posle uklanjanja block-a. Korisniku jasno prikazati tu semantiku.

**Default-deny outbound (advanced):** zasebna buduća faza sa unapred popisanim sistemskim izuzecima, potvrdom i AUTOMATSKIM rollback-om u slučaju gubitka konekcije. Nikad to ne aktivirati kao prvu implementaciju na stvarnoj radnoj stanici.

**Lockdown:** tek nakon implementacije rollback-a i testiranja na VM; profili moraju imati hitno vraćanje ranijeg stanja, čak i kad UI ne radi. Ne oslanjati se na korisnikov klik ako je sistem postao nedostupan.

### 6.4 Transakcioni tok komande

```text
VALIDATE -> WRITE(desired/pending) -> APPLY_OS -> READ_BACK ->
  SUCCESS => WRITE(applied, verifiedAt) -> NOTIFY_UI
  FAILURE => ATTEMPT_ROLLBACK -> WRITE(failed, reason, rollback_status)
```

Na restartu servisa obaviti reconciliation `desired` ↔ `actual` i logovati drift. Operacije idempotentne, serijalizovane po `ManagedRuleId`, sa audit tragom: user SID, vreme, pre/posle (bez čuvanja tajni).

---

## 7. SIGURNOSNI MODEL

**Princip najmanjih privilegija:**

- Korisnički UI radi bez admin tokena, nikad ne šalje sirove PowerShell komande, putanju skripte ili generički shell argument privilegovanom servisu.
- Servis za početni PoC može raditi kao LocalSystem zbog ETW/firewall ovlašćenja, ali hardening i minimalni dostupni service account treba proceniti pre javnog izdanja; zabeležiti privilegije koje zahtevaju konkretni API-ji.
- Named Pipe dostupan samo lokalnom interaktivnom autorizovanom SID-u i potrebnim servisnim identitetima; eksplicitni security descriptor, reject remote clients, client impersonation/identity check za privilegovane komande, rate limiting, message size limit, request ID, replay/idempotency.
- Ne koristiti podrazumevani pipe DACL bez analize: Windows dokumentuje da default može dozvoliti nepoželjna read prava.
- Konfiguracija, SQLite i backup-ovi pod `%ProgramData%\LocalFirewall\` sa eksplicitnim ACL; standardni korisnik ne piše u executable directory i ne može menjati binarne DLL-ove servisa.
- Installer u `%ProgramFiles%\LocalFirewall\`, potpisan za javno distribuiranje; nikada ne učitavati DLL ili plugin iz korisnički upisivih foldera.
- Ne preuzimati nepoznate block liste automatski, ne slati podatke o IP-ovima na javne threat-intel sajtove bez opt-in.
- U logove ne pisati TCP payload, DNS tajne/URL pun sadržaj, korisničke tokene, credentials.
- U odvojenim fuzz/unit testovima pokriti validaciju IP/CIDR, IPv6, portova, dužine stringova, JSON parsera, path normalization, SQL upita i DLL injection.
- Ukoliko servis umre, zadržavaju se već primenjena Windows Firewall pravila; UI mora pokazati `Service offline`. Uninstall mora pouzdano i samo ciljano ukloniti svoja pravila.

**Threat model:** maliciozan lokalni ne-admin proces, lokalni admin (van granica zaštite), neispravan installer, kompromitovan dependency, trovanje IPC zahteva, zamena exe na istoj putanji, lažni PID, cache poisoning, DoS visokim ETW event rate-om, offline recovery.

---

## 8. LOKALNA BAZA PODATAKA

SQLite `journal_mode=WAL`, `foreign_keys=ON`, schema migrations, prepared statements, batch insert, transactional updates, indexes po `time`, `app_id`, `remote_ip`, `rule_id`; `VACUUM` samo kontrolisano, `PRAGMA integrity_check` na oporavku ili periodično sa ograničenjem IO.

**Tabele (minimalne):**

- `apps(id, normalized_path, display_name, signer, sha256, first_seen_utc, last_seen_utc, file_changed_at, identity_confidence)`
- `process_instances(id, app_id, pid, start_time_utc, end_time_utc, user_sid, session_id)`
- `flows(id, process_instance_id, ip_version, protocol, local_ip, local_port, remote_ip, remote_port, interface_luid, start_utc, end_utc, direction, attribution_quality)`
- `traffic_buckets(app_id, remote_ip_nullable, bucket_start_utc, granularity, upload_bytes, download_bytes, event_count, quality_flags)`
- `dns_observations(id, process_instance_id_nullable, query, answer_json, time_utc, source, confidence)`
- `firewall_rules(id, display_name, executable_path, direction, action, profiles, protocol, ports, remote_cidrs, enabled, desired_state, actual_state, os_rule_name, last_verified_utc, last_error)`
- `rule_audit(id, rule_id, actor_sid, timestamp_utc, old_json, new_json, result, error_code)`
- `alerts(id, type, severity, app_id_nullable, flow_id_nullable, emitted_utc, dismissed_utc, details_json)`
- `settings(key, value_json, schema_version)`
- `schema_migrations(version, applied_utc, checksum)`

**Retencija (default predlog, podesivo):** raw flow/alerts 30 dana, sec buckets 24 h, min buckets 30 dana, hour buckets 12 meseci, day buckets dok korisnik ne obriše. Granice veličine baze npr. 2GB default soft cap uz upozorenje. Nema „unlimited“ bez kontrole.

**Bitno:** vremenske oznake UTC za bazu i lokalna zona samo za prikaz; 64-bit counters i `SUM` bez overflow-a; jasno definisati da prikazani „traffic bytes“ mogu biti približni ETW brojači, ne ISP obračun.

---

## 9. UX SPECIFIKACIJA (ORIGINALAN DIZAJN)

**Glavna navigacija:** `Overview | Live Connections | Apps | Firewall Rules | History | Alerts | Settings`.

### Overview
- Trenutna upload/download brzina (odvojene serije), selektor `Last 5m / 1h / 24h / 7d / custom`.
- Top 10 aplikacija po procenjenom saobraćaju.
- Broj novih aplikacija, aktivnih konekcija, uspešnih/odbijenih pravila.
- Status bar `Monitoring active | Firewall control active | ETW partial | Database OK`.
- U legendi: kako se meri traffic i kada je delimičan.

### Live Connections
- Tabela virtualizovana i sortirana: App (icon + ime), PID, protocol, local, remote IP:port, hostname? (samo ako confidence), status, direction, adapter, started, up/down estimated.
- Filteri: process, remote IP, port, UDP/TCP, IPv4/6, only new, blocked, active, loopback.
- Kontekstni meni: `Block outbound for this app`, `Block inbound`, `Open file location`, `Inspect signer`, `Copy IP`, `View history`.
- Tooltip jasno razlikuje `Observed DNS host` od `Verified endpoint`.

### Apps
- Grupisani procesi po `AppIdentity`, top traffic, first/last seen, status pravila, trust metadata bez izmišljenog malware score-a.
- Klik na app otvara detalj: sva opažena odredišta, trend i dugmad za block/unblock.

### Firewall Rules
- Precizni scope/direction/profiles, owned vs external rules (external read-only); mogućnost `Recheck Windows policy`.
- Pred-pregled promene i potvrda za sistemske procese / široke blokade.
- U slučaju konflikta `Blocked by another rule` umesto lažnog zelenog `Allowed`.

### History / Alerts
- Pretraga po aplikaciji, vremenu, IP-u, portu, protokolu, vrsti upozorenja; export.
- Alert rate-limiting: deduplikacija prvog povezivanja, quiet hours, snooze, no popup storms.
- Sistem notifikacija bez forced focus; UI startuje u tray, ali servis radi nezavisno.

### Settings
- Privacy: `No external lookups` default, GeoIP opt-in (offline DB), redaction, auto-retention.
- Sampling/polling interval, ETW health, event loss, database size, diagnostics export (sa redakcijom).
- Startup, theme dark/light, notifications, rules backup/restore.

**Stil:** moderan Windows desktop, neutralne boje, pristupačan kontrast, ne kopirati GlassWire raspored, grafičke elemente ili trademark. Lokalizacija EN/SR može kasnije; interni kod na engleskom.

---

## 10. UI / SERVICE IPC PROTOKOL

Envelope:

```json
{
  "version": 1,
  "id": "UUID",
  "type": "rule.apply",
  "requestedAtUtc": "2026-11-01T00:00:00Z",
  "payload": {
    "managedRuleId": "UUID",
    "appPath": "C:\\Program Files\\Example\\example.exe",
    "direction": "outbound",
    "action": "block",
    "enabled": true,
    "profiles": ["domain", "private", "public"]
  }
}
```

Server izdaje `capabilities`, `serviceHealth`, `snapshot`, `live.events`, `rule.apply`, `rule.remove`, `rule.verify`, `history.query`, `config.get/set`, `diagnostics.export`. Odgovor uključuje `{id, ok, result, error:{code,message}, currentRevision}`; event stream ima monotonic sequence i reconnect checkpoint.

**Validacija:** verzija protokola, max message npr. 256 KiB, regex/typed enum, path canonicalization/UNC policy, timeouts, cancellation, user SID, privilege checks per command; nema arbitrarnog `exec` endpointa. Kod komandi za firewall obavezno audit.

---

## 11. PREPORUČENA STRUKTURA REPOZITORIJUMA

```text
LocalFirewall/
  README.md
  LICENSE
  SECURITY.md
  CONTRIBUTING.md
  global.json
  Directory.Build.props
  Directory.Packages.props
  LocalFirewall.sln
  src/
    LocalFirewall.Contracts/         # messages, DTO, enums
    LocalFirewall.Core/              # domain logic, policies, reducers
    LocalFirewall.Infrastructure.Windows/
      IpHelper/
      Etw/
      ProcessIdentity/
      Wfp/
      FirewallCom/
    LocalFirewall.Persistence/       # sqlite + migrations
    LocalFirewall.Service/           # Worker/host/IPC
    LocalFirewall.UI/                # WPF MVVM Views/ViewModels
    LocalFirewall.Installer/         # WiX
  tests/
    LocalFirewall.Core.Tests/
    LocalFirewall.Persistence.Tests/
    LocalFirewall.Windows.IntegrationTests/
    LocalFirewall.IPC.SecurityTests/
    LocalFirewall.E2E.Tests/
    fixtures/
  docs/
    ARCHITECTURE.md
    API_CONTRACTS.md
    SECURITY_MODEL.md
    TRAFFIC_METRICS.md
    FIREWALL_RECOVERY.md
    TEST_MATRIX.md
    ADR/
  scripts/
    dev-install.ps1
    dev-uninstall.ps1
    verify-firewall.ps1
  .github/workflows/
    build.yml
    test.yml
    security.yml
```

**Repo hygiene:** nema automatskog commita ili merge-a bez proverenog build-a, testova i diff review-a. Raditi u malim PR-ovima. Dokumentovati arhitekturne odluke u `docs/ADR`.

---

## 12. REDOSLED IMPLEMENTACIJE — STRIKTNI MILESTONES

### FND-001 — Repo, build, mock UI
- Napraviti .NET solution sa clean boundaries, lint, nullable enable, warnings as errors selektivno.
- WPF shell sa navigacijom, mock connection stream i 2 serije grafikona; bez admin prava.
- Testirati build na ciljnom Windows OS i redovan start/close, dark/light.
- **DoD:** `dotnet build`, unit tests, video/screenshot UI, nula promena Windows firewall pravila.

### FND-002 — Real process/connection inventory (read-only)
- IP Helper adapter za IPv4/v6 TCP/UDP; proces identity; 1–2 sekunde polling.
- UI `Live Connections`, sortiranje, filter, deduplikacija.
- **DoD:** tačni PID-ovi i endpoints kod kontrolisanog test client/server procesa; kratke konekcije označene kao nepotpune (poll-only).

### FND-003 — Windows Service + secure local IPC
- Worker Service, installer samo za VM prvo; Named Pipe ACL i auth; UI reconnect.
- Bez firewall write endpointa u ovoj fazi.
- **DoD:** UI radi bez admin, drugi neovlašćeni Windows korisnik ne može pozvati servis; servis preživljava zatvaranje UI-ja.

### FND-004 — ETW traffic monitoring
- ETW TCP/UDP collection, PID mapping, event loss metrics, rolling buckets, UI graph.
- Dopuniti integration tests up/down, TCP/UDP, IPv6, loopback.
- **DoD:** korisnički vidljiv promet po app i kvalitativna oznaka; stres test bez memory leak; bez tvrdnje o apsolutnoj tačnosti.

### FND-005 — SQLite history
- Migracije, batch, agregacije, retention, query/paging, CSV.
- **DoD:** reboot/restart persistence, time-window queries, timezone, korektni 64-bit brojači, cleanup, corrupt DB recovery.

### FND-006 — Click-to-block firewall (PRVA WRITE FAZA)
- `IFirewallPolicyAdapter` COM; samo app-scoped outbound/inbound block u VM.
- Unique owned rules, transaction state, verify, idempotence, partial failure, safe uninstall.
- **DoD:** realno blokiranje test.exe outbound, drugi program nije pogođen, pravilo opstaje posle UI exit/reboot, unblock čisti SAMO svoje pravilo.

### FND-007 — Alerts + WFP evidence
- New-app event, blocked-event source, notifications, dedupe, snooze.
- Proceniti WFP subscription, event 5157 fallback; ne uključivati globalni audit bez opcije/consent-a.
- **DoD:** reproduktivni blocker alert u testu, bez pop-up storma, nepripisani eventi označeni unknown.

### FND-008 — Advanced rules, profiles, import/export
- IP/CIDR, port, protocol, Windows firewall profile; manual named profiles.
- Automatic switching kao opt-in tek nakon VM testova i recovery dizajna.
- **DoD:** pravila u UI odgovaraju verifikovanim OS pravilima, konfliktnu konfiguraciju prikazati bez lažnog `Allowed`.

### FND-009 — Installer, hardening, long-running QA
- MSI install/repair/upgrade/uninstall, backup/restore, recovery CLI, signed release process, perf/security tests.
- **DoD:** fresh install, upgrade, uninstall, 24h soak, multi-user, no data leakage, no remaining owned rules after uninstall.

### FND-010 — OPTIONAL premium-grade advanced features
- First attempt ask gating / global outbound deny only kao odvojen R&D, firewall driver samo uz dokaz da standardne WFP filtering conditions ne mogu rešiti zahtev.
- GeoIP offline, DNS visibility, local network device discovery, optional reputation provider, per-app profiles.
- **DoD:** posebno odobrene arhitekturne odluke i threat model, backwards compatibility, nema destabilizacije osnovnog monitora.

**Pravilo rada agenta:** bez skakanja na FND-006 pre završene read-only telemetrije; nijedan agent ne sme tvrditi da je program firewall dok nije demonstrirao OS-level block test.

---

## 13. VERIFIKACIJA I TEST MATRICA

| ID | Scenario | Očekivanje |
|---|---|---|
| T01 | TCP IPv4 outbound | prikazan pravi proces i IP/port |
| T02 | TCP IPv6 outbound | ispravan IPv6 i PID |
| T03 | UDP/QUIC | mrežni događaj zabeležen, remote kada je pouzdano poznat |
| T04 | 1000 kratkih konekcija | dokumentovane granice pollera; ETW ne guši UI |
| T05 | Lokalni localhost LLM HTTP server | jasno kao loopback; ne blokira se slučajno |
| T06 | 4 GPU workload + high network throughput | softver ne izaziva vidljiv stall ili nekontrolisanu CPU potrošnju |
| T07 | VPN/virtual NIC | nepotpuno pripisivanje označeno, ne duplirati automatski |
| T08 | Izlazni block samo za test app | drugi program nastavlja mrežni pristup |
| T09 | Inbound block test servera | test klijent ne može uspostaviti očekivanu vezu po scope-u |
| T10 | App path moved/EXE replaced | očuvana tačna semantika path-bound rule; alert za promenu identiteta |
| T11 | External conflicting rule/GPO | UI pokazuje conflict, ne pretpostavlja allow |
| T12 | Service killed / UI closed | pravila ostaju; monitoring offline se ne prikazuje kao online |
| T13 | Restart i reboot | servis se vrati, baza čitljiva, rules reconciliation |
| T14 | Uninstall | uklanja samo vlastite firewall rule GUID-ove |
| T15 | Neprivilegovani IPC klijent | pristup odbijen; nema generic command execution |
| T16 | Large logs / malformed IPC | rate limits, bounded memory, nema crash-a |
| T17 | Security 5157 off/on | objašnjeno šta je dostupno bez audit-a |
| T18 | DNS over HTTPS | hostname nije falsifikovan; prikazan unknown |
| T19 | Windows update / DNS / time sync | ne blokiraju se u običnom režimu |
| T20 | Sleep/resume, network switch | kolektori se oporavljaju bez lažnih duplikata |

**Dve vrste testa:** (1) *Unit/contract tests*: pure domain rules, IPC schema i SQL; (2) *Windows integration/E2E* u izolovanoj VM. Ne pokretati automatske destructive testove na produktivnoj radnoj stanici. Testirati i kada Windows firewall servis/BFE nisu dostupni: softver mora degradirati bez fatal crash-a.

**Rukovanje performansama:** profilisati ETW lost event count, upotrebu CPU-a i RAM-a, WAL veličinu, UI frame time, dužinu bounded queue; rezultati moraju biti zapisani u izveštaju. Ako polling, tracing ili DB worker pregaze budget, prilagoditi i zabeležiti kompromis.

---

## 14. INSTALACIJA, REŠAVANJE KVAROVA, POVRATAK

Prvo implementirati development mode **bez servisa**, samo read-only collector. Zatim servis instalirati u Windows VM, uz snapshot. Početna instalacija mora proveriti: OS, arhit., .NET, admin/UAC, BFE + Windows Firewall service status, slobodan disk, event tracing prava.

- Installer uključuje eksplicitan *opt-in* za firewall upravljanje; v1 default `Observe`.
- Upgrade/repair ne resetuje Windows Firewall, baze ili sve sistemske rules.
- Deinstalacija pronalazi tačna `LocalFirewall::{UUID}` pravila iz sopstvene baze i dopunske, proverene enumeracije; vrši brisanje sa verifikacijom. Kada bezbedno uklanjanje nije moguće, installer javlja stanje i pruža dokumentovanu ručnu recovery proceduru.
- `localfirewall-cli --status`, `--list-owned-rules`, `--disable-owned-rules`, `--repair-owned-rules` kao **privilegovane** dijagnostičke komande; CLI ne sme nuditi „reset whole OS firewall“.
- `Emergency restore`: lokalni recovery mehanizam za eksperimentalni lockdown (posebna faza) vraća PRETHODNO SNIMLJENE promene ili uklanja samo vlastite pravila. Obezbediti rollback i pri nedostupnom UI-ju.

**Ne činiti:** ručno gasiti firewall/BFE, brisati sve rule grupe, isključivati logove drugih proizvoda, menjati globalni outbound default policy tokom FND-006, automatski whitelist-ovati sve Windows procese.

---

## 15. AI AGENT PRAVILA RADA

Raditi kao iskusni Windows security/network engineer. Lokalni model treba da čita ovaj handoff i *tačno jednu FND fazu* po iteraciji. Pre implementacije:

1. Kratko potvrditi opseg date faze, uključene Windows API-je, rizike, i acceptance testove.
2. Proveriti dokumentaciju za API-je umesto izmišljanja P/Invoke signature/layout-a i ETW event fieldova. Potražiti postojeće testirane interop definicije odgovarajuće licence.
3. Kreirati mali PR sa kodom, testovima, dokumentacijom i jasnim uputstvom za lokalnu verifikaciju.
4. Pokrenuti `dotnet restore`, `dotnet build`, `dotnet test`, i dodatne Windows testove koji su mogući; ako nisu dostupni, jasno opisati *not run*.
5. Ne menjati unrelated fajlove; ne brisati istoriju; ne menjati OS firewall na lokalnom računaru bez korisničkog pristanka.
6. Pri problemu izneti konkretni logs i minimalno reprodukovanje; bez skrivanja `catch { }` ili izmišljene verifikacije.
7. Ne praviti „mock-like working firewall“: svaki enforcement feature mora imati demonstraciju realnog Windows pravila i test ponašanja mreže.
8. Nakon svake faze dostaviti: files changed, API decisions, build/test output, known limitations, risks, next phase, rollback.

### Definicija „kompletna v1“

Nije dovoljno da UI izgleda lepo. V1 je spreman tek kada:
- UI+servis rade bez cloud naloga, servis sa validnim IPC ACL;
- stvarni procesi, konekcije, traffic i istorija rade uz označen kvalitet podataka;
- kontrolisano blokiranje jedne aplikacije je dokazano;
- pravila se mogu bezbedno ukloniti/recover-ovati;
- odgovarajući integration/E2E testovi prođu na podržanom Windows OS-u;
- release je dokumentovan sa poznatim ograničenjima.

---

## 16. DOKUMENTOVANE TEHNIČKE GRANICE

**Firewall vs monitor:** Windows Firewall enforcement i monitoring su dve različite funkcije. Može postojati blokiranje kada UI/ETW ne rade. 

**Process attribution:** pri PID reuse, servisnim procesima i tunelima, identitet nekih tokova neće biti pouzdan. Prikazati `unknown` i quality metadata.

**Domains:** veza sa IP adresom nije jednaka domenu. DoH/QUIC, shared cache/CDN i aplikacioni DNS zahtevaju naročito opreznu korelaciju.

**Bandwidth:** korisnički bytes, ETW network event bytes i interface/ISP „wire bytes“ nisu isti; tačno imenovati metriku i testirati odstupanja.

**Ask-to-connect:** „popup posle blokiranja“ je validan oprezan režim, ali nije generalna interaktivna kernel autorizacija prvog paketa. Ne predstavljati korisniku kao istu stvar.

**Fokus:** izbegavati konkurenciju sa Windows Defender, antivirusima, VPN-ovima, drugim firewall-ovima; poštovati njihove aktivne filtere i prijaviti konflikte.

---

## 17. IZVORI ZA OBAVEZNU IMPLEMENTACIONU PROVERU

1. Windows Firewall COM API / `INetFwRule`: https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
2. `INetFwPolicy2::get_Rules`: https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_rules
3. WFP architecture: https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview
4. WFP kernel driver considerations: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations
5. IP Helper TCP owner table: https://learn.microsoft.com/en-us/windows/desktop/api/iphlpapi/nf-iphlpapi-getextendedtcptable
6. Windows Firewall rules / priority: https://learn.microsoft.com/en-za/windows/security/operating-system-security/network-security/windows-firewall/rules
7. WFP net events subscription: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe1
8. Auditing 5156/5157: https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging
9. Named Pipe security: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
10. Windows service worker: https://learn.microsoft.com/en-us/dotnet/core/extensions/windows-service
11. .NET 10 policy: https://dotnet.microsoft.com/en-us/platform/support/policy
12. .NET OS support: https://learn.microsoft.com/en-us/dotnet/core/install/windows
13. Windows 10 Pro 21H2 EOL: https://learn.microsoft.com/en-us/lifecycle/announcements/windows-10-21h2-end-of-servicing
14. GlassWire official features: https://www.glasswire.com/features/
15. GlassWire user guide: https://www.glasswire.com/userguide/
16. simplewall: https://github.com/henrypp/simplewall
17. Portmaster: https://github.com/safing/portmaster
18. ScottPlot: https://github.com/ScottPlot/ScottPlot
19. KernelTraceEventParser reference: https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs

---

## 18. ŠTA TREBA URADITI PRVO

**Prvi implementacioni zadatak: FND-001.** Napraviti `.NET 10` solution sa WPF UI i mock konekcijama, ugrađenom MVVM arhitekturom i testovima, bez instalacije servisa, bez kernel drajvera, bez menjanja sistemskih firewall pravila. Ciljna platforma je Windows 11 x64; Windows 10 Pro 21H2 best-effort / unsupported, to eksplicitno napisati u README.

**Tek posle FND-001 krenuti na FND-002**, tj. stvarni read-only Windows network process inventory.
