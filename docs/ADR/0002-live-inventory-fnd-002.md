# ADR 0002 — FND-002: stvarni read-only inventar soketa kroz Desktop composition root

- **Status:** prihvaćeno
- **Datum:** 2026-11-03
- **Milestone:** FND-002
- **Nadovezuje se na:** ADR 0001

## Kontekst

Korisnik mora da vidi **stvarne** procese i konekcije, ne demo redove. Handoff FND-002 traži IP Helper
adapter za IPv4/IPv6 TCP/UDP, identitet procesa, polling 1–2 s, deduplikaciju i UI `Live Connections`,
uz tačne PID-ove i endpointe za kontrolisani test.

Istovremeno važi pravilo iz handoff-a: **UI zavisi samo od Contracts** i ne sme da sadrži Win32/COM
kod. `LocalFirewall.UI` je do sada bio izvršni projekat (WPF shell), pa nije bilo mesta za Windows
adapter bez kršenja granice.

Dodatno, .NET SDK ne dozvoljava da self-contained izvršni projekat referencira drugi izvršni projekat
(`NETSDK1150`), a WPF biblioteka ne može da sadrži `ApplicationDefinition` (`MC1002`).

## Odluke

### 1. `LocalFirewall.UI` postaje WPF biblioteka, `LocalFirewall.Desktop` je jedini EXE

- UI zadržava Views/ViewModels/temu i **samo** `Contracts` referencu.
- Desktop je composition root: registruje `IpHelperConnectionSource`, pravi `ConnectionMonitor` i
  `MainViewModel`, pa pokreće WPF aplikaciju.
- `App.xaml` (resursi, DataTemplate-ovi, tema) živi u Desktop-u i koristi apsolutne pack URI-jeve ka
  `LocalFirewall.UI` assembly-ju.
- Standalone publish ima jedan ulazni assembly i ne referencira drugi EXE.

**Posledica:** dependency pravilo je sačuvano; UI se ne može kompajlirati ako pokuša da pozove
IP Helper ili firewall. Cena je jedan dodatni projekat i pack URI-ji u `App.xaml`.

### 2. IP Helper owner tabele, obe familije, two-call buffer

Koriste se `GetExtendedTcpTable`/`GetExtendedUdpTable` sa `OWNER_PID` klasom za `AF_INET` i `AF_INET6`.
Buffer se alocira u dva poziva; redovi se čitaju `PtrToStructure` sa tačnim veličinama (24/56/12/28).
Portovi se byte-swap-uju, IPv4 adrese čitaju kao mrežni redosled, IPv6 preko `IPAddress(bytes, scopeId)`.

**Posledica:** nema admina, nema drajvera, nema packet capture-a; čita se tabela koju Windows već drži.

### 3. Identitet procesa preko minimalnog handle-a

`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageName`, keš 30 s. Pristup
odbijen ili zaštićen proces → `unknown path`, kvalitet `Partial`, nikada izmišljena putanja.

**Posledica:** sistemski procesi (npr. `svchost` pod SYSTEM nalogom) često nemaju čitljivu putanju bez
elevacije; UI to prikazuje pošteno i broji takve redove u ograničenjima.

### 4. Smer, `first seen` i kvalitet su eksplicitno izvedeni

- IP Helper nema polje smera. TCP: `Listen` ili lokalni listener ispod efemernog opsega (49152) →
  inbound; ostalo outbound. UDP: `Unknown`.
- IP Helper nema vreme nastanka veze. `FirstObservedUtc` je prvi poll u kojem je veza viđena, a
  `IsNew` traje 60 s od tada.
- Kvalitet: `Observed` samo kada su PID > 4 i putanja pouzdani; inače `Partial`.

**Posledica:** nema lažne preciznosti; korisnik vidi `?` za UDP i `partial` za nepotpune redove.

### 5. PID 0 nije aplikacija

Redovi sa PID 0 su `TIME_WAIT`/kernel ostaci. Prikazuju se u tabeli kao
`System · unowned (PID 0)`, ne ulaze u `Apps` grupisanje, a broj se prikazuje u rezimeu.

**Posledica:** top liste prikazuju stvarne procese, ali se ne krije da postoji veliki broj neowned
soketa.

### 6. Polling 1 s sa diff ažuriranjem i live sortiranjem

`ConnectionMonitor` anketira izvor na UI dispatcher-u, a `CaptureAsync` radi na thread pool-u. Redovi
se ažuriraju u mestu po ključu `protocol|local|remote|pid`; novi se dodaju, nestali uklanjaju.
`DataGrid` sortira po `StateRank`, a `Apps` koristi `ListCollectionView.IsLiveSorting`.

**Posledica:** sortiranje i selekcija preživljavaju polling; nema treperenja tabele svake sekunde.
Kratke veze između pollova se propuštaju i to je dokumentovano.

### 7. Demo ostaje samo za grafik propusnosti

Bajtovi nisu dostupni iz owner tabela. `DemoTrafficEngine` i dalje crta demo seriju, jasno označenu
`DEMO SERIES`; `Live Connections` i `Apps` više ne sadrže demo redove. `DemoConnectionSnapshotSource`
ostaje kao fallback za dizajn/test, ali ga objavljeni Desktop ne registruje.

**Posledica:** nema mešanja izmišljenih konekcija sa stvarnim; merenje dolazi u FND-004.

### 8. `netstat -ano` je referentni oracle, ne `Get-Net*` cmdleti

Na test mašini `Get-NetTCPConnection` prikazuje ~100 dodatnih redova u stanju `Bound`, a
`Get-NetUDPEndpoint` ne prikazuje sve UDP endpointe. Poređenje sa `netstat -ano` (iste tabele) dalo je
TCP 223 vs 225 i UDP 114 vs 114.

**Posledica:** verifikacija je reproduktivna i objašnjava razliku; `Get-Net*` se ne koristi kao dokaz.

## Posledice

Pozitivne:

- Stvarni podaci bez admina i bez servisa; arhitektonska granica je sačuvana.
- Deterministički integracioni testovi za TCP/UDP i identitet procesa.
- Standalone publish je ponovo moguć i ostaje jedan EXE.

Negativne / rizici:

- Poll-only pristup propušta kratke veze i ne daje bajtove.
- Putanje sistemskih procesa su često nedostupne bez elevacije.
- Smer i `first seen` su heuristike; moraju ostati označene.
- Dodatni projekat i pack URI-ji povećavaju inicijalnu složenost WPF resursa.
- Nema perzistencije: restart gubi istoriju i `first seen`.

## Razmatrane alternative

| Alternativa | Zašto nije izabrana |
|---|---|
| UI direktno referencira `Infrastructure.Windows` | Krši pravilo „UI → Contracts“ i otvara put ka firewall kodu iz UI-ja |
| Odmah servis + IPC (FND-003) | Veći bezbednosni dizajn; FND-002 je read-only i ne zahteva ga |
| ETW pre inventara | ETW ne daje PID/endpoint tabelu; IP Helper je pravi prvi korak |
| WFP eventi za konekcije | Zahteva WFP pretplatu i privilegije; FND-007 |
| UI kao EXE sa `InternalsVisibleTo` trikom | Ne rešava `NETSDK1150` za self-contained publish |
| Demo redovi pomešani sa stvarnim | Nedopustivo: korisnik ne bi znao šta je merenje |

## Sledeće odluke

- FND-003: servisni nalog, ACL pipe-a, reconnect i premeštanje kolektora u servis.
- FND-004: ETW metrika (payload vs. wire), event-loss budžet, pravi grafik.
- FND-010: hash/potpis identiteta i PID start time.
