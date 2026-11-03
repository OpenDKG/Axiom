# LocalFirewall

**Repository:** https://github.com/a-51-50/VigilMesh · **License:** GPL-3.0-or-later ·
**Working name:** LocalFirewall (repository brand: VigilMesh)

*Intelligent protection. Open by design.*

Lokalna Windows aplikacija za praćenje mrežnog saobraćaja po aplikaciji i upravljanje pravilima
ugrađenog Windows Firewall-a. Originalan kod i vizuelni identitet; bez GlassWire brendinga i bez
preuzetog GPL koda.

> **Status: FND-005 — lokalna SQLite istorija.**
> `Live Connections` i `Apps` čitaju stvarne TCP/UDP sokete; servis ih upisuje u lokalnu bazu i
> `History` stranica prikazuje pretragu po vremenu, aplikaciji, udaljenoj adresi i PID-u, sa CSV
> izvozom. Grafik propusnosti je i dalje demo serija: **FND-004 (ETW bajtovi) je odložen** jer ETW
> kernel sesija zahteva elevaciju, koju ova razvojna sesija nema (`logman` → Access denied).
> Nijedno Windows Firewall pravilo se ne čita, ne kreira i ne menja.

## Šta trenutno radi

| Oblast | Stanje |
|---|---|
| .NET 10 solution, 7 projekata + 4 test projekta | ✅ build prolazi |
| Stvarni TCP/UDP inventar (IPv4/IPv6), polling 1 s | ✅ IP Helper owner tabele |
| Windows servis (konzolni režim) + Named Pipe IPC | ✅ ACL + SID provera + limiti |
| UI preko servisa (`--service`) sa reconnect-om | ✅ |
| SQLite istorija: schema, WAL, upsert, retencija | ✅ FND-005 |
| `History`: vremenski opseg, pretraga, CSV izvoz | ✅ |
| Oporavak od korumpirane baze | ✅ backup `.corrupt-*` + rekreacija |
| `Live Connections` / `Apps` / Overview | ✅ stvarni podaci |
| Grafik propusnosti / bajtovi po aplikaciji | ⚠️ demo serija (FND-004 odložen) |
| Testovi | ✅ 87 |
| Standalone (self-contained, single-file) build | ✅ `artifacts\publish\win-x64\LocalFirewall.Desktop.exe` |
| Instalacija servisa / MSI | ❌ FND-009 |
| Windows Firewall pravila | ❌ adapter `Unavailable` (FND-006) |

## Šta namerno ne radi

- Ne zahteva administratora u UI/konzolnom režimu; servis se ne instalira.
- Ne otvara HTTP port; samo lokalni Named Pipe sa DACL-om.
- Ne poziva COM `INetFwPolicy2`, `netsh`, WFP ni firewall API.
- Ne pravi odlazne mrežne zahteve.
- Ne čuva payload, TLS sadržaj ni DNS upite — samo metapodatke konekcije.
- Ne tvrdi da meri bajtove; grafik je označen `DEMO SERIES`.

## Zahtevi

- **Podržan target:** Windows 11 x64; Windows 10 je best-effort (razvojna mašina: Windows 10 IoT
  Enterprise LTSC 2021, 10.0.19044).
- **.NET SDK 10.0.403** (`global.json`) za build; objavljena verzija ne traži runtime.
- **ETW (FND-004) zahteva elevaciju** ili servisni nalog; ova sesija je UAC-filtered.

## Pokretanje

```powershell
# servisni režim (istorija radi samo ovako)
.\scripts\run-service.ps1

# ili ručno
dotnet run --project src\LocalFirewall.Service -c Release
dotnet run --project src\LocalFirewall.Desktop -c Release -- --service

# in-process (bez istorije)
.\artifacts\publish\win-x64\LocalFirewall.Desktop.exe
```

`--service` koristi Named Pipe i servisnu bazu; bez njega UI čita IP Helper direktno i `History`
prikazuje da je potreban servis.

## Istorija (FND-005)

- Baza: `%LOCALAPPDATA%\LocalFirewall\localfirewall.db` u konzolnom/per-user režimu;
  `%ProgramData%\LocalFirewall\` za instalirani servis (FND-009). `LOCALFIREWALL_DATA_DIR` menja putanju.
- SQLite `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`.
- Tabele: `schema_migrations`, `apps`, `flows`, `traffic_buckets` (pripremljena za FND-004), `settings`.
- Upis: servis grupiše snimke na **2 s** (ne po pollu); upsert po
  `(app, protocol, local, remote, pid)`; `first_seen` se ne menja, `last_seen` se ažurira.
- Retencija: 30 dana (`DefaultRetention`), pokreće se na startu i svakih sat vremena.
- Query: UTC opseg + pretraga po imenu/putanji/udaljenom endpointu/PID-u, limit i offset.
- CSV izvoz: korisnik bira putanju; UTF-8 sa BOM; escapovanje zareza, navodnika i novih redova.
- Korumpiran fajl: detektuje se (`integrity_check`/SQLite 26), premešta u
  `localfirewall.db.corrupt-<timestamp>` i baza se rekreira.

## Build, testovi, standalone

```powershell
dotnet restore LocalFirewall.sln --locked-mode
dotnet build LocalFirewall.sln -c Release --no-restore
dotnet test LocalFirewall.sln -c Release --no-build
.\scripts\publish-standalone.ps1
```

Testovi: Core 38, Contracts 10, Persistence 11 (uključujući istoriju), Infrastructure 28.

## IPC ugovor

- Pipe `\\.\pipe\LocalFirewall.Service.v1`, NDJSON, zahtev max **256 KiB**, odgovor max **4 MiB**
  (snapshot sa više hiljada soketa prelazi limit zahteva).
- Komande: `serviceHealth`, `capabilities`, `snapshot`, `history.query`.
- `rule.*`, `config.*`, `diagnostics.*`, `live.events` → `not_supported`.
- DACL: allow servisni nalog + jedan SID; deny `Network`/`Anonymous`/`Guests`; SID klijenta se
  proverava posle konekcije.

## Struktura

```text
src/
  Contracts/ · Core/ · Infrastructure.Windows/ · Persistence/
  Service/        # Worker host, monitoring, history writer, pipe
  UI/             # WPF biblioteka (Views/ViewModels/tema)
  Desktop/        # composition root / jedini UI EXE
tests/
  Core (38) · Contracts (10) · Persistence (11) · Infrastructure.Windows (28)
docs/
  ARCHITECTURE.md / SECURITY_MODEL.md / TEST_MATRIX.md / ADR/
scripts/
  run-local.ps1 / run-service.ps1 / publish-standalone.ps1
```

## Sledeći korak — FND-004 (ETW bajtovi)

1. ETW kernel network sesija (`Microsoft-Windows-Kernel-Network`), send/receive po PID-u.
2. Agregacija u `traffic_buckets`, event-loss metrika, `partial` kvalitet.
3. Pravi Up/Down po aplikaciji i grafik umesto demo serije.
4. Provera na eleviranoj sesiji ili VM-u: `logman`/`TraceEventSession` zahteva
   `SeSystemProfilePrivilege`, koji UAC-filtered token nema.

## Verifikacija

[docs/TEST_MATRIX.md](docs/TEST_MATRIX.md); snimci `artifacts/screenshots/fnd005-*.png`.

## Licenca

Projekat je licenciran pod **GPL-3.0-or-later**. Pun tekst: [`LICENSE`](LICENSE); autorska prava i
grant: [`NOTICE`](NOTICE); third-party komponente: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md);
imena i logotipi: [`TRADEMARKS.md`](TRADEMARKS.md). Licencne odluke i kompatibilnost zavisnosti:
[`docs/LICENSING.md`](docs/LICENSING.md) i
[`docs/ADR/0005-license-gpl-3.0-or-later.md`](docs/ADR/0005-license-gpl-3.0-or-later.md).

Doprinosi se prihvataju pod istom licencom uz DCO (`git commit -s`); vidi
[`CONTRIBUTING.md`](CONTRIBUTING.md). Svi pinovani paketi su MIT ili Apache-2.0 i kompatibilni su sa
GPLv3. Ne dodavati GPL-inkompatibilan kod niti tuđe feedove bez licence i pravne provere.
