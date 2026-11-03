# Arhitektura — LocalFirewall (FND-005)

Stvarno stanje: read-only inventar u servisu, lokalni Named Pipe, SQLite istorija i UI koji radi
in-process ili preko servisa. FND-004 (ETW bajtovi) je odložen jer zahteva elevaciju.

## 1. Kontekst

```text
┌────────────────────────────────────────────────────────┐
│ LocalFirewall.Desktop (WinExe, asInvoker)              │
│ bira izvor: in-process ili servis                      │
└───────────────┬────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────┐
│ LocalFirewall.UI (WPF biblioteka, samo Contracts)      │
│ Live/Apps/History/Overview · ConnectionMonitor         │
└───────┬──────────────────────────────┬─────────────────┘
        │ IConnectionSnapshotSource    │ ServicePipeClient
┌───────▼──────────────────┐    ┌──────▼──────────────────────┐
│ Infrastructure.Windows   │    │ \\.\pipe\LocalFirewall.…    │
│ IP Helper · process      │    └──────┬──────────────────────┘
│ identity · PipeServer    │           │
└──────────────────────────┘    ┌──────▼──────────────────────┐
                                │ LocalFirewall.Service       │
                                │ MonitoringWorker → cache    │
                                │ HistoryWriter → SQLite      │
                                │ PipeServerWorker            │
                                └──────┬──────────────────────┘
                                       │
                                ┌──────▼──────────────────────┐
                                │ Persistence (HistoryStore)  │
                                │ WAL · migracije · retencija │
                                └─────────────────────────────┘
```

## 2. Projekti i zavisnosti

| Projekat | Zavisi od | Odgovornost |
|---|---|---|
| Contracts | — | DTO, IPC, history ugovor, `IConnectionSnapshotSource` |
| Core | Contracts | domenska pravila, firewall port |
| Infrastructure.Windows | Contracts, Core | IP Helper, process identity, Named Pipe server |
| Persistence | Contracts | SQLite schema, upsert, query, retencija |
| Service | Contracts, Core, Infrastructure, Persistence | host, monitoring, history writer, pipe |
| UI | **samo Contracts** | Views/ViewModels/tema, pipe klijent |
| Desktop | UI, Infrastructure | composition root / jedini EXE |

`UI` nema nijednu Windows referencu; `System.IO.Pipes` je BCL. Windows API je u
Infrastructure/Service/Desktop.

## 3. Servis

- `MonitoringWorker`: IP Helper 1 s → `ConnectionSnapshotCache` (volatile + revizija).
- `HistoryWriter`: svake 2 s upisuje najnoviji snapshot u SQLite; retencija na startu i svakih 1 h.
- `PipeServerWorker`: pipe sa eksplicitnim DACL-om, SID proverom i limitima.
- `ServiceInfo`: vreme starta se postavlja eksplicitno (`MarkStarted`) da uptime ne zavisi od
  lazy inicijalizacije tipa.

## 4. IPC

- NDJSON, jedan `IpcEnvelope` po liniji.
- Zahtev max **256 KiB**; odgovor max **4 MiB** (snapshot sa hiljadama soketa prelazi limit zahteva).
- Buffered `IpcLineReader` (16 KiB čitanje, rastući izlaz) — nema bajt-po-bajt čitanja.
- Komande: `serviceHealth`, `capabilities`, `snapshot`, `history.query`.
- `rule.*`, `config.*`, `diagnostics.*`, `live.events` → `not_supported`.
- DACL: allow servisni nalog + jedan SID; deny `Network`/`Anonymous`/`Guests`; SID klijenta se čita iz
  procesnog tokena posle konekcije.

## 5. SQLite istorija (FND-005)

- Putanja: `LOCALFIREWALL_DATA_DIR` → inače `%LOCALAPPDATA%` (interaktivni proces) ili
  `%ProgramData%` (servis).
- WAL, `foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`.
- Tabele:
  - `schema_migrations(version, applied_utc, checksum)` — verzija 1,
  - `apps(id, app_key UNIQUE, display_name, executable_path, first_seen_utc, last_seen_utc)`,
  - `flows(id, app_id, process_id, protocol, local_endpoint, remote_endpoint, direction, state,
    quality, first_seen_utc, last_seen_utc, UNIQUE(app_id, protocol, local, remote, pid))`,
  - `traffic_buckets` — pripremljeno za FND-004, još se ne puni,
  - `settings`.
- Upsert: `first_seen` se ne menja; `last_seen`, `state`, `direction`, `quality` se ažuriraju.
- Query: UTC opseg, pretraga (ime/putanja/remote/PID), `LIMIT/OFFSET`, `COUNT(*)` za total.
- Retencija: 30 dana; briše stare `flows` i `apps` bez flows.
- Korumpirana baza: `integrity_check`/SQLite 26 → `ClearAllPools`, fajl u `.corrupt-<ts>`, rekreacija.
- Indeksi: `last_seen_utc`, `remote_endpoint`, `app_id`.

## 6. UI

- `ConnectionMonitor`: poll 1 s, diff po ključu, `Updated` i na grešku (offline banner).
- `HistoryViewModel`: opsezi 15m/1h/24h/7d, pretraga sa 400 ms debounce, auto-refresh 10 s,
  `history.query` preko pipe-a, CSV izvoz (UTF-8 BOM, escapovanje).
- U in-process režimu `History` prikazuje da je potreban servis; nema lažne istorije.
- Grafik propusnosti je i dalje demo serija (`DEMO SERIES`); bajtovi su FND-004.

## 7. Odloženo

- **FND-004 (ETW)**: kernel network sesija traži `SeSystemProfilePrivilege`; ova sesija je
  UAC-filtered (`logman` → Access denied). Implementacija i verifikacija idu na eleviranu sesiju/VM.
- FND-006 firewall write, FND-007 alerti, FND-009 installer/potpis.
- Servisni nalog i ACL instalacije; `traffic_buckets` punjenje.

Odluke: ADR 0001–0004.
