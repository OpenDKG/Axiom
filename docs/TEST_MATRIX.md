# Test matrica — LocalFirewall (FND-005)

Datum: 2026-11-03. Mašina: Windows 10 IoT Enterprise LTSC 2021, 10.0.19044, x64.
SDK: 10.0.403. Konfiguracija: `Release`.

## 1. Automatske provere (izvršeno)

| Komanda | Rezultat |
|---|---|
| `dotnet restore LocalFirewall.sln --locked-mode` | uspešno (i posle standalone publish-a) |
| `dotnet build LocalFirewall.sln -c Release --no-restore` | **0 warning(s), 0 error(s)** |
| `dotnet test LocalFirewall.sln -c Release --no-build` | **87/87 prošlo** |
| `dotnet publish src\LocalFirewall.Desktop -p:PublishProfile=win-x64-selfcontained` | uspešno, 58.8 MB jedan EXE |

| Test projekat | Broj | FND-005 dodatak |
|---|---|---|
| Core | 38 | — |
| Contracts | 10 | — |
| Persistence | 11 | +7: schema, round-trip UTC, idempotentni upsert, pretraga, opseg/paging, retencija, korumpirana baza |
| Infrastructure.Windows | 28 | +1: snapshot veći od limita zahteva (1.5 MB odgovor) |

### Istorija — pokriveno testovima

- `Initialize_creates_schema_version_one` — schema verzija 1.
- `Upsert_and_query_round_trip_utc_timestamps` — UTC round-trip.
- `Repeated_upsert_updates_last_seen_without_duplicating` — upsert semantika.
- `Search_matches_app_path_remote_and_pid` — parametrizovana pretraga.
- `Time_window_and_paging_are_applied` — opseg, limit/offset, total.
- `Retention_removes_old_flows_and_orphan_apps` — 30 dana.
- `Corrupt_database_is_moved_aside_and_recreated` — `.corrupt-*` + rekreacija.

### IPC — dodato u FND-003/005

- DACL allow/deny, SID odbijanje, `unknown_command`, `not_supported`, oversized zahtev.
- **Snapshot veći od 256 KiB** (3000 redova) se isporučuje preko 4 MiB response limita.
- Buffered line reader (16 KiB) — bez bajt-po-bajt čitanja.

## 2. End-to-end provere (izvršeno)

Servis u konzolnom režimu + objavljeni standalone UI sa `--service`.

| # | Provera | Rezultat | Dokaz |
|---|---|---|---|
| E01 | Servis pravi bazu i piše flows | ✅ 1.1 MB posle ~1 min | `svc-h*.log` |
| E02 | History prikazuje stvarne redove | ✅ 1000 od 3607 flows | `fnd005-history.png` |
| E03 | Pretraga/opsezi rade | ✅ (testovi + ručno) | — |
| E04 | Servis stop → UI `Service unavailable` | ✅ | `fnd003-service-offline.png` |
| E05 | Servis restart → istorija preživljava | ✅ 4229 flows posle restarta | `fnd005-history-after-restart.png` |
| E06 | Reconnect bez restarta UI-ja | ✅ | `fnd003-service-recovered.png` |
| E07 | Standalone EXE (bez SDK-a) | ✅ | svi snimci |
| E08 | CSV izvoz | ⚠️ kod + escapovanje; dijalog nije automatizovan | — |

## 3. DoD iz handoff-a (FND-005)

| Zahtev | Status |
|---|---|
| Migracije | ✅ schema v1 + checksum |
| Batch upis | ✅ svake 2 s, ne po pollu |
| Agregacije | ⚠️ query po flowovima; `traffic_buckets` pripremljen (FND-004) |
| Retention | ✅ 30 dana, satna provera |
| Query/paging | ✅ UTC opseg, pretraga, limit/offset, total |
| CSV | ✅ UTF-8 BOM + escapovanje (dijalog ručno) |
| Reboot/restart persistence | ✅ restart servisa; reboot nije testiran |
| Timezone | ✅ UTC u bazi, lokalno u UI |
| 64-bit brojači | ⚠️ kolone postoje; bajtovi se ne mere do FND-004 |
| Cleanup | ✅ retencija + orphan apps |
| Corrupt DB recovery | ✅ testirano |

## 4. FND-004 (ETW) — blokirano

`logman create trace -p Microsoft-Windows-Kernel-Network` vraća **Access is denied**; proces je
UAC-filtered (`BUILTIN\Administrators` je „deny only“), nema `SeSystemProfilePrivilege`. Zato:

- ETW kolektor nije implementiran; nema tvrdnji o bajtovima.
- Grafik je i dalje `DEMO SERIES`.
- Verifikacija ide na eleviranu sesiju ili VM.

## 5. Matrica scenarija (§13)

| ID | Scenario | Status |
|---|---|---|
| T01 | TCP IPv4 | ✅ |
| T02 | TCP IPv6 | ⚠️ čita se; nema kontrolisanog IPv6 testa |
| T03 | UDP/QUIC | ⚠️ endpointi; remote/smer unknown |
| T04 | 1000 kratkih konekcija | ❌ |
| T05 | Loopback LLM | ✅ |
| T06 | GPU + protok | ❌ |
| T07 | VPN/NIC | ❌ |
| T08/T09 | Firewall block | ❌ FND-006 |
| T10 | EXE zamena | ⚠️ putanja, bez hasha |
| T11 | GPO konflikt | ❌ FND-006 |
| T12 | Servis ubijen / UI zatvoren | ✅ |
| T13 | Restart/reboot | ✅ restart servisa; reboot ❌ |
| T14 | Uninstall | ❌ FND-009 |
| T15 | Neprivilegovani IPC | ✅ ACL/SID (stvarni drugi nalog ❌) |
| T16 | Veliki/malformisan IPC | ✅ limiti + 1.5 MB snapshot test |
| T17 | 5157 audit | ❌ FND-007 |
| T18 | DoH | ❌ FND-010 |
| T19 | Windows update/DNS | ❌ FND-006 |
| T20 | Sleep/resume | ❌ |

## 6. Nije izvršeno (eksplicitno)

- ETW/bajtovi (FND-004) — nema privilegija.
- Instalacija Windows servisa, servisni nalog, ACL ProgramData (FND-009).
- Stvarni drugi Windows korisnik.
- Windows 11, 24 h soak, stress, reboot.
- CSV dijalog kroz UI automatizaciju.
- Installer/potpis.

## 7. Reprodukcija

```powershell
dotnet restore LocalFirewall.sln --locked-mode
dotnet build LocalFirewall.sln -c Release --no-restore
dotnet test LocalFirewall.sln -c Release --no-build
.\scripts\run-service.ps1
```
