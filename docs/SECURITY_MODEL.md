# Bezbednosni model — LocalFirewall (FND-005)

## 1. Trenutna granica poverenja

| Proces | Prava | Šta radi |
|---|---|---|
| `LocalFirewall.Desktop.exe` | `asInvoker` | UI; čita IP Helper ili zove pipe |
| `LocalFirewall.Service.exe` | `asInvoker` (konzolni režim) | anketa IP Helper, SQLite upis, pipe server |

U produkciji servis bi radio kao servisni nalog (FND-009); UI ostaje neprivilegovan. Nema
COM/WFP/ETW/netsh poziva, nema firewall upisa i nema odlazne mrežne komunikacije.

ETW (FND-004) nije implementiran; kada dođe, zahteva `SeSystemProfilePrivilege` i biće u servisu.

## 2. Named Pipe zaštita

- `\\.\pipe\LocalFirewall.Service.v1`.
- Eksplicitni DACL: allow servisni nalog + jedan SID; deny `Network`/`Anonymous`/`Guests`.
- SID klijentskog procesa se čita iz tokena posle konekcije; nepoklapanje → zatvaranje.
- Limiti: zahtev 256 KiB, odgovor 4 MiB, 100 zahteva/s, 30 s idle, 4 instance.
- Samo imenovane komande; nema `exec`; firewall/history/config/diagnostics/`live.events` →
  `not_supported` (history.query je podržan).
- Greške se vraćaju kao kod + poruka, bez stack trace-a.

## 3. Podaci na disku (FND-005)

- Baza: `%LOCALAPPDATA%\LocalFirewall\localfirewall.db` (per-user/konzolni režim) ili
  `%ProgramData%\LocalFirewall\` (instalirani servis). `LOCALFIREWALL_DATA_DIR` menja putanju.
- Čuva se **samo metapodatak konekcije**: ime/putanja procesa, PID, protokol, lokalni/udaljeni
  endpoint, stanje, smer, kvalitet, prvi/poslednji put viđenja.
- Ne čuvaju se payload, TLS sadržaj, DNS upiti, tokeni ni akreditivi.
- Retencija: 30 dana; brisanje starih flows i aplikacija bez flows.
- SQLite WAL; `foreign_keys=ON`; `integrity_check` na startu.
- Korumpiran fajl se premešta u `.corrupt-<timestamp>` (ne briše) i baza se rekreira.
- CSV izvoz piše na putanju koju korisnik eksplicitno izabere; UTF-8 BOM; escapovanje.
- Installer (FND-009) mora postaviti eksplicitan ACL na `%ProgramData%\LocalFirewall\`; sada je to
  per-user LocalAppData u razvoju.

## 4. Model pretnji

| Pretnja | FND-005 | Kontrola |
|---|---|---|
| Drugi lokalni korisnik zove servis | DACL + SID provera | Testirano odbijanje stranog SID-a |
| Udaljeni pristup pipe-u | Deny `Network`/`Anonymous`/`Guests` | Lokalni pipe |
| Čitanje tuđe istorije | Baza u per-user LocalAppData; ProgramData ACL u FND-009 | Per-user putanja |
| Curenje sadržaja u bazu | Čuva se samo metapodatak | Nema payload-a/DNS-a |
| Preveliki odgovor / DoS | 4 MiB response cap, 256 KiB request, 100/s | Buffered reader + limiti |
| Korumpirana baza | `integrity_check` + backup `.corrupt-*` | Testirano |
| Neograničen rast baze | Retencija 30 dana, satna provera | Testirano |
| SQL injection kroz pretragu | Parametrizovani upiti + `LIKE ... ESCAPE` | Testirano |
| Lažni PID/putanja | `partial`, `unknown path` | FND-010 |
| Firewall izmena | Nema write komandi | FND-006 |
| Servis padne | UI `Service unavailable`, reconnect | E2E testirano |

## 5. Ograničenja i neizvršene provere

- Servis nije instaliran (nema admin/VM); testiran je konzolni host i pipe.
- Stvarni drugi Windows nalog nije testiran; ACL/SID odbijanje jesu.
- Nema instalacionog ACL-a ni potpisa (FND-009).
- Nema audit traga IPC komandi; biće potreban pre firewall komandi (FND-006).
- ETW/bajtovi nisu implementirani; FND-004 zahteva elevaciju.
- Nema šifrovanja baze; podaci su per-user i metapodaci, ali to je odluka za FND-009.

## 6. Prijava ranjivosti

Do javnog kanala, prijava ide direktno vlasniku projekta. Ne objavljivati stvarne SID-ove, putanje ili
sadržaj baze u reprodukciji.
