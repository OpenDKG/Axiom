# ADR 0003 — FND-003: Worker servis + lokalni Named Pipe sa SID proverom

- **Status:** prihvaćeno
- **Datum:** 2026-11-03
- **Milestone:** FND-003
- **Nadovezuje se na:** ADR 0001, ADR 0002

## Kontekst

FND-002 je čitao sokete u UI procesu. Handoff FND-003 traži razdvajanje: privilegovani deo treba da
živi u Windows servisu, a UI da ostane neprivilegovan i da komunicira preko **lokalnog** Named Pipe-a
sa eksplicitnim ACL-om. U ovoj fazi nema firewall write endpointa. DoD traži da UI radi bez admina,
da drugi neovlašćeni korisnik ne može da pozove servis i da servis preživi zatvaranje UI-ja.

Na razvojnoj mašini nema administratorskih prava ni VM-a, pa instalacija servisa nije izvršena.
Implementacija mora da bude ispravna i testirana onoliko koliko okruženje dozvoljava, bez lažne tvrdnje
da je servis instaliran.

## Odluke

### 1. Isti host radi kao Windows servis i kao konzolni proces

`Host.CreateApplicationBuilder` + `AddWindowsService` (servisno ime `LocalFirewall`). Kada se pokrene
van SCM-a, host koristi console lifetime; tako se razvoj i testiranje rade bez admina, a isti binarni
izlaz kasnije instalira installer.

**Posledica:** servisni kod je testiran kao proces; SCM životni ciklus (start/stop/restart) ostaje
VM/admin provera u FND-009.

### 2. Monitoring u servisu, keširan snapshot, tanki pipe

`MonitoringWorker` anketa IP Helper na 1 s i upisuje `ConnectionSnapshot` u `ConnectionSnapshotCache`.
Pipe zahtev `snapshot` vraća keširani snapshot, pa N klijenata ne množi OS pozive. Revizija se
inkrementira pri svakom uspešnom pollu.

**Posledica:** UI polling i servisni polling su razdvojeni; servis nastavlja da radi kada UI nestane.

### 3. Eksplicitni DACL + provera SID-a klijenta

- `PipeSecurity`: allow servisni nalog (FullControl) i jedan dozvoljeni SID (ReadWrite);
  deny `Network`, `Anonymous`, `Guests`.
- Posle konekcije server čita SID **klijentskog procesa** preko `GetNamedPipeClientProcessId` +
  procesnog tokena. Nepoklapanje → zatvaranje bez odgovora.
- Dozvoljeni SID: `LOCALFIREWALL_ALLOWED_SID`; u konzolnom režimu trenutni korisnik. Installer će ga
  upisati u FND-009.

**Posledica:** DACL sprečava neovlašćeni connect, SID provera sprečava pogrešnog klijenta čak i ako
DACL dozvoli više SID-ova. Nema oslanjanja na podrazumevani DACL.

### 4. NDJSON sa tvrdim limitima, bez generičkih komandi

- Jedan `IpcEnvelope` po liniji, UTF-8, max 256 KiB; prekoračenje se odbija pre JSON parsiranja.
- Verzija protokola se proverava; nepoznata komanda → `unknown_command`.
- Implementirane su samo `serviceHealth`, `capabilities`, `snapshot`.
- `rule.*`, `history.*`, `config.*`, `diagnostics.*`, `live.events` → `not_supported` (nema write puta).
- Rate limit 100 zahteva/s, 30 s idle, 4 instance.

**Posledica:** nema `exec`/shell površine; dodavanje komandi je eksplicitno i testirano.

### 5. UI klijent po zahtevu, bez trajnog stanja

`ServicePipeClient` se povezuje za svaki zahtev (2 s connect, 5 s request timeout). Time reconnect
posle pada servisa radi automatski, bez složenog state machine-a.

**Posledica:** nema streaming-a (`live.events`) u ovoj fazi; UI poll-uje `snapshot` na 1 s. To je
dovoljno za DoD i jednostavno za proveru; event stream dolazi sa FND-004.

### 6. Dva režima u Desktop-u: in-process (default) i `--service`

- Default ostaje in-process, da razvoj i standalone demo rade bez instaliranog servisa.
- `--service` koristi pipe i prikazuje `Service unavailable` kada servis nije dostupan.
- `run-service.ps1` podiže konzolni servis i UI sa `--service`.

**Posledica:** installer (FND-009) će verovatno prebaciti default na servis; do tada je izbor
eksplicitan i dokumentovan. Nijedan režim ne menja firewall.

## Posledice

Pozitivne:

- Jasna granica: UI bez Windows API-ja, servis bez UI zavisnosti.
- IPC je testiran bez admina: ACL, SID odbijanje, limiti, nepodržane komande.
- UI preživljava pad i restart servisa; nema lažnog „live“ stanja.

Negativne / rizici:

- Servis nije instaliran; SCM ponašanje, servisni nalog i ACL instalacije nisu provereni.
- Drugi Windows korisnik nije stvarno testiran (samo simulirano kroz dozvoljeni SID).
- Nema audit traga IPC komandi; biće potreban pre firewall komandi (FND-006).
- Keširani snapshot znači da UI može videti do 1 s star podatak; to je označeno vremenom polla.
- Nema streaming-a; `live.events` je odložen.

## Razmatrane alternative

| Alternativa | Zašto nije izabrana |
|---|---|
| UI direktno čita IP Helper (FND-002 stanje) | Nema razdvajanja privilegija; servis je cilj handoff-a |
| HTTP localhost API | Veći napadni otisak, port, CORS/auth problemi; handoff traži pipe |
| Trajna pipe konekcija sa event stream-om | Složeniji reconnect/checkpoint; FND-004 |
| `PipeOptions.CurrentUserOnly` | Servis kao SYSTEM ne bi mogao da usluži korisnika |
| DACL samo za „Authenticated Users“ | Preširoko; krši princip najmanjih privilegija |
| Instalacija servisa sada | Nema admin/VM; rizik od polovične provere |

## Sledeće odluke

- FND-004: ETW sesija (prava!), agregacija, event-loss, streaming `live.events`.
- FND-006: audit IPC komandi, firewall transakcija i read-back.
- FND-009: servisni nalog, installer, ACL `%ProgramData%`, potpis, uninstall.
