# ADR 0004 — FND-005: lokalna SQLite istorija i odlaganje FND-004

- **Status:** prihvaćeno
- **Datum:** 2026-11-03
- **Milestone:** FND-005 (FND-004 odložen)
- **Nadovezuje se na:** ADR 0001–0003

## Kontekst

Sledeći milestone po handoff-u je FND-004 (ETW merenje bajtova). ETW kernel network sesija traži
`SeSystemProfilePrivilege`. Na razvojnoj mašini proces je UAC-filtered: `BUILTIN\Administrators` je
„deny only“, `whoami /priv` ne prikazuje `SeSystemProfilePrivilege`, a
`logman create trace -p Microsoft-Windows-Kernel-Network` vraća **Access is denied**. Nema VM-a ni
mogućnosti da se podigne elevirana sesija iz agenta.

Implementirati ETW bez mogućnosti da se provere event ID-jevi, polja i semantika bajtova bilo bi
upravo ono što handoff zabranjuje („ne izmišljati P/Invoke/ETW polja“). Zato je FND-004 odložen, a
radi se FND-005 (istorija), koji je potpuno proverljiv bez elevacije i ne zavisi od bajtova.

## Odluke

### 1. SQLite schema v1 sa `flows` i `apps`

Tabele: `schema_migrations`, `apps`, `flows`, `traffic_buckets`, `settings`. Flow je jedinstven po
`(app_id, protocol, local_endpoint, remote_endpoint, process_id)`; `first_seen_utc` se ne menja,
`last_seen_utc`, `state`, `direction`, `quality` se ažuriraju.

**Posledica:** ponovljeni poll ne duplira redove; istorija raste samo sa novim flowovima.

### 2. Batch upis na 2 s, ne po pollu

`HistoryWriter` uzima najnoviji snapshot iz keša i upisuje ga u jednoj transakciji svake 2 s.
Retencija se primenjuje na startu i svakih sat vremena.

**Posledica:** ~30 upisa u minuti umesto 60+, WAL ostaje mali; UI i dalje dobija 1 s svežinu preko
pipe-a, istorija je do 2 s „iza“.

### 3. UTC u bazi, lokalno u UI

Sve vremenske kolone su ISO-8601 UTC stringovi (`O`), pa su leksikografsko sortiranje i opsezi
tačni. UI konvertuje u lokalno vreme samo za prikaz.

**Posledica:** DST i promene zone ne kvare upite.

### 4. Istorija samo kroz servis

UI ne referencira `Persistence`; `history.query` ide preko pipe-a. U in-process režimu `History`
eksplicitno kaže da je potreban servis.

**Posledica:** nema dve istine o bazi i nema SQLite fajla koji UI može da zaključa.

### 5. Retencija 30 dana i korumpirana baza

Podrazumevano 30 dana; brišu se flows stariji od granice i apps bez flows. Ako `integrity_check`
padne ili SQLite vrati „not a database“, fajl se premešta u `.corrupt-<timestamp>` i baza se
rekreira; ništa se ne briše tiho.

**Posledica:** ograničen rast baze i predvidiv oporavak; korisnik može da sačuva korumpirani fajl.

### 6. Odvojeni limiti za zahtev i odgovor

NDJSON zahtev ostaje 256 KiB; odgovor je do 4 MiB. Snapshot sa 3000 soketa ima ~1.5 MB i legalno
prelazi limit zahteva. Čitač je buffered (16 KiB), ne bajt-po-bajt.

**Posledica:** veliki snapshoti rade; test `Snapshot_larger_than_the_request_limit_is_returned` čuva
regresiju. Rizik: 4 MiB je i dalje ograničen, pa ekstremne mašine mogu zahtevati paginaciju
(budući rad).

### 7. PID 0 i nepoznate putanje se čuvaju kao takvi

Redovi sa PID 0 (`TIME_WAIT`/kernel) i nečitljivim putanjama upisuju se sa `quality=Partial` i
`app_key` iz PID-a. Ne izmišlja se aplikacija.

**Posledica:** istorija je vernа, ali može imati mnogo `System · unowned (PID 0)` redova; to je
vidljivo u UI-ju i može se filtrirati pretragom.

### 8. CSV izvoz iz UI-ja

UI traži do 5000 redova istim filterom i piše CSV na korisnički izabranu putanju (UTF-8 BOM,
escapovanje). Nema novog IPC endpointa za fajlove.

**Posledica:** servis ne dobija pravo pisanja van svoje baze; izvoz je eksplicitna korisnička akcija.

## Posledice

Pozitivne:

- Istorija je stvarna, pretraživa i preživljava restart servisa (provereno: 4229 flows posle restarta).
- Sve DoD stavke FND-005 su proverljive bez admina (osim CSV dijaloga).
- Baza je per-user u razvoju; installer će dodati ProgramData ACL.

Negativne / rizici:

- FND-004 ostaje neurađen; grafik je demo i nema bajtova.
- Baza raste sa brojem jedinstvenih flowova; 30 dana retencije je fiksno u kodu.
- Nema šifrovanja baze; čuvaju se metapodaci (putanje, endpointi), ne sadržaj.
- CSV izvoz je ograničen na 5000 redova po akciji.
- `traffic_buckets` je prazna tabela do FND-004.

## Razmatrane alternative

| Alternativa | Zašto nije izabrana |
|---|---|
| ETW sada, bez provere | Zabranjeno handoff-om; neproverena semantika bajtova |
| In-memory istorija | Ne preživljava restart; DoD FND-005 pada |
| CSV kao primarni store | Nema upita, indeksa, retencije |
| Upis svakog polla | Nepotrebno opterećenje WAL-a |
| Baza u UI procesu | Krši granicu UI → Contracts |
| Paginacija snapshota odmah | Veći protokol; 4 MiB pokriva realne slučajeve |

## Sledeće odluke

- FND-004: ETW sesija, event-loss, `traffic_buckets`, pravi grafik (elevirana sesija/VM).
- FND-009: installer, ProgramData ACL, servisni nalog, potpis.
- FND-006: firewall komande + audit trag u bazi.
