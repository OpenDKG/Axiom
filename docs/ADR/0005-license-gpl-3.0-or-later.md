# ADR 0005 — Licenca GPL-3.0-or-later i model open-source distribucije

- **Status:** prihvaćeno
- **Datum:** 2026-11-03
- **Milestone:** pre FND-001 UI usklađivanja (licencna osnova)
- **Nadovezuje se na:** ADR 0001–0004, Handoff V2 §Q

## Kontekst

Handoff V2 traži **pravi open-source projekat, potpuno besplatan**, bez plaćenih funkcija, reklama,
praćenja i obaveznog naloga. Predlog u V2 je GPL-3.0-or-later za desktop i servis, uz odvojene
MIT/Apache-2.0 pakete za opcione integracije. Repo `VigilMesh` je privatan i korisnik je odobrio
licencu.

Do sada projekat nije imao izabranu licencu; README je govorio „licenca nije izabrana“. To je
blokiralo javnu distribuciju i pravilo nesigurnost za doprinose.

## Odluke

### 1. GPL-3.0-or-later za desktop, servis i core biblioteke

Svi proizvodni projekti (`Contracts`, `Core`, `Infrastructure.Windows`, `Persistence`, `Service`,
`UI`, `Desktop`) i testovi su pod GPL-3.0-or-later. Time derivati moraju ostati open source, a
korisnici zadržavaju slobodu korišćenja, izmene i redistribucije. Komercijalna distribucija i
naplata podrške ostaju dozvoljeni.

### 2. SPDX identifikator u svakom izvornom fajlu

`SPDX-License-Identifier: GPL-3.0-or-later` u `.cs` i `.xaml` fajlovima; `LICENSE`, `NOTICE` i
`THIRD_PARTY_NOTICES.md` u korenu. Time je licenca vidljiva i u pojedinačnim fajlovima, ne samo u
README-u.

### 3. Odvojeni MIT/Apache-2.0 paketi za integracije

`integrations/agent-security-memory` i slični moduli mogu biti permissive, ali ne smeju sadržati
GPL-only kod i moraju imati sopstvene notice fajlove. Ovo omogućava DKG registry ekosistem bez
mešanja licencnih režima.

### 4. DCO umesto CLA

Doprinosi se prihvataju uz `Signed-off-by` (Developer Certificate of Origin), bez prenosa autorskih
prava. Time se izbegava CLA koji odbija deo open-source zajednice.

### 5. Automatska evidencija third-party licenci

`THIRD_PARTY_NOTICES.md` se generiše iz `packages.lock.json` i nuspec metapodataka. Sve zavisnosti su
MIT ili Apache-2.0; nema GPL/AGPL trećeg koda. .NET runtime u self-contained buildu je MIT.

## Posledice

Pozitivne:

- Jasna, proverljiva licenca i mogućnost javnog release-a.
- GPL sprečava zatvorene derivate, ali dozvoljava komercijalnu distribuciju i podršku.
- Permissive integracije ostaju dostupne drugim ekosistemima.
- DCO i SPDX smanjuju pravnu nesigurnost doprinosa.

Negativne / rizici:

- Distribucija binarnog fajla zahteva dostupan odgovarajući izvorni kod.
- GPL kod se ne može kopirati u MIT/Apache module; potrebna je disciplina pri refaktorisanju.
- Neke kompanije izbegavaju GPL; to je prihvaćena posledica izbora.
- Licence eksternih feedova (VT, Blackbox, DKG, GeoIP) i dalje zahtevaju odvojenu proveru.
- Ovo nije pravni savet; pravna provera pre javnog release-a je obavezna.

## Razmatrane alternative

| Alternativa | Zašto nije izabrana |
|---|---|
| MIT/Apache-2.0 | Dozvoljava zatvorene derivate; V2 traži copyleft i pravi open source |
| AGPL-3.0 | Namenjena hostovanom servisu; desktop alat ne zahteva mrežni copyleft |
| Dual license (GPL + komercijalna) | Nema komercijalnog izdavaoca ni potrebe u ovoj fazi |
| Bez licence (all rights reserved) | Nije open source; blokira doprinose i distribuciju |
| GPL-2.0 | Apache-2.0 zavisnosti nisu kompatibilne sa GPLv2 |

## Sledeće odluke

- Pravna provera pre prvog javnog release-a.
- Pravila za signed release i izvorni tarball (FND-009).
- Licencna politika za GeoIP bazu i threat feedove (FND-010/012).
