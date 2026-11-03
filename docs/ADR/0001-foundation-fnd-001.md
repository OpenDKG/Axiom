# ADR 0001 — FND-001: .NET 10 WPF shell sa slojevitim projektima i demo podacima

- **Status:** prihvaćeno
- **Datum:** 2026-11-03
- **Milestone:** FND-001
- **Kontekst dokument:** `LocalFirewall_HANDOFF_V1_SR.md`

## Kontekst

Prvi milestone zahteva solution sa čistim granicama, WPF shell sa sedam stranica, mock konekcije,
grafik sa dve serije, testove i build, **bez** instalacije servisa, bez administratorskih prava, bez
menjanja Windows Firewall-a i bez kernel drajvera. Cilj je da kasniji milestone-i (IP Helper, ETW,
SQLite, COM firewall) mogu da se dodaju bez preuređivanja UI-ja i bez mešanja demo podataka sa
stvarnom telemetrijom.

Ograničenja okruženja: razvojna mašina je Windows 10 IoT Enterprise LTSC 2021 x64; podržani target
je Windows 11 x64. Na mašini je postojao samo .NET runtime, pa je SDK 10.0.403 instaliran lokalno za
korisnika (nije deo repozitorijuma). Aplikacija mora da se isporuči i kao **standalone** build, bez
zahteva za .NET runtime-om na ciljnoj mašini.

## Odluke

### 1. WPF na .NET 10, ne WinUI 3 / Electron / Avalonia

WPF daje zrelu Windows integraciju, MVVM bez dodatnog runtime-a i najmanji rizik za buduće COM/ETW
integracije. Electron bi dodao Chromium (nepotreban napadni i potrošni otisak za lokalni security
alat). WinUI 3 bi dodao packaging/Windows App SDK rizik i veći broj zavisnosti. Avalonia nije izabrana
jer cilj nije cross-platform, a Windows-only interop je primaran.

### 2. Šest proizvodnih projekata sa fizičkim granicama zavisnosti

`Contracts`, `Core`, `Infrastructure.Windows`, `Persistence`, `Service`, `UI`. UI referencira **samo**
`Contracts`; to je kompajlerska, a ne konvencijska granica. `Core` je bez WPF/COM/P-Invoke i testira
se na bilo kojoj platformi.

**Posledica:** demo generatori i ViewModel-i ne mogu slučajno da koriste SQLite ili Windows API; svaki
budući pristup OS-u ide kroz eksplicitni port (`IFirewallPolicyAdapter`) i Infrastructure adapter.

### 3. Demo podaci su izolovani u UI sloju i eksplicitno označeni

`DemoDataFactory` i `DemoTrafficEngine` žive u `LocalFirewall.UI/Services`. Deterministični seed
(`20261101`) daje ponovljive snimke. Udaljene adrese su iz IPv4 dokumentacionih opsega. UI nosi
`DEMO DATA` oznake, a status traka prikazuje stvarno stanje (`monitoring not started`, `firewall not
implemented`, `database not connected`), nikada „Protection enabled“.

**Posledica:** nema prelaznog perioda u kojem demo vrednosti izgledaju kao merenje; prelazak na
FND-002 menja izvor podataka, a ne značenje prikaza.

### 4. Bez chart biblioteke u FND-001

Grafikon je `TrafficChart` (`FrameworkElement`, `DrawingContext`) sa dve serije i mrežom. ScottPlot je
kandidat iz handoff-a, ali za 60 demo tačaka predstavlja nepotrebnu zavisnost i nepoznat rizik verzije.
Odluka se revidira u FND-004 kada postoje stvarni obimi i zahtevi za interakciju.

### 5. Centralno pinovanje paketa + lock fajlovi + warnings-as-errors

`Directory.Packages.props` pinuje verzije; `RestorePackagesWithLockFile` daje `packages.lock.json` po
projektu; CI koristi `--locked-mode`. `TreatWarningsAsErrors` je uključen, uz dve ciljane iznimke:
`CA1822` za MVVM binding-only properties (UI) i `CA1707` za opisna imena testova.

**Posledica:** promena zavisnosti je vidljiva u diff-u, a nullability/analyzer regresije obaraju build.

### 6. `RuntimeIdentifiers=win-x64` i standalone publish profil

UI projekat deklariše RID da lock fajl i `dotnet restore --locked-mode` pokriju i self-contained
publish. `win-x64-selfcontained.pubxml` proizvodi jedan `LocalFirewall.UI.exe` (~59 MB) bez .NET
runtime-a. Trimming je isključen jer WPF nije podržan za trimming.

**Posledica:** isporuka je jedan fajl, ali je izvršni fajl veći i pri prvom pokretanju raspakuje
native biblioteke u korisnički temp direktorijum.

### 7. Ne diramo Windows Firewall ni u čitanju

`NotAvailableFirewallPolicyAdapter` vraća `Unavailable` i baca `NotSupportedException` za sve
operacije. Nema COM reference, nema `netsh`, nema WFP-a. `RuleSpecValidator` i `OwnedRuleName` su
pripremljeni i testirani, ali nisu povezani na OS.

**Posledica:** FND-001 ne može da promeni sistem čak i ako se pokrene kao administrator; enforcement
rizik počinje tek u FND-006, uz transakciju i read-back.

### 8. Persistence baseline postoji, ali nije povezan

`LocalDatabase` uvodi WAL, foreign keys, `schema_migrations` i integrity check sa testovima. UI ga ne
koristi, a servis ga ne poziva pri startu. Time FND-005 dobija proveren temelj, a FND-001 ne tvrdi da
ima istoriju.

## Posledice

Pozitivne:

- Build i testovi su brzi i deterministični; UI se može proveriti bez mreže i bez admina.
- Granice modula su mehanički sprovedene, pa je bezbedno dodavati kolektore i adaptere.
- Standalone isporuka je već deo build pipeline-a, ne naknadna dorada.

Negativne / rizici:

- Dvostruki prikaz istine (demo vs. real) mora se pažljivo ukloniti u FND-002; demo režim ne sme da
  ostane dostupan kao „production“.
- WPF single-file nije trimovan; veličina i startup su kompromis.
- Windows 10 LTSC 2021 je razvojna mašina, ali nije dokaz ponašanja na Windows 11; to zahteva VM test.
- `RuleSpecValidator` još ne pokriva CIDR/port opseg; to je svesno odloženo za FND-008.

## Razmatrane alternative

| Alternativa | Zašto nije izabrana |
|---|---|
| Electron + React | Chromium runtime, veći otisak, dodatni IPC sloj bez potrebe |
| WinUI 3 + Windows App SDK | Packaging i dependency rizik; manje zreo ekosistem za COM interop |
| Avalonia | Cross-platform nije cilj; Windows interop je primaran |
| ScottPlot odmah | Zavisnost bez koristi za 60 demo tačaka |
| Baza pre UI-ja | FND-001 DoD traži UI shell; baza bez događaja nema šta da čuva |
| Servis odmah | FND-003 zahteva IPC bezbednosni dizajn; prerano bi povećao rizik |

## Sledeće odluke

- FND-002: izvor identiteta procesa i semantika `partial` podataka.
- FND-003: IPC ACL, servisni nalog, verzionisanje i reconnect.
- FND-004: ETW metrika (payload vs. wire), event-loss budžet.
- FND-006: COM lifecycle, transakcioni tok i recovery.
