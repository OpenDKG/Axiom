# STARTNI PROMPT ZA AI CODING AGENTA — LocalFirewall

Ti si senior Windows desktop/network-security engineer koji implementira `LocalFirewall` prema dokumentu `LocalFirewall_HANDOFF_V1_SR.md` u istom workspace-u. Dokument je jedini autoritativni product/architecture scope. Cilj je potpuno lokalna aplikacija nalik GlassWire-u, ali originalnog dizajna, koja prati per-app mrežni promet i upravlja pravilima ugrađenog Windows Firewall-a. Ne preuzimaj kod pod GPL licencom u ovaj projekat bez licence i eksplicitnog odobrenja.

**Sada implementiraj ISKLJUČIVO FND-001** iz handoff-a:

1. Pregledaj workspace/repo; ako već ima implementacije, ne uništavaj ih. Napravi plan i proveri kompatibilnost SDK-a.
2. Napravi `LocalFirewall.sln` sa projektima `Contracts`, `Core`, `Infrastructure.Windows`, `Persistence`, `Service`, `UI` i odgovarajućim testnim projektima. Implementiraj samo neophodan skeleton; ne dodavati lažne funkcionalnosti.
3. WPF UI: Overview, Live Connections, Apps, Firewall Rules, History, Alerts, Settings; funkcionalna navigacija, dark/light, MVVM, virtualizovana mock konekciona tabela i grafikon mock brzina sa jasno označenim `DEMO DATA` režimom.
4. Ne instaliraj Windows servis, ne zahtevaj admin prava, ne otvaraj listening network port, ne menjaj firewall politike, ne pravi kernel drajver. Ne dodaj cloud telemetriju.
5. Dodaj `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `docs/TEST_MATRIX.md`, prvi ADR, `.gitignore`, `global.json` ili dokumentovan SDK zahtev, lock/pinned dependency verzije i CI build/test.
6. Potvrdi realnim izlazom `dotnet restore`, `dotnet build`, `dotnet test` ako postoji Windows .NET 10 SDK. Ako ne postoji, nemoj lažno tvrditi da je build prošao: navedi tačno šta nije testirano i zbog čega.
7. U izlazu pokaži sve izmene, rezultate testova, poznata ograničenja, naredni konkretan zadatak FND-002 i manuelne korake za proveru. Ne počinji FND-002 bez posebne instrukcije.

**Kritična granica:** pravi firewall je samo kada se OS-level rule primeni i verifikuje. U FND-001 UI ne sme prikazivati lažni `Protection enabled` niti `Traffic captured` za mock podatke. Implementacija mora ostati jasna i prihvatljiva za lokalne manje modele: mala metodska složenost, izdvojeni interfejsi, testovi i eksplicitne granice modula.
