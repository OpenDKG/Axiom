# Contributing

Thanks for helping with Axiom. The project is pre-1.0 and moves one milestone
at a time; small, verifiable changes are preferred over broad rewrites.

## License of contributions

By contributing you agree that your contribution is licensed under **GPL-3.0-or-later**, the same
license as the project. Use the Developer Certificate of Origin (DCO):

```text
git commit -s -m "Short description"
```

The `Signed-off-by` line certifies that you have the right to submit the change under this license.
Do not copy GPL-incompatible or unlicensed code into the repository.

Public pull requests also use the repository's Contributor License Agreement (CLA) check.
Follow the CLA Assistant link shown on the pull request using your own GitHub account.
If you previously accepted the agreement and the status is pending, use the bot's recheck link.
Keep the DCO sign-off on each commit.

## Before you start

- Read `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md` and the current milestone in
  `docs/TEST_MATRIX.md`.
- Keep the dependency rules: `Axiom.UI` references **only** `Contracts`; Windows API code
  belongs in `Infrastructure.Windows`; only `Service` may eventually write firewall rules.
- Do not add telemetry, accounts, external lookups or network calls to the Standard path.
- Do not change Windows Firewall, BFE, Defender or audit policy outside an isolated VM with explicit
  approval.

## Build and test

```powershell
dotnet restore Axiom.sln --locked-mode
dotnet build Axiom.sln -c Release --no-restore
dotnet test Axiom.sln -c Release --no-build
```

The repository builds with warnings as errors, nullable enabled and pinned package versions. If you
change a dependency, update `Directory.Packages.props`, regenerate `packages.lock.json` with
`dotnet restore --force-evaluate`, and update `THIRD_PARTY_NOTICES.md`.

## Code style

- C# with nullable enabled; no `catch { }` that hides failures.
- Small methods, explicit interfaces, no hidden global state.
- Tests for pure logic; Windows integration tests must be read-only unless the ticket says otherwise.
- UI text must state what is real and what is demo. Never show `Protected`, `Blocked` or `Scanned`
  unless the OS/adapter result is verified.
- Keep changes focused. One logical change per pull request.

## Reporting

For bugs and feature work, open an issue with: version/commit, Windows version, steps, expected vs.
actual, and relevant logs with secrets removed. Security issues go through `SECURITY.md`, not public
issues.

## Pull requests are mandatory

Every change, including documentation, scripts, version bumps and release preparation, must go
through a pull request. Never commit directly to `main`.

1. Create a short branch from the current `main`.
2. Make small, signed commits (`git commit -s`).
3. Open a PR, link it in the working session, and state the exact build/test results.
4. Wait for the relevant checks and review; merge through the PR.
5. Create tags and releases only from a merged `main` commit.

Direct pushes to `main` are not accepted, even for one-line fixes.

## Review and merge

- Maintainers review for correctness, security and scope.
- Firewall, IPC, authentication and storage changes need an independent review.
- Do not merge your own security-sensitive change without review.
