# Versioning

Axiom versions are milestones, not patches. **Every released fix or feature set bumps the minor
version** on the 1.x line (`1.0.0` since 17 November 2026): `1.1.0`, `1.2.0`, and so on.

Patch releases (`0.24.1`, `0.24.2`, …) are **not used**. A fix ships with the next minor so the path
to `1.0.0` stays short, each release is a visible milestone, and the release history is not padded
with tiny increments.

## Release checklist

For every release `1.X.0`:

1. Version in `Directory.Build.props` and `README.md`.
2. `docs/RELEASES/1.X.0.md` with what changed and how it was verified.
3. `docs/CHANGELOG.md` gets a `## What's in 1.X.0` section.
4. `scripts/build-release.ps1 -Version 1.X.0` and `scripts/publish-setup.ps1`.
5. Merge the release PR into `main`, tag `v1.X.0` on the merge commit, push the tag.
6. `gh release create v1.X.0 --notes-file docs/RELEASES/1.X.0.md`.
7. Log the result in `F:\Pen Testing\Logs\autonomous-progress.md` and mirror to `H:`.

## Boundaries

- **One focused commit per fix:** make a separate, descriptive commit for each fix or isolated change (for example `fix(privacy): ...`, `fix(dns): ...`) instead of combining unrelated fixes into one generic commit, so every change is easy to audit on GitHub and by agents.
- A release tag points at the merge commit on `main`, never at a feature branch.
- The installed setup and the tag must carry the same code; rebuild the setup from the release
  commit before publishing.
- `0.23.2` and `0.23.3` are historical hotfixes merged before this rule; both are included in
  `0.24.0` and every later release. No new patch versions are created.
