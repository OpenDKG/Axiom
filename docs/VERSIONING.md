# Versioning

Axiom versions are milestones, not patches. **Every released fix or feature set bumps the minor
version**: `0.24.0`, `0.25.0`, `0.26.0`, and so on, until `1.0.0`.

Patch releases (`0.24.1`, `0.24.2`, …) are **not used**. A fix ships with the next minor so the path
to `1.0.0` stays short, each release is a visible milestone, and the release history is not padded
with tiny increments.

## Release checklist

For every release `0.X.0`:

1. Version in `Directory.Build.props` and `README.md`.
2. `docs/RELEASES/0.X.0.md` with what changed and how it was verified.
3. `docs/CHANGELOG.md` gets a `## What's in 0.X.0` section.
4. `scripts/build-release.ps1 -Version 0.X.0` and `scripts/publish-setup.ps1`.
5. Merge the release PR into `main`, tag `v0.X.0` on the merge commit, push the tag.
6. `gh release create v0.X.0 --notes-file docs/RELEASES/0.X.0.md`.
7. Log the result in `F:\Pen Testing\Logs\autonomous-progress.md` and mirror to `H:`.

## Boundaries

- A release tag points at the merge commit on `main`, never at a feature branch.
- The installed setup and the tag must carry the same code; rebuild the setup from the release
  commit before publishing.
- `0.23.2` is a historical hotfix (wildcard protected-path delete) merged before this rule; it is
  included in `0.24.0` and every later release. No new patch versions are created.
