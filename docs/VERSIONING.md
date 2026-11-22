# Versioning

Axiom uses `MAJOR.MINOR.PATCH`. Minor versions mark development milestones and patch versions
ship focused fixes within a minor series. The public [v1.4.x releases](https://github.com/OpenDKG/Axiom/releases)
include both minor and patch updates.

## Release checklist

For a release `X.Y.Z`:

1. Set the version in `Directory.Build.props` and update the relevant release documentation.
2. Add or update `docs/RELEASES/X.Y.Z.md` with changes and validation results.
3. Update `docs/CHANGELOG.md` for user-facing changes.
4. Merge the release changes into `main` and build the distribution packages from the release commit.
5. Tag that commit as `vX.Y.Z` and publish the packages, checksums and notes on
   [OpenDKG/Axiom Releases](https://github.com/OpenDKG/Axiom/releases).
6. Record validation results in the release notes or link to reproducible CI evidence.

Use one focused commit per fix. The release tag, package source commit and release version
must agree. Historical releases retain their original tags and metadata.
