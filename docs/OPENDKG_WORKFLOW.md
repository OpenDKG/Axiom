# Axiom development in OpenDKG

[OpenDKG/Axiom](https://github.com/OpenDKG/Axiom) is the public repository for source, issues,
team pull requests and [official downloads](https://github.com/OpenDKG/Axiom/releases).
Keep implementation discussion and review on the originating pull request. Merge reviewed
public changes into OpenDKG's `main`.

Maintainers with access to the separate private upstream can import public changes through its
`opendkg/sync-main` review branch. The importer supports scheduled and manual runs. An upstream
maintainer with workflow write access handles workflow changes if needed. Merge reviewed imports
with a merge commit to preserve commit identity. GitHub keeps issues, pull requests and reviews
in their original repository.

When a change starts in the private upstream, bring it to the public repository through a
reviewed PR. Public releases and update checks use OpenDKG. See [Versioning](VERSIONING.md)
for the release process.
