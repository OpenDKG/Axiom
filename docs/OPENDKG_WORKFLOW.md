# Axiom development in OpenDKG

Open PRs for team work in [OpenDKG/Axiom](https://github.com/OpenDKG/Axiom).
Keep implementation discussion and review on the originating PR. Merge team
changes into OpenDKG's `main` to queue them for upstream review.

[a-51-50/Axiom](https://github.com/a-51-50/Axiom) is the canonical repository
for builds and releases. The importer checks OpenDKG `main` twice per hour
and updates the canonical `opendkg/sync-main` review branch. The upstream
maintainer [opens an import PR](https://github.com/a-51-50/Axiom/compare/main...opendkg/sync-main?expand=1),
reviews it, and uses **Create a merge commit** to preserve commit identity.
Further imports update the same PR while it is open. Contributors should use
OpenDKG for team changes and avoid direct pushes to the canonical `main`.

When a change lands directly in canonical `main`, merge the canonical branch
into OpenDKG through a team PR so both histories stay compatible. Download
official packages from the [canonical Releases page](https://github.com/a-51-50/Axiom/releases).
