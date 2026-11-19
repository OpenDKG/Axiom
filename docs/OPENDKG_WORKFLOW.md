# Axiom development in OpenDKG

Open PRs for team work in [OpenDKG/Axiom](https://github.com/OpenDKG/Axiom).
Keep implementation discussion and review on the originating PR. Merge team
changes into OpenDKG's `main` to queue them for upstream review.

[a-51-50/Axiom](https://github.com/a-51-50/Axiom) is the private upstream
repository. The importer checks OpenDKG `main` twice per hour and advances
the upstream `opendkg/sync-main` review branch. Further imports update the
same PR while it is open. The upstream maintainer
[opens a new import PR when needed](https://github.com/a-51-50/Axiom/compare/main...opendkg/sync-main?expand=1)
and uses **Create a merge commit** after review to preserve commit identity.
GitHub stores issues, pull requests, and reviews in their original repository.

When a change lands directly in canonical `main`, merge the canonical branch
into OpenDKG through a team PR so both histories stay compatible. Publish
public packages on the [OpenDKG Releases page](https://github.com/OpenDKG/Axiom/releases),
which Axiom 1.4.4 and later use for update checks. Package building and release
publication are separate from the upstream import.
