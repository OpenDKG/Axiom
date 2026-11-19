# Axiom repository stewardship and project provenance

**Status:** Documentation of the current development arrangement. Not a contract or copyright assignment.

## Project creator

The original creator, [@a-51-50](https://github.com/a-51-50), is responsible for the canonical
upstream's overall direction, the initial architecture and lead maintainership. This credit is
permanent and is not changed by later contributions.

## Founding leadership

- [@a-51-50](https://github.com/a-51-50) - **Founder & Original Creator**.
- [@dreddster](https://github.com/dreddster) - **Co-Founder & Core Maintainer**.
- [@brxtrac](https://github.com/brxtrac) - **Co-Founder & Core Maintainer**.

## Responsibility model

The Founder & Original Creator is recognized for initiating the project and developing the original
application. Co-Founders & Core Maintainers participate in ongoing development, architectural
collaboration, maintenance, reviews and cross-platform expansion. Platform-specific
responsibilities are recorded once explicitly agreed; this document does not invent a Linux or
macOS lead assignment.

Founding titles are technical project roles. They do not assign copyright, trademarks, repository
administration, revenue rights or legal ownership.

## Ownership boundaries

The canonical repository remains [a-51-50/Axiom](https://github.com/a-51-50/Axiom). Project titles do
not transfer GitHub ownership, copyright, trademarks, signing authority or legal rights, and the
existing signed founder agreements and contributor obligations are unaffected.

The complete Git history (commits, timestamps and Git author metadata) is the technical record
of contributions. [AUTHORS.md](../AUTHORS.md) records project origin and credited roles.
Being named in Git history does not by itself prove legal ownership of every contribution.

## Review and access

The default [CODEOWNERS](../.github/CODEOWNERS) entry requests review from `@a-51-50`
for changes to the canonical repository. This is **not** an exclusive right, a copyright
assignment, or a substitute for protected-branch/ruleset configuration: administrators may
override review settings where GitHub permissions allow. Every change must pass through
a pull request as specified in [CONTRIBUTING.md](../CONTRIBUTING.md).

Repository access, copyright and branding rights are separate. Contributor copyright stays
with the applicable rightsholders unless valid agreements say otherwise; the
[GPL-3.0-or-later license](../LICENSE), notices, and any applicable signed agreements
continue to apply. This document does not amend an existing signed founders' agreement.

### Proposed CODEOWNERS matrix (documented, not applied)

The live [CODEOWNERS](../.github/CODEOWNERS) file keeps its single global entry until platform
assignments and final directory names are confirmed. A future matrix, to be applied only after
review, would look like:

| Area | Proposed review request | Status |
|---|---|---|
| Linux infrastructure, desktop host, packaging and tests | `@dreddster` after confirmation | proposed |
| macOS infrastructure, desktop host, Network Extension, packaging and tests | `@brxtrac` after confirmation | proposed |
| Shared `Axiom.Core`, `Axiom.Contracts`, `Axiom.Presentation`, `Axiom.UI.Avalonia` | `@a-51-50` plus the relevant platform lead | proposed |
| Repository administration, releases and CI security | `@a-51-50` | current |

CODEOWNERS does not establish legal ownership. Listing several owners requests review from eligible
owners; it is not a legal or merge-authority grant. Branch protection and rulesets are configured
separately and must not prevent a platform maintainer from working on their platform.

## OpenDKG working repository

[OpenDKG/Axiom](https://github.com/OpenDKG/Axiom) hosts team development and
distribution copies of Axiom releases. The original discussion history and official package
builds stay with the canonical upstream.

The upstream importer advances the separate `opendkg/sync-main` review branch from
OpenDKG's `main`. A maintainer opens and reviews the corresponding upstream PR.
Organization owners administer the OpenDKG repository. Upstream collaborator access
is managed separately. See the [working-repository guide](OPENDKG_WORKFLOW.md).

## Checklist before making Axiom public

- Review **all Git history**, not just the latest tree, for secrets, access tokens,
  private identities, paths, internal endpoints and accidentally committed data;
  rotate compromised credentials and remediate history appropriately.
- Review Issues, PRs, review comments, Actions logs and release artifacts for disclosures.
- Confirm copyright/license notices, DCO sign-offs and third-party redistribution obligations.
- Confirm private signing documents and personal contact details are not in public paths.
- Check permissions, branch rules, required reviews, CI trust boundaries and SECURITY.md.
- Approve public visibility as a separate, explicit operation; do not infer approval from this file.
