# Axiom repository stewardship and project provenance

**Status:** Documentation of the current development arrangement. Not a contract or copyright assignment.

## Project creator

The original creator, [@a-51-50](https://github.com/a-51-50), is responsible for the canonical
upstream's overall direction, the initial architecture and lead maintainership. This credit is
permanent and is not changed by later contributions.

## Core maintainers

**Core Maintainer & Platform Lead:** [@dreddster](https://github.com/dreddster),
[@brxtrac](https://github.com/brxtrac).

Core maintainers contribute to architecture, platform development, maintenance, testing and review
within their agreed areas, and should have appropriate collaboration and review opportunities for
their assigned work. Core maintainership is a technical role; it does not transfer repository
ownership, copyright, trademarks, signing authority or legal rights.

## Platform responsibility

Platform leads are the primary technical maintainers of their assigned platform implementations:
platform-specific runtime integration, compatibility, testing, packaging and regression prevention.
They coordinate shared Core and Avalonia changes rather than independently replacing shared
implementations. Specific Linux and macOS assignments are recorded only when formally confirmed, so
this document deliberately keeps the generic Platform Lead role.

## Ownership boundaries

The canonical repository remains [a-51-50/Axiom](https://github.com/a-51-50/Axiom). Project titles do
not transfer GitHub ownership, copyright, trademarks, signing authority or legal rights, and the
existing signed founder agreements and contributor obligations are unaffected. The planned OpenDKG
fork relationship described below is unchanged.

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

## Optional future OpenDKG repository

**No transfer, fork or synchronization is authorized or performed by this document.**

The intended arrangement, if approved later, is:

1. Keep `a-51-50/Axiom` as the canonical upstream, maintaining original administration,
   issues, PRs, releases and security-advisory workflow there.
2. Once the project is deliberately made public after a disclosure/security review,
   an OpenDKG organization repository may be created as a **fork** of that public upstream.
   It will preserve the upstream Git commits, but have separate organization permissions,
   settings, issues, PRs, releases and workflows.
3. Prefer changes via pull requests **to the canonical upstream**. Keep a future OpenDKG fork
   synchronized deliberately and label it clearly as a fork; it does not become the release
   authority by default. A fork is not a live, bidirectional mirror.
4. Do not automate destructive `git push --mirror` operations, publish private branches,
   or expose confidential CI logs and materials without separate approval.
5. GitHub organization owners can administer repositories inside that organization, including
   its forks. They do not become administrators of the personal upstream merely by operating
   an organization fork. Existing collaborator access on the upstream is separate.

If OpenDKG is to distribute an **official** Axiom build, agree the release and trademark
permissions separately; the fork itself does not convey those privileges.

## Checklist before making Axiom public

- Review **all Git history**, not just the latest tree, for secrets, access tokens,
  private identities, paths, internal endpoints and accidentally committed data;
  rotate compromised credentials and remediate history appropriately.
- Review Issues, PRs, review comments, Actions logs and release artifacts for disclosures.
- Confirm copyright/license notices, DCO sign-offs and third-party redistribution obligations.
- Confirm private signing documents and personal contact details are not in public paths.
- Check permissions, branch rules, required reviews, CI trust boundaries and SECURITY.md.
- Approve public visibility as a separate, explicit operation; do not infer approval from this file.
