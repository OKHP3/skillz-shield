# Changelog

Material changes to Skillz Shield are recorded here. Consumers use full commit
pins; release tags identify reviewed milestones and are not moved.

## Unreleased

- Preserve same-line NVIDIA reference-exception occurrence counts for exact
  review records, and handle normalized NVIDIA rules that have several finding
  locations. Missing or changed evidence remains review-blocking.

- Add a separate exact-content, expiring review policy for located scanner
  false positives and fully inspected NVIDIA reference-resolution limitations.
  PRs read approvals only from their base commit; raw scan reports and vendor
  decisions remain unchanged and visible.

- Add bounded whole-ZIP package staging and an operator scan CLI with JSON and
  standalone HTML reports, safe locations and reviewed rule guidance. Drafts
  remain eligible. Public authenticated upload hosting is still pending.

- Locate NVIDIA completeness-gap origins with allowlisted reason codes and known
  staged file/line identities. Missing reference targets and arbitrary ledger
  text remain excluded; incomplete coverage remains blocking.

- Reconcile the unpublished Replit site work with current dependencies and scanner
  fixes while retaining both commit histories. Add page-specific sharing metadata,
  icons, social artwork, sitemap, and a Node 24 Replit preview workflow.
- Keep analytics disabled unless a Shield-specific measurement ID is explicitly
  configured for a production build; do not reuse the Forge property.
- Retain bounded finding file/line diagnostics matched to staged package files.
  Absolute paths, scanner prose, snippets and remote-source locations remain
  excluded. Findings, coverage and failure decisions are unchanged.

- Preserve six additional public NVIDIA v2.12.0 ledger reason codes in sanitized
  coverage diagnostics. Incomplete verdicts, findings, fatal errors, and
  redaction of arbitrary vendor text remain unchanged.

- Add a source-backed technology inventory, read-only weekly release comparison,
  and reviewed update procedure covering npm, runtimes, Actions and scanner pins.
  Keep missing environment evidence and historical scanner observations explicit.

- Update the site to React 19.3, Vite 8, and TypeScript 7 together, with matching
  React types and plugin. Update the pinned uv, artifact, and Pages actions;
  scanner input/output and evidence verdict contracts remain unchanged.

- Retain bounded, allowlisted NVIDIA analyzer counters and ledger reason counts,
  distinguishing complete file coverage from incomplete analysis without exposing
  scanner messages or changing verdicts.

- Split the public Shield companion into separate Overview, Evidence, Engines,
  Integrate, and Guidance pages, each directly addressable on GitHub Pages.
- Bring Forge-style GitHub access and a persisted light, dark, or system-display
  choice into Shield's sticky navigation, including a compact keyboard-safe menu.
- Add compact skill guidance and source links, with Agent Skills best practices,
  provider and project catalogs, and a separately labeled community collection.
  Identify OpenAI's deprecated skills catalog and current plugins destination.
- Add a standalone Vite, React, TypeScript, and Tailwind SPA on GitHub Pages,
  reusing Forge's typefaces and component patterns with an inverted dark palette.
- Publish sanitized security evidence and exact scanner identities separately
  from the current Shield action pin, with explicit incomplete and stale states.
- Separate website builds from scanner verification so frontend-only changes
  do not run the real-engine smoke suite or expand skill scan scope.

## [1.0.2](https://github.com/OKHP3/skillz-shield/releases/tag/v1.0.2) - 2026-09-19

- Rename the project from `skill-security-pipeline` to **Skillz Shield**, with
  repository identity `OKHP3/skillz-shield` and an explicit relationship to
  OverKill Hill's Skillz Forge and MurderBird story.
- Expand the README and add architecture, contribution, security-reporting, and
  agent-operation documentation.
- Add contribution templates, portable text-file settings, private vulnerability
  reporting, and a clearly proposed roadmap for a static web companion.
- Brand the Action, verification workflow, summaries, and outbound user agent as
  Skillz Shield without changing scanner scope or decision rules.

## [1.0.1](https://github.com/OKHP3/skillz-shield/releases/tag/v1.0.1) - 2026-09-19

Commit: `f81a2ba9cda9be52312b7ebbb793a80ac1b41934`.

- Treat NVIDIA-declared input exclusions as incomplete package coverage, even
  when the upstream report describes its narrower analysis as complete.
- Retain sanitized exclusion counts and add regression coverage for excluded
  package content.
- Report count-only progress during large inventories.

## [1.0.0](https://github.com/OKHP3/skillz-shield/releases/tag/v1.0.0) - 2026-09-19

Commit: `66dd153f62bde67235daea34c8d81985f5573561`.

- Introduce the reusable plan, resolve, install, and scan action for Cisco Skill
  Scanner and NVIDIA SkillSpector.
- Select committed skill packages, including family drafts without `SKILL.md`,
  and preserve source bytes in bounded temporary staging.
- Resolve official stable vendors to immutable source, wheel, and dependency
  identities; supervise scanners without executing skill content.
- Normalize findings and completeness separately, bind reports to the selected
  package identity, and produce sanitized evidence.
- Add contract tests and real-engine smoke checks using synthetic fixtures.
