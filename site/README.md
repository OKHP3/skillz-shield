# Skillz Shield website

The standalone public explanation, evidence, and integration surface for
[Skillz Shield](https://github.com/OKHP3/skillz-shield). Vite builds this React,
TypeScript, and Tailwind CSS application as static files for GitHub Pages at
`https://okhp3.github.io/skillz-shield/`.

## Run locally

Use Node.js 24 (or another compatible version declared in `package.json`):

```text
cd site
npm ci
npm run dev
```

The development URL includes `/skillz-shield/`. Validate with:

```text
npm test
npm run build
```

The build includes TypeScript checking and writes `site/dist/`. `npm run preview`
serves that production output. The exact dependency graph lives in
`package-lock.json`.

## Evidence boundary

The page fetches `public/data/evidence.json` under Vite's configured base path.
The repository's publisher generates that file from verified full-scan reports;
do not hand-edit it to improve a displayed result. No scan runs in the browser.
There are no uploads, browser credentials, or application server. The production
build can send page views only when `VITE_GA_MEASUREMENT_ID` is explicitly set
to a Shield-specific public GA4 measurement ID. Analytics is disabled by default
and in development; do not copy Forge's ID or use an API secret. The Pages build
does not currently configure a measurement ID.
Google Fonts supplies the shared OverKill Hill typefaces, with local fallbacks.

The brand assets in `public/` include a 1200×630 PNG social image, a square
project avatar, browser and Apple icons, a Safari pinned-tab mask, and web app
icons. The social PNG is suitable for GitHub's repository social-preview upload
and as a Replit project cover; repository/account settings must be updated
separately because those settings are not controlled by this GitHub Pages build.

The frontend checks the evidence schema, source consistency, known engines,
immutable identities, inventory coverage, and finding totals before displaying
it. Missing or incompatible evidence remains unavailable. A failed refresh, a
different source revision, or an observed scan older than eight days is labeled
historical. This freshness cue does not replace the scan date or source SHA.

The published Shield release and the consumer's current pin are displayed
separately from the historical control pin and scanner versions used by the
recorded scan. Installation copies a complete read-only starter workflow pinned
to the published release. If the clipboard is unavailable, a selected text field
provides a manual copy path.

## Design provenance

The compact Skill basics & sources section provides a brief definition and
links to external authoring guidance, provider/project catalogs, and a separately
labeled community collection. Keep skill-authoring advice at those sources
instead of duplicating tutorials here. Preserve clear legacy labels when a
provider replaces a catalog; OpenAI's deprecated skills catalog links alongside
its current plugins repository. Shield's own integration instructions remain
specific to the security action and its supported repository layouts.

The styling adapts the MIT-licensed `OKHP3/skillz` Forge design: Alfa Slab One
headlines, DM Sans body, JetBrains Mono labels, OverKill Hill palette, copper
rules, compact square corners, navigation, and footer patterns. The default
palette is inverted from the published light Forge: espresso backgrounds,
warm-paper text, teal structural panels, and amber actions. The inspection sheet
uses a restrained paper surface. The Shield illustration is local SVG.

Navigation uses native fragment links and landmarks. Menus expose expanded
state, Escape returns focus, the page includes a skip link and visible focus
styles, and reduced-motion preferences disable smooth scrolling. Expandable
engine pins use native details/summary controls. The page supports narrow screens
without hiding the evidence or replacing it with decorative status claims.
