# Functional, SEO, Accessibility and PageSpeed Audit - 2026-05-26

## Scope

Requested scope: full generated-site audit, navigation and CTA validation, visual/accessibility cleanup, SEO/schema validation, PageSpeed optimization, tests, report, commit and push to `main` and `master`.

Actual generated inventory from the repository:

- 94 canonical URLs in `sitemap.xml`
- 161 source HTML files
- 308 redirect rules in `_redirects`
- 187 files generated in `dist` by `npm run build`

The request referenced 128 generated pages. The current repository build produces 94 canonical sitemap URLs and 161 HTML source files; the functional test covers the canonical URL set and representative legacy/fallback routes.

## Implemented Changes

- Added a focused functional Playwright test: `tests/faber-functional-checks.mjs`.
- Added `npm run test:functional` to validate canonical routes, menu links, CTAs, program grid links, representative redirects, fallback 404 behavior and mobile hamburger navigation.
- Normalized future `dateModified` JSON-LD values on priority pages so structured-data validation passes with the repository audit date.
- Added `favicon.ico` and a long cache policy for ICO assets in `_headers`.
- Improved contrast in the homepage palette and shared article/SEO hub styles while preserving the FABER color system.
- Updated minified CSS counterparts for the same contrast fixes.
- Fixed footer badge accessible names on the homepage.
- Delayed Microsoft Clarity loading until first user interaction or after the initial load window. Tracking remains present, but it no longer competes with initial rendering in Lighthouse.
- Kept the homepage program presentation as a responsive grid and verified there are no carousel controls.
- Did not change files under `tools/` or `scripts/`.
- Did not invent testimonials, project results, local claims or CAEN-specific facts. Missing source-backed expansion remains documented below.

## Functional Validation

Validated by `npm run test:functional`:

- All 94 sitemap canonical URLs return HTTP 200 and include a page heading.
- Main homepage navigation links resolve to valid local targets.
- Desktop program dropdown opens and exposes its links.
- Mobile hamburger opens and exposes menu links at 390 x 844 viewport.
- Primary/secondary visible links on the homepage resolve to valid local targets.
- Program cards in the homepage grid resolve to valid local targets.
- Public program filter changes the visible program set.
- Representative redirects resolve correctly:
  - `/dr12-vs-dr14`
  - `/dr14-afir-ferme-mici`
  - `/ro/5.html`
- Representative legacy fallback `/ro/11.html` returns HTTP 404 and includes noindex behavior.

In-app browser QA snapshot on the local `dist` server:

| Check | Result |
| --- | ---: |
| Homepage H1 count | 1 |
| Financing cards | 11 |
| Carousel controls | 0 |
| Financing grid display | grid |
| Visible primary/secondary links | 27 |
| Inert visible buttons | 0 |
| Mobile links present in DOM | 16 |
| Desktop dropdown links | 10 |
| Horizontal overflow delta | -15 |

## SEO and Schema

Validation status:

- `robots.txt` is valid according to the repository SEO audit.
- 161 of 161 HTML files pass the SEO integrity audit.
- Structured data audit passes: 161 files scanned, 138 files with schema, 0 issues.
- Representative GSC routes pass: canonical pages are index/follow; the legacy `/ro/11.html` fallback returns 404.
- Existing redirect coverage remains intact: 308 redirect rules validated by the Cloudflare validator.

Schema handling:

- Existing `Article`, `BlogPosting`, `FAQPage` and local schema remain in place where already present.
- Date fields on edited structured data were corrected to non-future values relative to the repository audit date.
- `LocalBusiness` schema was not expanded with unconfirmed data.

## Lighthouse / PageSpeed Evidence

Local Lighthouse was run against the built `dist` output for the representative routes requested. Scores below are local Lighthouse scores, not live PageSpeed Insights after deployment.

| Route | Mode | Performance | Accessibility | Best Practices | SEO | LCP (s) | CLS | TBT (ms) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `/` | mobile | 99 | 100 | 100 | 100 | 1.65 | 0 | 89 |
| `/` | desktop | 100 | 100 | 100 | 100 | 0.48 | 0 | 0 |
| `/fonduri-europene` | mobile | 100 | 100 | 100 | 100 | 1.06 | 0 | 39 |
| `/fonduri-europene` | desktop | 100 | 100 | 100 | 100 | 0.29 | 0 | 0 |
| `/afir` | mobile | 100 | 100 | 100 | 100 | 1.06 | 0 | 62 |
| `/afir` | desktop | 100 | 100 | 100 | 100 | 0.29 | 0 | 0 |
| `/ghiduri` | mobile | 100 | 100 | 100 | 100 | 1.06 | 0 | 40 |
| `/ghiduri` | desktop | 100 | 100 | 100 | 100 | 0.29 | 0 | 0 |
| `/contact` | mobile | 99 | 100 | 100 | 100 | 1.06 | 0 | 96 |
| `/contact` | desktop | 100 | 100 | 100 | 100 | 0.29 | 0 | 0 |
| `/dr12-afir` | mobile | 100 | 100 | 100 | 100 | 1.06 | 0 | 65 |
| `/dr12-afir` | desktop | 100 | 100 | 100 | 100 | 0.28 | 0 | 0 |
| `/dr14` | mobile | 100 | 100 | 100 | 100 | 1.06 | 0 | 54 |
| `/dr14` | desktop | 100 | 100 | 100 | 100 | 0.29 | 0 | 0 |

Performance notes:

- LCP is below 2.5 seconds on all representative local Lighthouse runs.
- Accessibility, Best Practices and SEO are 100 on all representative local Lighthouse runs.
- Mobile Performance remains 99 on `/` and `/contact` due to small residual main-thread variance. The controllable work found during this pass was addressed.
- Lighthouse emitted non-blocking Windows temp cleanup warnings after JSON reports were written. The reports were still generated and parsed successfully.

## Commands Run

Passing checks:

```text
git fetch origin --prune
npm run build
npm run test:functional
npm run verify:all
npm run audit:structured-data
npm run audit:content
npm run validate:cloudflare
npm run audit:program-routes
npm run audit:gsc-routes
git diff --check
```

`npm run audit:content` exits successfully, but it reports 154 indexable pages under the repository's 2000-word depth threshold. That is a content-depth gap, not a broken-build condition.

## Remaining Items

- Content depth: 154 indexable pages remain under 2000 words according to `npm run audit:content`. Expanding every page with verified regional, CAEN, eligibility, calculation and FAQ content needs source-backed business data. No claims were invented in this pass.
- Portfolio, testimonials and case studies: the request asked for real projects and real reviews. The repository does not contain enough verified material to safely create those. This remains blocked on client-approved source content.
- Live PageSpeed Insights: local Lighthouse evidence is included above. Live PSI should be rerun after the pushed changes deploy to production.
- Absolute PageSpeed target: most representative mobile and desktop runs reached 100/100. `/` and `/contact` mobile Performance reached 99 locally, with all other categories at 100.

## Modified Files Summary

- `_headers`
- `favicon.ico`
- `package.json`
- `tests/faber-functional-checks.mjs`
- `index.html`
- `contact.html`
- `afir.html`
- `afir/index.html`
- `ghiduri.html`
- `ghiduri/index.html`
- `dr12-vs-dr14.html`
- `dr14-afir-ferme-mici.html`
- `assets/seo-hub.css`
- `assets/seo-hub.min.css`
- `assets/blog/article.css`
- `assets/blog/article.min.css`
- `reports/final-functional-seo-pagespeed-audit-2026-05-26.md`
