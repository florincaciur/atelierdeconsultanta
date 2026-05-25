# Final functional, SEO, accessibility and PageSpeed audit - FABER

Generated: 2026-05-25

Scope: local repository and local production build. The audit preserved the existing site architecture and did not edit page generators in `tools/` or `scripts/`.

## Inventory

- Canonical URLs in `sitemap.xml`: 94
- Source HTML files verified by the validation suite: 161
- Redirect rules in `_redirects`: 308
- Link audit coverage after fixes: 4,153 links
- Representative Lighthouse/PageSpeed routes tested locally: `/`, `/fonduri-europene`, `/afir`, `/ghiduri`, `/contact`, `/dr12-afir`, `/dr14`

## Implemented fixes

- Fixed confirmed self-redirect loops where root HTML aliases redirected to their own canonical clean URL. The affected aliases now contain the canonical page content instead of looping.
- Preserved intentional legacy redirects and added accessible fallback body content to redirect-only legacy HTML files.
- Added the missing related-content stylesheet link to static article pages that render related-link sections.
- Removed visible placeholder copy such as public TODO markers and "In curs de actualizare" text from non-generator source content.
- Replaced invalid placeholder source/reviewer metadata with cautious, verifiable editorial language. No fake sources, testimonials, project results or local claims were added.
- Kept portfolio, testimonials and case-study content constrained to anonymized or already verifiable material.
- Improved color contrast while preserving the FABER palette by darkening the orange accent variables used by shared button/article styles.
- Confirmed the homepage program presentation is a responsive grid in the production build and does not expose carousel controls.
- Added long-lived static asset cache headers and short cache headers for `robots.txt` and `sitemap.xml`.
- Confirmed `robots.txt` is valid, accessible and references the sitemap.

## Verification commands

| Check | Result |
| --- | --- |
| `git fetch origin --prune` before work | Passed; `main...origin/main` was clean |
| `node tools/audit-site-links.js` | Passed; 0 missing targets, 0 missing anchors, 0 redirect issues |
| `npm run verify:all` | Passed; SEO, inline scripts, functional checks, SEO integrity, robots and link audit all passed |
| `npm run build` | Passed; production build generated 186 files in `dist` |
| `npm run validate:cloudflare` | Passed; Cloudflare Pages configuration and 308 redirects validated |
| `npm run audit:program-routes` | Passed; program canonical routes returned 200 without loops |
| `npm run audit:gsc-routes` | Passed; representative GSC routes resolved to canonical/indexable pages or valid 404 fallback |

## Browser QA

Manual browser automation was run against the local production build on desktop and mobile viewports.

- Desktop homepage: 1 H1, 11 financing cards, 0 broken in-page anchors, no inert visible buttons detected.
- Desktop program menu: opened correctly, 10 menu links visible, no horizontal overflow.
- Mobile hamburger menu: opened correctly, 16 menu links visible, click target covered the viewport width without overflow.
- Legacy route sample: redirected to the expected canonical URL without a loop.

## Local Lighthouse results

The checks below used Lighthouse 13.3.0 against the local production build. They are local equivalents for the PageSpeed work; live PageSpeed Insights should be rerun after deployment because network, CDN and third-party conditions can change final scores.

| Route | Performance | Accessibility | Best Practices | SEO | LCP | CLS | TBT |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `/` | 99 | 96 | 100 | 100 | 1.7 s | 0 | 70 ms |
| `/fonduri-europene` | 100 | 95 | 100 | 100 | 1.1 s | 0 | 10 ms |
| `/afir` | 100 | 95 | 100 | 100 | 1.1 s | 0 | 10 ms |
| `/ghiduri` | 100 | 95 | 100 | 100 | 1.1 s | 0 | 10 ms |
| `/contact` | 100 | 96 | 100 | 100 | 1.1 s | 0 | 0 ms |
| `/dr12-afir` | 100 | 95 | 100 | 100 | 1.1 s | 0 | 10 ms |
| `/dr14` | 100 | 96 | 100 | 100 | 1.1 s | 0 | 10 ms |

## Files and areas changed

- Root and canonical HTML aliases: fixed self-redirecting canonical aliases and added safe fallback text to redirect-only pages.
- `assets/seo-hub.css`, `assets/seo-hub.min.css`, `assets/blog/article.css`, `assets/blog/article.min.css`: contrast improvements.
- `_headers`: production cache policy for static assets, images, fonts, scripts, stylesheets, `robots.txt` and `sitemap.xml`.
- `blog.json`, `config/editorial-pages.json`, `config/seo-programs.json`, `llms.txt`: placeholder cleanup and verifiable editorial metadata.
- `reports/final-functional-seo-pagespeed-audit.md`: final delivery report.

## Remaining limitations

- No fabricated testimonials, "real" reviews, project results or local statistics were created. Pages that need client-confirmed proof remain intentionally cautious.
- Live PageSpeed Insights was not rerun after deployment because these changes had not yet been pushed/deployed at audit time. Local Lighthouse shows all representative pages at 99-100 performance and 100 SEO.
- Lighthouse reported temporary local cleanup permission warnings for its own cache folders after JSON reports were written. The reports were generated and parsed successfully; this did not affect site validation.
