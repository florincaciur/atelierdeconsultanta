# SEO, Performance and AI Search Audit Notes

Updated: 2026-05-03

## Stack and deployment

- Static HTML/CSS/JavaScript site.
- No `package.json`, Vite, Next.js, Astro, Nuxt, Netlify or Vercel build pipeline was found.
- Public deployment is consistent with GitHub Pages: `CNAME`, static HTML files, `robots.txt`, `sitemap.xml`.
- `_redirects` is kept for hosts that support it, but GitHub Pages does not apply Netlify-style redirect rules. For old URLs on GitHub Pages, lightweight HTML fallback redirect pages are also present.

## Issues found and fixed

- Removed remaining internal links to `/dr14.html` and `/autoconsum-publici.html`; internal links now point to canonical URLs.
- Added fallback pages for `/contact.html` and `/consultanta-fonduri-europene.html`.
- Kept `/contact/` and `/consultanta-fonduri-europene/` as canonical 200 URLs.
- Kept `/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` as canonical DR 14 URL.
- Kept `/autoconsum-public-fotovoltaice-institutii-publice.html` as canonical autoconsum public/fotovoltaice URL.
- Added missing `og-image.jpg` so Open Graph image references do not return 404.
- Removed the Formspree CDN dependency from the homepage newsletter form.
- Changed homepage/blog `blog.json` loading to avoid cache-busting on every visit.
- Delayed Phosphor icon CDN loading until after `window.load` so it does not block critical rendering.
- Added `loading="lazy"` and `decoding="async"` to dynamic blog card images.
- Updated homepage, contact and consultanta title/description tags.
- Updated `robots.txt` to explicitly allow Googlebot, Bingbot, OAI-SearchBot, ChatGPT-User, GPTBot and PerplexityBot while keeping `/admin/` private.
- Rebuilt `llms.txt` with canonical URLs and no unverifiable success-rate claims.
- Added 30 static SEO/AI-search hub pages with visible HTML content, breadcrumbs, CTAs, FAQ content and JSON-LD.
- Updated `sitemap.xml` to include only canonical final URLs and the new hub URLs.
- Updated the admin sitemap generator list so future admin-generated sitemaps keep the new canonical URLs.

## Canonical URLs

- Contact: `https://atelierdeconsultanta.ro/contact/`
- Consultanta fonduri europene: `https://atelierdeconsultanta.ro/consultanta-fonduri-europene/`
- DR 14 AFIR: `https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html`
- Autoconsum public/fotovoltaice: `https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice.html`
- Hub fonduri europene: `https://atelierdeconsultanta.ro/fonduri-europene/`
- Hub AFIR: `https://atelierdeconsultanta.ro/afir/`
- Hub PNRR: `https://atelierdeconsultanta.ro/pnrr/`
- Hub Start-Up Nation: `https://atelierdeconsultanta.ro/start-up-nation/`

## Redirects configured

Configured in `_redirects` for hosts that support 301 redirect rules:

- `/autoconsum-publici.html` -> `/autoconsum-public-fotovoltaice-institutii-publice.html`
- `/dr14.html` -> `/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html`
- `/contact.html` -> `/contact/`
- `/contact` -> `/contact/`
- `/consultanta-fonduri-europene.html` -> `/consultanta-fonduri-europene/`
- `/consultanta-fonduri-europene` -> `/consultanta-fonduri-europene/`
- `/start-up-nation-2026/` -> `/start-up-nation-2026.html`
- `/femeia-antreprenor-2026/` -> `/femeia-antreprenor-2026.html`
- `/fonduri-europene-herambursabile-2026/` -> `/fonduri-europene-nerambursabile-2026/`
- `/fonduri-europene-herambursabile-2026.html` -> `/fonduri-europene-nerambursabile-2026/`
- `/fonduri-europene-nerambursabile-2026.html` -> `/fonduri-europene-nerambursabile-2026/`
- `.html` variants for the SEO hub pages -> their canonical trailing-slash hub URLs

GitHub Pages limitation: these rules are not enforced as HTTP 301 by GitHub Pages. Existing legacy pages include canonical/meta/JavaScript fallback behavior so users and crawlers are sent to the final URL even on this hosting.

## New hub pages

- `/fonduri-europene/`
- `/fonduri-nerambursabile/`
- `/pnrr/`
- `/afir/`
- `/start-up-nation/`
- `/fonduri-europene-imm/`
- `/fonduri-europene-agricultura/`
- `/fonduri-europene-digitalizare/`
- `/fonduri-europene-femei-antreprenor/`
- `/calendar-fonduri-europene/`
- `/eligibilitate-fonduri-europene/`
- `/ghiduri/`
- `/studii-de-caz/`
- `/intrebari-frecvente/`
- `/start-up-nation-2026-conditii/`
- `/start-up-nation-2026-cheltuieli-eligibile/`
- `/start-up-nation-2026-idei-afaceri/`
- `/start-up-nation-2026-plan-de-afaceri/`
- `/consultanta-start-up-nation/`
- `/consultanta-afir/`
- `/fonduri-pentru-ferme/`
- `/fonduri-pentru-utilaje-agricole/`
- `/granturi-digitalizare-imm/`
- `/consultanta-pnrr-digitalizare/`
- `/finantari-panouri-fotovoltaice/`
- `/cum-alegi-consultant-fonduri-europene/`
- `/cat-costa-consultanta-fonduri-europene/`
- `/firma-consultanta-fonduri-europene/`
- `/consultant-fonduri-europene-imm/`
- `/greseli-fonduri-europene/`

## Test commands

- `node --check assets/official-guides.js`
- extract and check homepage inline JavaScript with Node
- run local static server from the repository root
- crawl `sitemap.xml` locally and live
- verify important local and live URLs return 200
- render sitemap pages in headless Chrome and check that HTML is produced
- scan internal `href` and `src` references for missing local files
- validate JSON-LD blocks by parsing them as JSON

## Recrawl recommendations

Recrawl in the SEO audit tool and Google Search Console:

- `/`
- `/contact/`
- `/consultanta-fonduri-europene/`
- `/fonduri-europene/`
- `/fonduri-nerambursabile/`
- `/pnrr/`
- `/afir/`
- `/start-up-nation/`
- `/fonduri-europene-imm/`
- `/fonduri-europene-agricultura/`
- `/fonduri-europene-digitalizare/`
- `/calendar-fonduri-europene/`
- `/eligibilitate-fonduri-europene/`
- `/ghiduri/`
- `/intrebari-frecvente/`
- `/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html`
- `/autoconsum-public-fotovoltaice-institutii-publice.html`
- `/sitemap.xml`
- `/robots.txt`
- `/llms.txt`

## Remaining monitoring

- Configure true HTTP 301 redirects at DNS/CDN/hosting level if the site stays on GitHub Pages and strict 301 behavior is required for legacy URLs.
- Add real Google Analytics, Bing Webmaster or conversion tracking IDs only when the real IDs are available.
- Publish real case studies only with client approval; do not add invented results or review schema.
