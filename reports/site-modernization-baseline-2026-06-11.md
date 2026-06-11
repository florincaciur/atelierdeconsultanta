# Site modernization baseline - 2026-06-11

Acest raport documenteaza auditul facut inaintea modificarilor noi din sesiunea curenta. Working tree-ul continea deja schimbari locale relevante pentru hero-ul homepage-ului (`index.html`, `banners.json`, `sitemap.xml`) si artefacte generate in `reports/`; acestea au fost pastrate si integrate cu prudenta, fara reset, clean sau suprascriere destructiva.

## Stare Git initiala

- Branch local: `main`.
- `HEAD`, `origin/main` si `origin/master`: `c2b60c722ab5def313b4c387141ed7cb9d0bc97f`.
- `git fetch origin --prune`: rulat cu succes.
- `git merge-base --is-ancestor HEAD origin/main`: exit code `0`.
- `git merge-base --is-ancestor origin/main HEAD`: exit code `0`.
- `fd` nu este instalat local; pentru descoperire s-a folosit fallback cu `rg --files`.

## Inventar generat

- Inventar rute publice: `reports/site-modernization-route-inventory-2026-06-11.csv`.
- Randuri inventar: 92 rute din `sitemap.xml`.
- Coloane: URL, ruta, fisier sursa, template/generator, H1, title, description, canonical, tipuri structured data, CTA primar, numar linkuri interne, formulare, robots, status indexare.

## Source of truth

| Arie | Source of truth |
| --- | --- |
| Homepage, hero, navigatie principala, formular homepage | `index.html` |
| Banners / carousel programe | `banners.json` + fallback din `index.html` |
| Pagini program generate | `config/seo-programs.json` + `tools/generate-program-pages.js` |
| Pagini programatice FAQ/CAEN/regional | `config/seo-programmatic-pages.json` + `tools/generate-programmatic-seo.js` |
| Sitemap | `tools/generate-sitemap.js` -> `sitemap.xml` |
| Deploy Cloudflare | `wrangler.jsonc`, `_redirects`, `_headers`, `tools/build-cloudflare-assets.js` |
| Structured data comun | `tools/schema-helpers.js`, `tools/editorial-metadata.js`, JSON-LD inline in HTML |
| Surse oficiale | `official-guides.json`, `assets/official-guides.js`, `tools/official-sources.js` |
| Validari | `scripts/verify-seo-integrity.js`, `scripts/visual-integrity-check.js`, `verify-and-fix.js`, `tests/faber-functional-checks.mjs` |

## Baseline comenzi

Fisierul local `baseline-results.txt` continea deja rularea baseline a comenzilor cerute. Rezultatele relevante:

| Comanda | Baseline |
| --- | --- |
| `npm ci` | PASS; 3 vulnerabilitati npm raportate de audit, fara blocare |
| `npm run check:copy` | PASS |
| `npm run verify:seo` | PASS; 170 fisiere, 0 fail |
| `npm run verify:visual` | PASS; 18 verificari, 0 fail |
| `npm run verify:functional` | PASS; 22 functional checks, 0 fail |
| `npm run verify:sitemap` | PASS; 92 URL-uri canonice |
| `npm run audit:program-routes` | PASS |
| `npm run audit:gsc-routes` | PASS; 39 randuri GSC |
| `npm run test:functional` | PASS |
| `npm run build` | PASS; `dist` generat |
| `npm run validate:cloudflare` | PASS |

## Audit tehnic

- Homepage-ul este pagina statica manuala si poate fi modificat direct in `index.html`.
- Hero-ul are un singur H1, canonicalul homepage ramane `https://atelierdeconsultanta.ro/`.
- Linkurile din hero folosesc rute existente: `/verificare-eligibilitate-fonduri-europene`, `/fonduri-europene`, `/afir-autoconsum-agroalimentar`, `/dr12-afir`, `/dr14`, `/e-move`, `/pro-infra`, `/start-up-nation-2026`, `/investitii-modernizarea-microintreprinderilor-apel-2`.
- Redirecturile si canonicalurile nu necesita schimbare pentru modernizarea vizuala.
- Formularul homepage si endpointul FormSubmit nu trebuie modificate.
- `banners.json` continea texte fara diacritice pe cateva slide-uri; acestea sunt publice si pot fi corectate fara schimbare de rute.
- `sitemap.xml` este generat de `tools/generate-sitemap.js`; orice modificare manuala trebuie evitata daca nu este produsa de generator.

## Directie implementare aprobata de audit

- Modernizare progresiva a hero-ului in `index.html`, fara framework si fara dependinte noi.
- SVG inline original pentru traseul proiectului, cu `title` si `desc`.
- Selector de programe progresiv: linkurile raman vizibile in HTML, JavaScript doar sincronizeaza cardul activ.
- Fara autoplay obligatoriu si fara continut SEO critic injectat exclusiv prin JavaScript.
- Respectarea `prefers-reduced-motion` prin oprirea animatiilor decorative.
- Pastrarea tuturor URL-urilor, formularului, canonicalurilor, sitemapului si redirecturilor.
