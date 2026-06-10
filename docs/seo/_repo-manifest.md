# SEO repository manifest and route inventory

Data inventar: 2026-06-10

Acest document este doar inventar intern. Nu modifica design, CSS, componente vizuale, structura formularelor sau logica de navigare.

## Comenzi de descoperire

- Comanda ceruta `fd -HI "robots|sitemap|llms|layout|head|metadata|seo|schema|breadcrumb|redirect|rewrite|route|content|mdx|markdown|page|post|build|deploy" .` a fost rulata, dar `fd` nu este instalat local.
- Comanda ceruta `rg -n "Implementare SEO FABER|in curs de validare|canonical|og:url|FAQPage|BreadcrumbList|Organization|Article|LocalBusiness|Start-Up Nation|DR14|PNRR|Digitalizare" .` a fost rulata.
- Fallback folosit pentru lista de fisiere: `rg --files -uu -g '!node_modules/**' -g '!dist/**' -g '!.git/**' -g '!.wrangler/**' | Where-Object { $_ -match 'robots|sitemap|llms|layout|head|metadata|seo|schema|breadcrumb|redirect|rewrite|route|content|mdx|markdown|page|post|build|deploy' } | Sort-Object`

## Manager pachete si build

- Manager detectat: `npm`
- Lockfile: `package-lock.json`
- Config deploy Cloudflare: `wrangler.jsonc`
- Build assets: `tools/build-cloudflare-assets.js`
- Director build generat: `dist/`

Scripturi disponibile in `package.json`:

```text
optimize:assets
extract:sources
audit:content
audit:structured-data
audit:gsc-queries
normalize:copy
check:copy
generate:program-pages
generate:programmatic-seo
apply:design-profiles
generate:lead-magnets
generate:sitemap
verify:sitemap
verify:seo-local
verify:seo
verify:visual
verify:functional
verify:all
fix:all
build
validate:cloudflare
audit:program-routes
audit:gsc-routes
test:functional
deploy
deploy:pages
```

Nu exista scripturi standard numite `lint` sau `test`; exista `test:functional` si scripturi `verify:*`.

## Fisiere reale pe arii

| Arie | Fisiere reale |
| --- | --- |
| Routing si redirecturi | `_redirects`, `wrangler.jsonc`, `tools/build-cloudflare-assets.js`, `tools/generate-redirect-fallbacks.js` |
| Headers indexare/cache | `_headers`, `tools/validate-cloudflare-deploy.js` |
| Sitemap | `sitemap.xml`, `tools/generate-sitemap.js`, `tools/verify-sitemap.js` |
| Robots si AI policy | `robots.txt`, `llms.txt` |
| Meta/canonical/head static | fisierele `*.html` si `*/index.html` listate in tabelul de rute |
| Meta/canonical/head generat | `tools/generate-program-pages.js`, `tools/generate-programmatic-seo.js`, `tools/generate-seo-hubs.js`, `tools/generate-seo-blog-article.js`, `admin/index.html` |
| Schema JSON-LD | `tools/schema-helpers.js`, `tools/editorial-metadata.js`, `tools/official-sources.js`, plus schema inline in fisierele HTML |
| Breadcrumbs | schema inline in HTML, generatoare SEO, `tools/schema-helpers.js` pentru helper comun |
| Continut programe | `config/seo-programs.json`, `tools/generate-program-pages.js`, output in directoare program |
| Continut programmatic | `config/seo-programmatic-pages.json`, `tools/generate-programmatic-seo.js`, output local/FAQ/CAEN/regional |
| Continut editorial | fisiere HTML statice, `config/editorial-pages.json`, `blog.json`, `tools/generate-seo-blog-article.js`, `config/seo-blog-article.example.json` |
| Surse oficiale | `official-guides.json`, `assets/official-guides.js`, `tools/official-sources.js` |
| Formulare publice | `index.html`, `contact/index.html`, `contact.html`, verificari in `verify-and-fix.js` si `tests/faber-functional-checks.mjs` |
| Admin/editor intern | `admin/index.html` |
| CI/deploy | `.github/workflows/seo-freshness.yml`, `package.json`, `wrangler.jsonc` |

## Observatii de arhitectura

- Nu exista un layout/head helper central de tip Next/Astro. Site-ul este static, iar head-ul este in fiecare HTML sau este injectat de generatoare Node.
- `_redirects` este sursa principala pentru canonicalizare de rute, alias-uri si fallback-uri.
- `wrangler.jsonc` seteaza deploy-ul Cloudflare cu `assets.directory = "./dist"` si `html_handling = "drop-trailing-slash"`.
- `tools/build-cloudflare-assets.js` copiaza fisierele publice in `dist/`, creeaza variante `.html` pentru rute directory-backed si copiaza `_redirects`/`_headers`.
- `tools/generate-sitemap.js` extrage canonical din HTML, exclude noindex/redirect/meta-refresh si scrie `sitemap.xml`.
- `tools/verify-sitemap.js` verifica potrivirea dintre canonical si URL-urile asteptate.
- `llms.txt` este politica pentru AI/search crawlers si trimite catre URL-urile canonice, `robots.txt` si `sitemap.xml`.

## Route -> sursa continut

Tabel derivat din `sitemap.xml` si fisierele HTML existente.

| Ruta publica | Sursa continut |
| --- | --- |
| `/` | `index.html` |
| `/apeluri-gal` | `apeluri-gal/index.html` |
| `/consultanta-fonduri-europene` | `consultanta-fonduri-europene/index.html` |
| `/digitalizare-imm` | `digitalizare-imm/index.html` |
| `/dr12-afir` | `dr12-afir/index.html` |
| `/dr14` | `dr14/index.html` |
| `/fonduri-europene` | `fonduri-europene/index.html` |
| `/start-up-nation-2026` | `start-up-nation-2026/index.html` |
| `/blog` | `blog/index.html` |
| `/despre-faber` | `despre-faber/index.html` |
| `/glosar-fonduri-europene` | `glosar-fonduri-europene/index.html` |
| `/metodologie-verificare-eligibilitate` | `metodologie-verificare-eligibilitate/index.html` |
| `/studii-de-caz-fonduri-europene` | `studii-de-caz-fonduri-europene/index.html` |
| `/surse-oficiale-fonduri-europene` | `surse-oficiale-fonduri-europene/index.html` |
| `/acte-necesare-fonduri-europene-nerambursabile` | `acte-necesare-fonduri-europene-nerambursabile/index.html` |
| `/afir` | `afir/index.html` |
| `/afir-autoconsum-agroalimentar` | `afir-autoconsum-agroalimentar/index.html` |
| `/autoconsum-public-fotovoltaice-institutii-publice` | `autoconsum-public-fotovoltaice-institutii-publice/index.html` |
| `/blog-afir-fotovoltaice-ferme-2026` | `blog-afir-fotovoltaice-ferme-2026.html` |
| `/calculator-soc` | `calculator-soc.html` |
| `/calendar-fonduri-europene` | `calendar-fonduri-europene/index.html` |
| `/cand-merita-consultant-fonduri-europene` | `cand-merita-consultant-fonduri-europene.html` |
| `/cat-costa-consultanta-fonduri-europene` | `cat-costa-consultanta-fonduri-europene/index.html` |
| `/cat-costa-consultanta-fonduri-europene-ghid` | `cat-costa-consultanta-fonduri-europene-ghid.html` |
| `/ce-acte-sunt-necesare-fonduri-europene` | `ce-acte-sunt-necesare-fonduri-europene.html` |
| `/cheltuieli-eligibile-digitalizare-imm` | `cheltuieli-eligibile-digitalizare-imm.html` |
| `/cod-caen-start-up-nation-2026` | `cod-caen-start-up-nation-2026/index.html` |
| `/consultant-fonduri-europene-imm` | `consultant-fonduri-europene-imm/index.html` |
| `/consultanta-afir` | `consultanta-afir/index.html` |
| `/consultanta-fonduri-europene-bucuresti` | `consultanta-fonduri-europene-bucuresti/index.html` |
| `/consultanta-pnrr-digitalizare` | `consultanta-pnrr-digitalizare/index.html` |
| `/consultanta-start-up-nation-2026` | `consultanta-start-up-nation-2026/index.html` |
| `/contact` | `contact/index.html` |
| `/cum-alegi-consultant-fonduri-europene` | `cum-alegi-consultant-fonduri-europene/index.html` |
| `/cum-alegi-programul-potrivit-fonduri-europene-2026` | `cum-alegi-programul-potrivit-fonduri-europene-2026.html` |
| `/cum-se-calculeaza-cofinantarea-fonduri-europene` | `cum-se-calculeaza-cofinantarea-fonduri-europene.html` |
| `/cum-se-verifica-eligibilitatea-fonduri-europene` | `cum-se-verifica-eligibilitatea-fonduri-europene.html` |
| `/digitalizare-imm-erp-crm-cloud` | `digitalizare-imm-erp-crm-cloud.html` |
| `/digitalizare-imm-pnrr` | `digitalizare-imm-pnrr/index.html` |
| `/dr-12-afir-instalarea-tinerilor-fermieri` | `dr-12-afir-instalarea-tinerilor-fermieri.html` |
| `/dr-14-afir-conditii-eligibilitate-greseli-frecvente` | `dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` |
| `/dr12-vs-dr14` | `dr12-vs-dr14.html` |
| `/dr14-afir-ferme-mici` | `dr14-afir-ferme-mici/index.html` |
| `/e-move` | `e-move/index.html` |
| `/eligibilitate-fonduri-europene` | `eligibilitate-fonduri-europene/index.html` |
| `/femeia-antreprenor-2026` | `femeia-antreprenor-2026/index.html` |
| `/femeia-antreprenor-2026-conditii-idei-afaceri` | `femeia-antreprenor-2026-conditii-idei-afaceri.html` |
| `/finantari-panouri-fotovoltaice` | `finantari-panouri-fotovoltaice/index.html` |
| `/firma-consultanta-fonduri-europene` | `firma-consultanta-fonduri-europene/index.html` |
| `/fondul-de-modernizare` | `fondul-de-modernizare/index.html` |
| `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum` | `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum/index.html` |
| `/fondul-modernizare-energie-regenerabila-2026` | `fondul-modernizare-energie-regenerabila-2026/index.html` |
| `/fonduri-europene-agricultura` | `fonduri-europene-agricultura/index.html` |
| `/fonduri-europene-bucuresti` | `fonduri-europene-bucuresti/index.html` |
| `/fonduri-europene-digitalizare` | `fonduri-europene-digitalizare/index.html` |
| `/fonduri-europene-femei-antreprenor` | `fonduri-europene-femei-antreprenor/index.html` |
| `/fonduri-europene-imm` | `fonduri-europene-imm/index.html` |
| `/fonduri-europene-nerambursabile-2026` | `fonduri-europene-nerambursabile-2026/index.html` |
| `/fonduri-europene-nord-est` | `fonduri-europene-nord-est/index.html` |
| `/fonduri-nerambursabile` | `fonduri-nerambursabile/index.html` |
| `/fonduri-pentru-ferme` | `fonduri-pentru-ferme/index.html` |
| `/fonduri-pentru-utilaje-agricole` | `fonduri-pentru-utilaje-agricole/index.html` |
| `/fonduri-regionale` | `fonduri-regionale/index.html` |
| `/gal-afir` | `gal-afir/index.html` |
| `/gdpr` | `gdpr.html` |
| `/ghiduri` | `ghiduri/index.html` |
| `/granturi-digitalizare-imm` | `granturi-digitalizare-imm/index.html` |
| `/greseli-fonduri-europene` | `greseli-fonduri-europene/index.html` |
| `/idei-afaceri-fonduri-europene` | `idei-afaceri-fonduri-europene.html` |
| `/instrumente` | `instrumente/index.html` |
| `/intrebari-frecvente` | `intrebari-frecvente/index.html` |
| `/investitii-modernizarea-microintreprinderilor-apel-2` | `investitii-modernizarea-microintreprinderilor-apel-2/index.html` |
| `/pnrr` | `pnrr/index.html` |
| `/pnrr-digitalizare-imm-cheltuieli-eligibile` | `pnrr-digitalizare-imm-cheltuieli-eligibile.html` |
| `/politica-de-confidentialitate` | `politica-de-confidentialitate.html` |
| `/por-adr-nord-est` | `por-adr-nord-est/index.html` |
| `/portofoliu` | `portofoliu/index.html` |
| `/pro-infra` | `pro-infra/index.html` |
| `/resurse` | `resurse/index.html` |
| `/start-up-nation-2026-cheltuieli-eligibile` | `start-up-nation-2026-cheltuieli-eligibile/index.html` |
| `/start-up-nation-2026-conditii` | `start-up-nation-2026-conditii/index.html` |
| `/start-up-nation-2026-idei-afaceri` | `start-up-nation-2026-idei-afaceri/index.html` |
| `/start-up-nation-2026-plan-de-afaceri` | `start-up-nation-2026-plan-de-afaceri/index.html` |
| `/studii-de-caz` | `studii-de-caz/index.html` |
| `/termeni-si-conditii` | `termeni-si-conditii.html` |
| `/testimoniale` | `testimoniale/index.html` |
| `/verificare-eligibilitate-fonduri-europene` | `verificare-eligibilitate-fonduri-europene/index.html` |
| `/webinarii` | `webinarii/index.html` |
| `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm` | `intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html` |
| `/intrebari/ce-documente-sunt-necesare-pentru-dr12` | `intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html` |
| `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene` | `intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html` |
| `/fonduri-europene-caen/0111-culturi-cereale` | `fonduri-europene-caen/0111-culturi-cereale/index.html` |
| `/fonduri-europene-caen/4321-instalatii-electrice` | `fonduri-europene-caen/4321-instalatii-electrice/index.html` |
| `/fonduri-europene-caen/5610-restaurante` | `fonduri-europene-caen/5610-restaurante/index.html` |
| `/fonduri-europene-caen/6201-dezvoltare-software` | `fonduri-europene-caen/6201-dezvoltare-software/index.html` |

## Mapping issue -> fisier de remediat

| Issue SEO / tehnic | Fisiere de remediat |
| --- | --- |
| Redirect canonical, slash/no-slash, alias HTML vs directory | `_redirects`, `tools/build-cloudflare-assets.js`, `wrangler.jsonc` |
| Pagina publica lipsa sau canonical route mismatch | fisierul HTML din tabelul de rute, `tools/build-cloudflare-assets.js`, `_redirects` |
| Titlu, description, canonical, `og:url` pe pagina statica | fisierul HTML al rutei afectate |
| Titlu, description, canonical, `og:url` pe pagini program | `config/seo-programs.json`, `tools/generate-program-pages.js`, output-ul rutei afectate |
| Titlu, description, canonical, `og:url` pe pagini programmatic/FAQ/CAEN/regional | `config/seo-programmatic-pages.json`, `tools/generate-programmatic-seo.js`, output-ul rutei afectate |
| Schema `Organization`, `LocalBusiness`, `BreadcrumbList`, `FAQPage`, `Article` | `tools/schema-helpers.js`, generatoarele SEO, fisierul HTML al rutei afectate |
| Breadcrumb vizual sau schema breadcrumb | fisierul HTML al rutei afectate, `tools/schema-helpers.js`, generatoarele SEO |
| Sitemap include/exclude/lastmod/canonical | `tools/generate-sitemap.js`, `tools/verify-sitemap.js`, `sitemap.xml` |
| Robots sau politica AI crawler | `robots.txt`, `llms.txt`, `_headers` |
| Noindex/cache/security headers | `_headers`, `tools/validate-cloudflare-deploy.js` |
| Articole blog generate | `tools/generate-seo-blog-article.js`, `config/seo-blog-article.example.json`, fisierul articolului HTML, `blog.json` |
| Liste/carduri blog | `blog/index.html`, `blog.json`, `index.html` daca articolul apare pe homepage |
| Surse oficiale si blocuri de validare | `official-guides.json`, `assets/official-guides.js`, `tools/official-sources.js`, `_headers` |
| Metadate editoriale comune | `config/editorial-pages.json`, `tools/editorial-metadata.js`, fisierul HTML al rutei afectate |
| Formulare publice/contact | `index.html`, `contact/index.html`, `contact.html`, `verify-and-fix.js`, `tests/faber-functional-checks.mjs` |
| Build/deploy Cloudflare | `package.json`, `wrangler.jsonc`, `tools/build-cloudflare-assets.js`, `_redirects`, `_headers` |
| Validari locale SEO | `scripts/verify-seo-integrity.js`, `tools/validate-seo-local.js`, `tools/verify-sitemap.js` |
| Audit GSC/program routes | `tools/audit-gsc-routes.js`, `tools/audit-cloudflare-program-routes.js`, rapoartele din `reports/` |

## Fisiere cel mai probabil atinse in prompturile urmatoare

- Pentru corectii de indexare/canonical/redirect: `_redirects`, `tools/build-cloudflare-assets.js`, `wrangler.jsonc`, HTML-ul rutei afectate.
- Pentru corectii de sitemap/robots/llms: `tools/generate-sitemap.js`, `tools/verify-sitemap.js`, `sitemap.xml`, `robots.txt`, `llms.txt`.
- Pentru corectii schema/meta in pagini generate: `tools/schema-helpers.js`, `tools/generate-program-pages.js`, `tools/generate-programmatic-seo.js`, `tools/generate-seo-hubs.js`, `tools/generate-seo-blog-article.js`, fisierele `config/*.json` relevante si output-ul HTML.
- Pentru corectii de continut static: fisierul HTML exact din tabelul `Route -> sursa continut`.
- Pentru formulare: doar `index.html`, `contact/index.html`, `contact.html` si testele/verificarile aferente, fara schimbare de structura fara cerinta explicita.

## Guardrail pentru modificarile urmatoare

Modificarile SEO trebuie sa fie facute in fisierul sursa real al rutei sau in generatorul/config-ul care produce acea ruta. Nu se modifica CSS, design, structura formularului sau logica de navigare fara cerinta explicita separata.
