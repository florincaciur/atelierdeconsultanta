# Raport GSC, UI și copy - 2026-05-27

## 1. Fișiere modificate

- `_redirects`
- `acte-necesare-fonduri-europene-nerambursabile.html`
- `acte-necesare-fonduri-europene-nerambursabile/index.html`
- `afir-autoconsum-agroalimentar.html`
- `afir-autoconsum-agroalimentar/index.html`
- `afir/index.html`
- `apeluri-gal/index.html`
- `autoconsum-public-fotovoltaice-institutii-publice.html`
- `autoconsum-public-fotovoltaice-institutii-publice/index.html`
- `banners.json`
- `calendar-fonduri-europene/index.html`
- `cat-costa-consultanta-fonduri-europene/index.html`
- `cod-caen-start-up-nation-2026/index.html`
- `config/seo-programs.json`
- `consultant-fonduri-europene-imm/index.html`
- `consultanta-afir/index.html`
- `consultanta-fonduri-europene/index.html`
- `consultanta-pnrr-digitalizare/index.html`
- `consultanta-start-up-nation-2026/index.html`
- `cum-alegi-consultant-fonduri-europene/index.html`
- `digitalizare-imm-pnrr/index.html`
- `digitalizare-imm.html`
- `digitalizare-imm/index.html`
- `dr12-afir.html`
- `dr12-afir/index.html`
- `dr14-afir-ferme-mici.html`
- `dr14-afir-ferme-mici/index.html`
- `dr14.html`
- `dr14/index.html`
- `e-move/index.html`
- `eligibilitate-fonduri-europene/index.html`
- `femeia-antreprenor-2026.html`
- `femeia-antreprenor-2026/index.html`
- `finantari-panouri-fotovoltaice/index.html`
- `firma-consultanta-fonduri-europene/index.html`
- `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html`
- `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum/index.html`
- `fondul-de-modernizare/index.html`
- `fondul-modernizare-energie-regenerabila-2026.html`
- `fondul-modernizare-energie-regenerabila-2026/index.html`
- `fonduri-europene-agricultura/index.html`
- `fonduri-europene-digitalizare/index.html`
- `fonduri-europene-femei-antreprenor/index.html`
- `fonduri-europene-imm/index.html`
- `fonduri-europene-nerambursabile-2026/index.html`
- `fonduri-europene/index.html`
- `fonduri-nerambursabile/index.html`
- `fonduri-pentru-ferme/index.html`
- `fonduri-pentru-utilaje-agricole/index.html`
- `gal-afir/index.html`
- `ghiduri/index.html`
- `granturi-digitalizare-imm/index.html`
- `greseli-fonduri-europene/index.html`
- `index.html`
- `instrumente/index.html`
- `intrebari-frecvente/index.html`
- `investitii-modernizarea-microintreprinderilor-apel-2.html`
- `investitii-modernizarea-microintreprinderilor-apel-2/index.html`
- `pnrr/index.html`
- `por-adr-nord-est.html`
- `por-adr-nord-est/index.html`
- `portofoliu/index.html`
- `pro-infra.html`
- `pro-infra/index.html`
- `reports/gsc-ui-copy-fix-2026-05-27.md`
- `reports/seo-integrity-report.json`
- `resurse/index.html`
- `sitemap.xml`
- `start-up-nation-2026-cheltuieli-eligibile/index.html`
- `start-up-nation-2026-conditii/index.html`
- `start-up-nation-2026-idei-afaceri/index.html`
- `start-up-nation-2026-plan-de-afaceri/index.html`
- `start-up-nation-2026.html`
- `start-up-nation-2026/index.html`
- `studii-de-caz/index.html`
- `testimoniale/index.html`
- `tests/faber-functional-checks.mjs`
- `tools/audit-gsc-routes.js`
- `tools/build-cloudflare-assets.js`
- `tools/generate-program-pages.js`
- `tools/generate-sitemap.js`
- `tools/schema-helpers.js`
- `verificare-eligibilitate-fonduri-europene/index.html`
- `webinarii/index.html`
- `wrangler.jsonc`

## 2. Probleme GSC remediate

- Convenția canonical a fost uniformizată: HTTPS, domeniul `https://atelierdeconsultanta.ro`, fără `.html`, fără trailing slash pentru paginile normale și homepage păstrat ca `/`.
- `wrangler.jsonc` folosește acum `html_handling: drop-trailing-slash`, cu `not_found_handling: 404-page` păstrat.
- `_redirects` a fost curățat pentru rutele critice, cu reguli 301 explicite pentru `.html`, `/`, `/index.html` și variante istorice.
- `politica-de-confidentialitate` este indexabilă prin canonical-ul `https://atelierdeconsultanta.ro/politica-de-confidentialitate`; varianta HTTP `.html` redirecționează la canonical.
- Sitemap-ul include numai URL-uri canonical indexabile și exclude `.html`, `/index.html`, query string-uri, surse de redirect, pagini `noindex` și alternate.
- Noindex-ul intenționat pentru `/404`, `/404.html` și `/ro/*` a rămas neafectat.

## 3. URL-uri verificate și verdict final

| URL verificat | Verdict |
| --- | --- |
| `https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/consultanta-start-up-nation/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/fonduri-europene-imm/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/fonduri-europene/` | `PASS_REDIRECT_TO_CANONICAL` |
| `http://atelierdeconsultanta.ro/politica-de-confidentialitate.html` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/dr12-vs-dr14` | `PASS_CANONICAL_200` |
| `https://atelierdeconsultanta.ro/dr14-afir-ferme-mici` | `PASS_CANONICAL_200` |
| `https://atelierdeconsultanta.ro/afir` | `PASS_CANONICAL_200` |
| `https://atelierdeconsultanta.ro/ghiduri` | `PASS_CANONICAL_200` |
| `https://atelierdeconsultanta.ro/fonduri-nerambursabile` | `PASS_CANONICAL_200` |
| `https://atelierdeconsultanta.ro/blog?post=blog-1` | `PASS_ALTERNATE_CANONICAL` |
| `http://atelierdeconsultanta.ro/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-afir/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software/` | `PASS_REDIRECT_TO_CANONICAL` |
| `https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale/` | `PASS_REDIRECT_TO_CANONICAL` |

## 4. Modificări UI - „CUM LUCRĂM”

- Label-ul „CUM LUCRĂM” are acum subliniere discretă, aliniată și integrată în stilul premium existent.
- Cardurile statistice au înălțime și ritm vizual stabil pe desktop și mobil.
- Cele două carduri cerute au fost actualizate:
  - `Peste 150` / `proiecte finanțate`
  - `250 milioane euro` / `fonduri absorbite pentru beneficiari`
- A fost verificat local că toate cele patru carduri au aceeași înălțime și că textele nu produc overflow.

## 5. Modificări UI - „Blog & Ghiduri Utile”

- Carousel-ul și cardurile de blog au fost ajustate pentru a elimina spațiul mort de sub carduri.
- Cardurile folosesc layout coerent, cu imagine stabilă, conținut pe coloană și CTA aliniat.
- Wrapper-ul carousel-ului nu mai forțează înălțimi inutile, iar butoanele de navigare rămân funcționale.
- Verificarea locală cu Playwright a confirmat carduri aliniate, fără slide-uri goale vizibile și fără goluri excesive.

## 6. Banners hero pentru paginile de program

- Asocierea dintre bannerele din caruselul homepage și paginile de program a fost centralizată în `banners.json` și consumată de `tools/generate-program-pages.js`.
- Generatorul construiește mapping-ul pe baza `ctaLink` + `image`, apoi îl folosește ca sursă pentru hero-ul paginii de program.
- Pentru programele relevante sunt folosite imaginile existente: agricultură, business, digital, solar sau local, în funcție de bannerul asociat din homepage.
- Paginile program generate păstrează overlay-ul și contrastul pentru lizibilitate, fără fundaluri generice improvizate.

## 7. Diacritice și consistență editorială

- Generatorul de pagini normalizează acum expresiile frecvente fără diacritice în text, meta, atribute accesibile și descrieri.
- Au fost uniformizate formulări precum `consultanță`, `finanțare`, `finanțări nerambursabile`, `eligibilitate`, `cheltuieli eligibile`, `proiecte finanțate`.
- Schema de brand folosește denumiri și descrieri cu diacritice.
- Paginile hub și program consolidate au titluri, descrieri, H1-uri și linkuri interne mai clare.

## 8. Comenzi rulate

| Comandă | Rezultat |
| --- | --- |
| `npm run build` | PASS - sitemap generat cu 86 URL-uri canonical, assets Cloudflare construite |
| `npm run generate:sitemap` | PASS - 86 URL-uri canonical |
| `npm run verify:seo` | PASS - 167 fișiere verificate, 167 pass, 0 fail |
| `npm run validate:cloudflare` | PASS - 321 reguli redirect, validare Cloudflare trecută |
| `npm run audit:gsc-routes` | PASS - toate URL-urile cerute au verdict acceptat |
| `npm run test:functional` | PASS - verificările funcționale au trecut |
| verificare Playwright locală pe `dist` | PASS - carduri, underline și carousel validate vizual/DOM |

## 9. Riscuri rămase

- Nu au rămas blocaje tehnice cunoscute în build, sitemap, redirecturi, audit GSC sau testele funcționale.
- Articolele istorice scrise manual pot fi rafinate editorial în continuare în iterații separate, dar paginile generate și rutele critice au fost normalizate și validate.
