# Baseline SEO și vizibilitate AI

- Commit auditat: `93c7c74147a28d1a069a6432681bdf6c41d52606`
- Branch de lucru: `codex/seo-ai-visibility-2026`
- Data auditului: 2026-07-10 (Europe/Bucharest)
- Fișiere urmărite în repository: 398
- Fișiere HTML: 172
- URL-uri canonice în `sitemap.xml`: 95

## Scripturi SEO existente

- `tools/audit-content-depth.js`
- `tools/audit-site-links.js`
- `tools/audit-gsc-routes.js`
- `tools/verify-sitemap.js`
- `tools/validate-seo-local.js`
- `tools/audit-structured-data.js`
- `tools/audit-indexing.js`
- `tools/audit-cloudflare-program-routes.js`
- `tools/generate-sitemap.js`
- `tools/generate-program-pages.js`
- `tools/generate-programmatic-seo.js`
- `tools/generate-seo-hubs.js`
- `tools/generate-seo-blog-article.js`
- `tools/schema-helpers.js`
- `tools/build-cloudflare-assets.js`
- `tools/validate-cloudflare-deploy.js`
- `scripts/verify-seo-integrity.js`
- `scripts/visual-integrity-check.js`
- `scripts/optimize-assets.js`

## Pagini indexabile

Sursa unică a inventarului este `sitemap.xml`. La baseline sunt indexabile următoarele 95 de URL-uri:

```text
/
/apeluri-gal
/consultanta-fonduri-europene
/digitalizare-imm
/dr12-afir
/dr14
/e-move
/fonduri-europene
/investitii-modernizarea-microintreprinderilor-apel-2
/pocidif-21
/pro-infra
/programul-tranzitie-justa
/programul-tranzitie-justa-intrebari-documente
/start-up-nation-2026
/blog
/despre-faber
/glosar-fonduri-europene
/metodologie-verificare-eligibilitate
/studii-de-caz-fonduri-europene
/surse-oficiale-fonduri-europene
/acte-necesare-fonduri-europene-nerambursabile
/afir
/afir-autoconsum-agroalimentar
/autoconsum-public-fotovoltaice-institutii-publice
/blog-afir-fotovoltaice-ferme-2026
/calculator-soc
/calendar-fonduri-europene
/cand-merita-consultant-fonduri-europene
/cat-costa-consultanta-fonduri-europene
/cat-costa-consultanta-fonduri-europene-ghid
/ce-acte-sunt-necesare-fonduri-europene
/cheltuieli-eligibile-digitalizare-imm
/cod-caen-start-up-nation-2026
/consultant-fonduri-europene-imm
/consultanta-afir
/consultanta-fonduri-europene-bucuresti
/consultanta-pnrr-digitalizare
/consultanta-start-up-nation-2026
/contact
/cum-alegi-consultant-fonduri-europene
/cum-alegi-programul-potrivit-fonduri-europene-2026
/cum-se-calculeaza-cofinantarea-fonduri-europene
/cum-se-verifica-eligibilitatea-fonduri-europene
/digitalizare-imm-erp-crm-cloud
/digitalizare-imm-pnrr
/dr-12-afir-instalarea-tinerilor-fermieri
/dr-14-afir-conditii-eligibilitate-greseli-frecvente
/dr12-vs-dr14
/dr14-afir-ferme-mici
/eligibilitate-fonduri-europene
/femeia-antreprenor-2026
/femeia-antreprenor-2026-conditii-idei-afaceri
/finantari-panouri-fotovoltaice
/firma-consultanta-fonduri-europene
/fondul-de-modernizare
/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum
/fondul-modernizare-energie-regenerabila-2026
/fonduri-europene-agricultura
/fonduri-europene-bucuresti
/fonduri-europene-digitalizare
/fonduri-europene-femei-antreprenor
/fonduri-europene-imm
/fonduri-europene-nerambursabile-2026
/fonduri-europene-nord-est
/fonduri-nerambursabile
/fonduri-pentru-ferme
/fonduri-pentru-utilaje-agricole
/fonduri-regionale
/gal-afir
/gdpr
/ghiduri
/granturi-digitalizare-imm
/greseli-fonduri-europene
/idei-afaceri-fonduri-europene
/instrumente
/intrebari-frecvente
/pnrr
/pnrr-digitalizare-imm-cheltuieli-eligibile
/politica-de-confidentialitate
/por-adr-nord-est
/resurse
/start-up-nation-2026-cheltuieli-eligibile
/start-up-nation-2026-conditii
/start-up-nation-2026-idei-afaceri
/start-up-nation-2026-plan-de-afaceri
/termeni-si-conditii
/verificare-eligibilitate-fonduri-europene
/webinarii
/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm
/intrebari/ce-documente-sunt-necesare-pentru-dr12
/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene
/fonduri-europene-caen/0111-culturi-cereale
/fonduri-europene-caen/4321-instalatii-electrice
/fonduri-europene-caen/5610-restaurante
/fonduri-europene-caen/6201-dezvoltare-software
```

## Pagini și resurse noindex

- Pagini tehnice: `/404`, `/admin/`.
- Resurse tehnice protejate prin `_headers`: `official-guides.json`, rapoarte, fișiere de configurare și alte artefacte care nu sunt pagini publice.
- Fallback-uri HTML legacy cu `noindex, follow`: `afir.html`, `blog.html`, `calendar-fonduri-europene.html`, `contact.html`, `consultanta-fonduri-europene.html`, `consultanta-afir.html`, `consultanta-pnrr-digitalizare.html`, `consultanta-start-up-nation.html`, `digitalizare-imm-pnrr.html`, `fonduri-europene.html`, `pnrr.html`, precum și celelalte fallback-uri `.html` generate pentru rutele canonice fără extensie.
- Pagini locale consolidate și păstrate numai ca alias: directoarele Iași, Suceava și Bacău pentru consultanță/fonduri, toate cu `noindex, follow` și redirect către `/fonduri-europene-nord-est`.
- Pagini editoriale retrase/consolidate: `/portofoliu`, `/studii-de-caz`, `/testimoniale`, fiecare exclusă din sitemap și păstrată ca fallback/noindex unde este cazul.

Niciun URL `noindex` nu apare în sitemap la baseline.

## Rute redirectate

Harta completă este în `_redirects`. La baseline conține redirecturi 301 directe, fără chain sau loop, pentru:

- normalizare globală: `/index.html`, `/:slug.html`, `/:slug/`, `/:slug/index.html` și variantele echivalente pe două sau trei niveluri;
- aliasuri AFIR: `/calculator-so-afir` → `/calculator-soc`, `/dr12-afir-tineri-fermieri` → `/dr12-afir`, `/dr14-afir` și `/dr-14-afir` → `/dr14`;
- aliasuri Start-Up Nation: `/start-up-nation`, `/consultanta-start-up-nation`, `/startup-nation-2026-conditii`, `/cod-caen-startup-nation`, `/cheltuieli-eligibile-startup-nation` și variantele lor → rutele canonice 2026;
- aliasuri locale Iași, Suceava și Bacău → `/fonduri-europene-nord-est`;
- `/pnrr-digitalizare-imm` → `/digitalizare-imm-pnrr`;
- typo-ul `/fonduri-europene-herambursabile-2026` → `/fonduri-europene-nerambursabile-2026`;
- `/autoconsum-publici` → `/autoconsum-public-fotovoltaice-institutii-publice`;
- aliasuri GAL/LEADER → `/gal-afir`;
- aliasuri e-MOVE → `/e-move`;
- aliasurile articolului AFIR fotovoltaice și ale întrebării AFIR → destinațiile canonice.

Auditul funcțional confirmă 0 chain-uri, 0 loop-uri și 0 linkuri interne către redirecturi.

## Fișiere legacy și artefacte

- Fallback-urile `.html` din rădăcină sunt fișiere deliberate, `noindex`, necesare pentru redirecturi și compatibilitate; nu sunt duplicate indexabile.
- Directoarele locale consolidate Iași, Suceava și Bacău sunt aliasuri deliberate cu redirect și `noindex`.
- Nu există fișiere `.bak`, `.old` sau `.tmp`.
- Nu există copia offline numită `FABER – Atelier de Consultanță _ Fonduri Europene.html` și nici un folder asociat.
- `testimoniale.html` și `testimoniale/index.html` sunt fallback-uri noindex, nu pagini publicate în sitemap.
- `dist/` este output de build și nu este sursa canonică editată.

## Erori și diferențe găsite

1. Lipsesc paginile canonice `/proiectare-fonduri-europene`, `/studiu-fezabilitate-fonduri-europene`, `/plan-de-afaceri-fonduri-europene`, `/management-proiecte-fonduri-europene` și `/resurse-utile`.
2. Homepage-ul nu are title-ul, H1-ul, textul introductiv și blocurile comerciale cerute de sprint.
3. Pagina `/consultanta-fonduri-europene` nu are title-ul, H1-ul și ordinea exactă a secțiunilor cerute.
4. `llms.txt` folosește structura anterioară și nu include clusterul nou de proiectare.
5. Nu există `feed.xml` și generator RSS.
6. Lipsesc `scripts/verify-canonical-consistency.js`, `scripts/verify-redirect-map.js`, `scripts/audit-search-intent.js` și `scripts/seo-release-check.js`.
7. Lipsesc `reports/search-intent-map.csv`, `reports/internal-link-map.csv`, `docs/offsite-seo-actions.md` și raportul final al sprintului.
8. Fișierul GSC `atelierdeconsultanta.ro-Coverage-2026-07-09.xlsx` nu există în repository; auditul continuă pe rapoartele GSC existente.

## Cerințe deja implementate și care nu trebuie refăcute distructiv

- `robots.txt` este permisiv pentru conținutul public, blochează `/admin/` și declară sitemapul.
- Sitemapul conține 95 de URL-uri HTTPS canonice, indexabile și fără extensie; validarea curentă este PASS.
- Canonicalele, `og:url`, rutele fizice și linkurile interne existente sunt validate de auditurile locale.
- `_redirects` normalizează formele `.html`, `/index.html` și slash final într-un singur hop.
- Pagina principală, paginile comerciale și paginile de program au deja schema de bază, FAQ vizibil unde se publică `FAQPage` și o entitate FABER coerentă.
- Programul Tranziție Justă și pagina suport de întrebări/documente există și sunt legate reciproc.
- Clusterele AFIR, GAL/LEADER, PNRR, Start-Up Nation, Femeia Antreprenor, energie și regional sunt deja consolidate în mare parte.
- Link audit: 195 fișiere, 4.297 linkuri locale, 0 ținte lipsă, 0 ancore lipsă și 0 probleme de redirect.
- SEO local: PASS pentru 95 URL-uri și 3.604 linkuri interne.
- Date structurate: 172 fișiere, 113 cu schema, 0 probleme detectate.
- Indexare locală: PASS pentru toate cele 95 URL-uri din sitemap.
- Endpointul formularului, newsletterul, CTA-urile prudente, headerul, footerul, paleta și fonturile trebuie păstrate.
