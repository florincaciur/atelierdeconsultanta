# Baseline de arhitectură FABER

Data inspecției: **21 august 2026**
Task: **00 — baseline complet și freeze de arhitectură**
Commit inspectat înainte de modificări: `1e0bed69eb1f8f7bbdaf2321d37066d7b1fcbe51` (`main`, `origin/main`, `origin/master` după `git fetch origin --prune`)

Actualizare controlată: **22 august 2026, Task 03 — registru unic pentru programele de finanțare**. Secțiunea „Arhitectura după Task 03” documentează diferențele față de baseline-ul istoric.

Acest document descrie starea observată, nu propune o migrare. În Task 00 nu s-au schimbat rute, conținut public, statusuri, componente, stiluri, build sau deployment.

## Rezumat executiv

FABER este un site static HTML/CSS/JavaScript, fără framework frontend și fără router de aplicație. Node.js și npm sunt folosite ca sistem de generare, sincronizare, audit și build. Conținutul critic al celor **104 URL-uri canonice** este pre-randat în fișiere HTML; JavaScript adaugă interacțiuni, formular, calculator, carusele și unele îmbunătățiri după încărcare.

Arhitectura are un registry declarat drept sursă unică pentru programe, dar păstrează multe artefacte materializate și surse paralele. La baseline există **25 programe**, **62 definiții de pagină**, **23 bannere**, **34 surse oficiale**, **189 fișiere HTML urmărite**, **54 perechi `slug.html` + `slug/index.html`**, dintre care **51 diferă byte-for-byte**, și **136 reguli de redirect**. Build-ul Cloudflare sincronizează variantele publicate, însă diferențele din surse rămân un risc de regresie.

## Toolchain

| Element | Stare observată |
|---|---|
| Framework | Niciun framework frontend detectat; HTML/CSS/JavaScript static |
| Runtime de build | Node.js; CI declară Node `22`, mediul local a rulat Node `v24.14.1` |
| Package manager | npm; `package-lock.json` lockfile v3; npm local `11.11.0` |
| Manifest | `package.json` fără câmp `version` și fără `engines` |
| Dependență runtime | `@microsoft/clarity` `^1.0.2` |
| Dependențe de dezvoltare | Cheerio, Clean CSS, ExcelJS, Playwright, Sharp, Terser |
| Build | `npm run build` → `generate:2026-program-pages` → `tools/run-build.js` → `build:pipeline` → `tools/build-cloudflare-assets.js` |
| Output | `dist/`, recreat integral de `tools/build-cloudflare-assets.js` |
| Bundler | Nu există bundler general; unele active au variante `.min.*`, iar build-ul copiază activele publice |
| Lockfile alternativ | Nu există pnpm/yarn/bun lockfile |

Comanda de build este un pipeline write-heavy: validează registre, rescrie/sincronizează HTML și JSON, generează sitemap/feed/rapoarte, rulează contracte și apoi construiește `dist/`. Nu trebuie tratată ca o comandă pur read-only.

## Arhitectura de routing

Nu există router client-side sau server-side. Ruta este determinată de fișierul static și de regulile Cloudflare.

- Homepage: `/` → `index.html`.
- Rute curate: de regulă `/slug`, materializate prin `slug/index.html`, `slug.html` sau ambele.
- `wrangler.jsonc` folosește `html_handling: "drop-trailing-slash"` și `not_found_handling: "404-page"`.
- Forma canonică folosită de sitemap și metadata este HTTPS, host apex, fără `.html` și fără slash final, cu excepția homepage-ului `/`.
- `tools/generate-sitemap.js` a identificat 104 rute canonice: 26 programe, 30 ghiduri/conținut editorial și 48 pagini core.
- `_redirects` conține 136 reguli. Workerul de domeniu mai normalizează HTTP, `www`, query-ul istoric de căutare, query-urile de contact și rutele retrase.
- `404.html` este pagina de eroare; are `noindex, nofollow`, canonical `/404`, iar `_headers` repetă protecția de indexare.

### Variante fizice ale aceleiași rute

Există 54 perechi urmărite `slug.html` + `slug/index.html`; numai 3 sunt identice și 51 diferă. Selecția sursei canonice este codificată în mai multe locuri:

- `tools/build-cloudflare-assets.js`: `CANONICAL_ROOT_HTML_ROUTES`, `CANONICAL_DIRECTORY_HTML_ROUTES`, `CANONICAL_INDEX_SOURCE_OVERRIDES`;
- `tools/generate-program-pages.js`: `CANONICAL_DIRECTORY_ONLY_SLUGS`;
- `tools/structured-data-utils.js`: un alt `CANONICAL_ROOT_HTML_ROUTES`.

Build-ul copiază sursa aleasă peste aliasurile existente din `dist/`, ceea ce protejează output-ul Cloudflare, dar nu elimină riscul ca o unealtă, un test sau un alt origin să citească varianta greșită.

## Arhitectura de rendering

| Mod | Utilizare |
|---|---|
| SSG/prerender | Modul principal. Pagini, metadata, H1, corp editorial, breadcrumbs, FAQ și JSON-LD sunt scrise în HTML înainte de deploy. |
| CSR | Interacțiuni homepage/carusele, navigație, calculator SO, validare și submit formular, analytics, filtrare huburi, layout long-form. |
| Date încărcate la runtime | `/blog.json` pe hubul `/blog` și `/official-guides.json` pentru îmbunătățirea CTA-urilor către ghiduri. |
| SSR | Nu există. |
| Server/edge logic | Workerul Cloudflare face redirecturi, headers și API-urile de contact/lead; nu randează paginile editoriale. |

Conținutul critic pentru indexare este prezent în HTML-ul inițial al rutelor canonice. Contractul de structured data a trecut pentru toate cele 104 URL-uri, iar contractul tehnic a raportat zero rute orfane și zero linkuri locale rupte/redirectate în inventarul său. Hubul de blog își hidratează lista/detaliul query din `blog.json`; articolele canonice importante există însă și ca pagini statice separate.

## Arhitectura datelor

| Domeniu | Sursă/artefact | Rol și cardinalitate la baseline |
|---|---|---|
| Registry programe | `config/seo-programs.json#programs` | Sursă declarată; 25 programe publice |
| Definiții pagini | `config/seo-programs.json#pages` | 62 pagini: 18 program, 21 hub, 9 resource, 3 trust, 7 service, 1 tool, 3 article |
| Aprobare status | `config/program-status-approvals.json` | 4 programe cu aprobare nominală: DR12, DR14, PRO INFRA, Digitalizare IMM |
| Surse oficiale | `official-guides.json` | 34 intrări; artefact sincronizat, consumat și la runtime |
| Bannere | `banners.json` | 23 bannere active; toate declară `sourceOfTruth=config/seo-programs.json#programs` |
| Homepage programe | `config/seo-programs.json#programs[*].presentation` | Includerea și ordinea celor 23 de programe provin din registry; `homepage-programs.json` păstrează numai comportamentul componentei |
| Familii/catalog | `config/program-family-hubs.json` | 5 huburi și taxonomii pentru solicitant/regiune/investiție |
| Guvernanță editorială | `config/editorial-governance.json` | 38 înregistrări: 27 publice, 11 `pending_validation` |
| Metadata editorială veche | `config/editorial-pages.json` | 6 înregistrări; paralelă cu guvernanța nouă |
| Blog | `blog.json` | 37 postări |
| Metadata/schema | `tools/schema-helpers.js`, `tools/structured-data-utils.js`, config-urile SEO | Generează canonical, metadata și JSON-LD |
| Breadcrumbs | `config/breadcrumbs.json`, `tools/breadcrumb-registry.js` | Registry + fallback semantic pe rută |
| FAQ/AEO | FAQ din config/page content, `config/aeo-question-blocks.json` | FAQ vizibil sincronizat cu FAQPage unde se aplică |
| Identitate juridică | `config/legal-identity.json` | Config aprobat, 16 câmpuri și suprafețe coordonate |
| About/trust | `config/about-faber-governance.json` | Blochează echipă, cazuri, afilieri și claims fără dovezi |
| Calculator SO | `config/calculator-so-methodology.json` | Metodă `FABER-SO-1.0`, 46 coeficienți, sursă AFIR și hash document |
| Analytics/funnel | `config/funnel-analytics.json` | Taxonomie de evenimente și câmpuri permise/interzise |
| Contact | `config/contact-triage.json` și schema payload | Endpoint, transport, anti-spam, privacy și atribuire |

### Taxonomia curentă de status

Registry-ul folosește șase valori operaționale:

| Status curent | Număr programe | Observație |
|---|---:|---|
| `calendar_estimativ` | 8 | Reunește programe anunțate, în implementare și calendare variabile |
| `consultare_publica` | 2 | Eticheta vizibilă poate preciza că perioada de consultare s-a închis |
| `ghid_aprobat_nedeschis` | 7 | Reunește ghid/schemă aprobate și sesiuni anunțate, fără depunere activă |
| `apel_deschis` | 1 | Depunere activă conform registry-ului verificat la 18.08.2026 |
| `apel_inchis` | 7 | Depunere închisă/finalizată |
| `arhivat` | 0 | Permis de cod, nefolosit în cele 25 de programe |

Taxonomia este mai puțin granulară decât taxonomia obligatorie pentru remediere. Etichetele compensează parțial, dar o mapare viitoare trebuie să separe clar `ANUNȚAT`, `ÎN PREGĂTIRE`, `GHID FINAL PUBLICAT`, `SCHEMĂ APROBATĂ`, `APEL PROGRAMAT`, `SUSPENDAT`, `ANULAT`, `FINALIZAT` și `STATUS NECONFIRMAT`, fără a transforma schema/ghidul în apel deschis.

## Mecanisme funcționale inventariate

| Suprafață | Mecanism actual |
|---|---|
| Programe de finanțare | Registry + generatoare/sincronizatoare Node + HTML materializat |
| Statusuri | Registry, approval registry, surse oficiale, bannere, header, homepage și atribute HTML sincronizate |
| Homepage | `index.html` + config-uri homepage + `sync-homepage-*` |
| Carusel/bannere | 23 slide-uri pre-randate din registry și `banners.json`; JS doar pentru interacțiune, fără autorotire |
| Catalog | Hubul `/fonduri-europene` și homepage explorer, cu filtre client-side |
| Family/category pages | 5 familii în `program-family-hubs.json`, reutilizând URL-uri canonice existente |
| Metadata/canonical | `schema-helpers.js`, generator pagini, sincronizatoare și validator SEO |
| Structured data | `sync-structured-data.js`, `schema-helpers.js`, `structured-data-utils.js` |
| Breadcrumbs | `breadcrumbs.json`, registry și sync pe HTML |
| FAQ | Conținut vizibil în HTML; FAQPage generat numai din întrebări/răspunsuri vizibile |
| Sitemap | Index + trei sitemaps generate determinist din HTML, canonical, robots/headers și guvernanță |
| Robots | `robots.txt`, API disallow, crawleri publici allow, sitemap declarat |
| Redirects | `_redirects` + `cloudflare/domain-seo-redirects.mjs` |
| 404 | `404.html` + `not_found_handling: 404-page` |
| Formulare | Formular canonical în `/contact` → `/api/contact-triage`; formular legacy FormSubmit în `/idei-afaceri-fonduri-europene` |
| Calculator SO | `calculator-soc.html` + config și active de metodologie; calcul exclusiv client-side |
| Legal | `termeni-si-conditii.html`, `politica-de-confidentialitate.html`, `gdpr.html`, guvernate de `legal-identity.json` |
| Analytics | `assets/analytics-events.js`, `lead-attribution.js`, `dataLayer` + Microsoft Clarity |
| Cookies/consent | Politica menționează cookies și banner, dar nu a fost găsit un CMP/banner/gate de consimțământ în cod |
| Cloudflare | Worker cu assets `dist/` + worker de domeniu separat pentru redirect/API |

## Metadata și structured data

- Canonicalele, URL-urile absolute și entitățile sunt centralizate parțial în `tools/schema-helpers.js`.
- `tools/structured-data-utils.js` selectează fișierul fizic pentru o rută și extrage FAQ vizibil; conținutul ascuns nu este acceptat ca sursă FAQ.
- `tools/sync-structured-data.js` sincronizează grafurile JSON-LD în HTML.
- Tipurile declarate în cele 62 definiții de pagină sunt: 18 `GovernmentService`, 27 `WebPage`, 10 `Service`, 6 `CollectionPage`, 1 `WebApplication`.
- Contractul de entitate a trecut pe 104 URL-uri: o singură identitate FABER, 31 suprafețe Article și un WebApplication.
- Breadcrumb-urile sunt HTML vizibil și `BreadcrumbList`; FAQ este HTML vizibil și `FAQPage` numai unde există paritate.
- Metadata editorială poate proveni din `seo-programs.json`, `editorial-pages.json` și `editorial-governance.json`; ultima este autoritatea pentru `dateModified` numai când înregistrarea este publică și completă.

## Sitemap, robots, redirects și 404

- `sitemap.xml` este un sitemap index pentru `sitemap-programs.xml`, `sitemap-guides.xml`, `sitemap-core.xml`.
- Generatorul include numai HTML indexabil, self-canonical, care nu este redirect source și nu are `noindex` în meta/header.
- `lastmod` este emis numai din `lastMeaningfulUpdate` verificat al unei înregistrări editoriale complete; la baseline, 26/104 URL-uri au `lastmod`.
- `robots.txt` permite crawl public și blochează `/api`; `/admin` rămâne crawlable ca Google să poată vedea `noindex` din HTML/header.
- `_headers` setează noindex pentru 404/admin/active tehnice și cache pentru active; `official-guides.json` și `release.json` sunt JSON noindex.
- `_redirects` și workerul sunt validate pentru cicluri/lanțuri și normalizare într-un singur hop.
- Riscul principal este că selecția sursei fizice și listele de rute canonice sunt întreținute în mai multe scripturi.

## Formulare, analytics și cookies

### Formular canonical

`/contact` conține un formular progresiv în două etape. Submit-ul JS și no-JS ajunge la `/api/contact-triage`. Workerul validează metoda, originea, dimensiunea, timpul minim, honeypot-ul și schema, apoi forwardează către URL-ul păstrat în secretul Cloudflare `CONTACT_FORM_FORWARD_URL`. PII nu este trimis în analytics; `lead_id` este corelarea first-party.

### Formular legacy

`/idei-afaceri-fonduri-europene` trimite direct către `https://formsubmit.co/atelier.consultanta@gmail.com` și are un checkbox propriu. Acesta este un al doilea transport public, în afara adaptorului și a schemei canonical contact.

### Analytics

`assets/analytics-events.js` inițializează `dataLayer`, încarcă Microsoft Clarity (`wnvzyco6rq`) după load/idle sau prima interacțiune și emite taxonomia din `funnel-analytics.json`. Nu a fost găsit un API de consimțământ, un CMP sau o condiție care să blocheze Clarity până la consimțământ. Politica publică spune că analytics neesențial necesită consimțământ acolo unde legea îl cere și indică un banner de cookies. Neconcordanța este în matrice și necesită decizie juridică/operațională înaintea unei modificări.

## Calculator SO

Ruta canonică este `/calculator-soc`; `calculator-so-afir.html` este o suprafață legacy. Config-ul `calculator-so-methodology.json` definește formula, rotunjirea, sursa AFIR, versiunea și hash-ul documentului. `sync-calculator-so-methodology.js` materializează metoda în HTML/JS/schema, iar contractul verifică 46 coeficienți, trei exemple și WebApplication. Calculul rulează local în browser și nu este dovadă de eligibilitate.

## Arhitectura de deployment

### Worker cu active statice

- `wrangler.jsonc` definește proiectul/workerul `atelierdeconsultanta` și `assets.directory = "./dist"`.
- Build-ul Cloudflare rulează `gate:p0:deploy-guard`, construiește activele și validează output-ul.
- `tools/build-cloudflare-assets.js` recreează `dist/`, exclude cod/config/rapoarte, sincronizează aliasurile canonice și scrie `dist/release.json` cu SHA și timestamp.
- `/release.json` este mecanismul verificabil pentru asocierea exactă deploy–commit.

### Worker de domeniu

- `wrangler.redirects.jsonc` definește `atelierdeconsultanta-domain-seo` pe `atelierdeconsultanta.ro/*` și `www.atelierdeconsultanta.ro/*`.
- `cloudflare/domain-seo-redirects.mjs` normalizează host/protocol/rute, adaugă HSTS/security headers, servește API-ul de contact și proxy-uiește restul cererilor la origin.

### Automatizare observată

Nu există workflow GitHub versionat care să execute `wrangler deploy` la push. În schimb, `production-live-verification.yml` și `indexnow.yml` pornesc pe `main`; primul așteaptă ca `/release.json` să indice exact `github.sha`, iar al doilea notifică IndexNow după ce URL-urile sunt accesibile. Acest model indică o integrare Git→Cloudflare configurată extern, cu build-ul din `wrangler.jsonc`.

La baseline, probele live au confirmat:

- `https://atelierdeconsultanta.ro/` → 200, `Server: cloudflare`;
- `/release.json` → 200 și commit `1e0bed69eb1f8f7bbdaf2321d37066d7b1fcbe51`;
- `/contact` și `/robots.txt` → 200;
- `http://atelierdeconsultanta.ro/` → 301 către HTTPS apex;
- `https://www.atelierdeconsultanta.ro/` → 301 către HTTPS apex.

Enumerarea read-only prin Wrangler nu a putut fi finalizată: `npx` a eșuat cu `ECONNRESET` la registry. Nu există dovadă de dashboard/API în acest mediu; dovada live este `release.json` și răspunsul rutelor.

## Arhitectura testelor și starea baseline

Nu există script generic `test`, `lint` sau `typecheck`. Testarea este compusă din scripturi `test:*`, validatoare, audituri și contracte Node/Playwright. CI versionat include:

- P0 release gate pentru PR-uri către `main`/`master` și execuții manuale staging/production;
- verificarea commitului live după push pe `main`;
- audit săptămânal sitemap/llms;
- IndexNow după push pe `main`.

### Contracte `tests/*.mjs` înainte de documentare

Au fost rulate toate cele 44 de contracte: **39 PASS, 5 FAIL**.

| Contract eșuat | Eșec observat |
|---|---|
| `dr14-final-page-contract.mjs` | data actuală `2026-08-18`, așteptare stale `2026-08-15` |
| `editorial-governance-contract.mjs` | filtrul CMS a întors 0 verificări expirate, testul așteaptă 10 |
| `faber-functional-checks.mjs` | sitemap actual 104 URL-uri, testul așteaptă 91 |
| `long-form-layout-contract.mjs` | DR18 actual 2.119 cuvinte, testul așteaptă 2.054 |
| `program-page-template-contract.mjs` | schema Article și răspunsul vizibil AFIR autoconsum nu sunt identice |

Contractele au regenerat sitemap în timpul testării, dar nu au produs diff în această rulare. Acest side effect trebuie păstrat în vedere.

### Validări suplimentare înainte de documentare

| Comandă | Rezultat baseline |
|---|---|
| `npm run validate:program-registry` | PASS — 25 programe publice |
| `npm run validate:program-statuses` | PASS — 4 aprobate |
| `npm run validate:legal-identity` | PASS — publicare aprobată |
| `npm run validate:about-faber` | PASS — 4 grupe rămân private |
| `npm run validate:contact-triage` | PASS structural |
| `npm run verify:sitemap` | PASS — 104 URL-uri, 26 lastmod |
| `npm run check:copy` | FAIL — 131 fișiere raportate |
| `npm run validate:editorial-governance` | FAIL — raportul de expirare nesincronizat |
| `npm run validate:cloudflare` | FAIL — `dist/` era stale (SHA `ad776ea…`) și avea 17 nepotriviri |
| `npm run verify:seo-local` | FAIL — 6 linkuri interne către rute redirectate |

Aceste eșecuri sunt preexistente Task 00. `dist/` este un artefact de build și trebuie evaluat din nou după build, nu corectat manual.

## Design invariants

Sursa declarată este `config/design-system.json` (`p1.07-v1`), cu rollout explicit pe `/`, `/contact`, `/afir-autoconsum-agroalimentar`. În HTML au fost găsite cinci suprafețe care includ stylesheet-ul, deci rollout-ul și inventarul trebuie sincronizate înaintea extinderii.

### Fonturi și tipografie

- Font principal: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif`.
- Body design-system: 17 px, line-height 1.65, măsură maximă 68ch.
- H1: `clamp(2.35rem, 5vw, 3.5rem)`; H2: `clamp(1.8rem, 3.2vw, 2.5rem)`; H3: `clamp(1.2rem, 1.7vw, 1.45rem)`.
- Familia `program-showcase-2026` folosește deliberat Georgia/Times pentru headings și Inter pentru corp; aceasta este o variantă existentă, nu un motiv de redesign.

### Culori

- Fundal `#f6f3ed`, suprafață `#ffffff`, suprafață muted `#eef2f6`.
- Text `#18243a`, text secundar `#536176`, border `#7b899c`, navy `#0d1f3c`.
- Accent `#b84716`, accent hover `#91360f`, focus `#0b63ce`, focus pe dark `#ffd166`.
- Success `#12603a`/`#e7f5ed`, warning `#6b4300`/`#fff2cc`, closed `#455163`/`#edf0f4`, error `#a61b1b`/`#feecec`.

### Spacing, raze, umbre și containere

- Scala spacing: `.25rem`, `.5rem`, `.75rem`, `1rem`, `1.5rem`, `2rem`, `3rem`, `4rem`, `6rem`.
- Raze: `.5rem`, `.75rem`, `1.125rem`, pill `999px`.
- Containere: text 68ch, content 47.5rem, wide 73.75rem, full 80rem.
- Umbre: small `0 2px 12px`, medium `0 12px 32px`, large `0 24px 56px`, toate pe navy transparent.

### Breakpoints și responsive

Nu există o singură scară globală. Breakpointurile dominante sunt 480, 560/600/640/700/720/760/768, 820/840/900/960, 1023/1024 și 1179/1180 px. Headerul trece la mobil sub 1180 px. Matricea a11y declară viewporturi 320, 360, 390, 768, 1024 și 1366 px, resize text 200%, target minim 24 px și preferat mobil 44 px. `prefers-reduced-motion` este tratat în componentele principale.

### Header, footer, cards, bannere și CTA

- Headerul este generat din `config/main-navigation.json` în `partials/global-header.html`, apoi sincronizat în pagini; breakpoint desktop 1180 px.
- Footerul este materializat în fiecare pagină, nu are un partial unic; datele de contact sunt sincronizate între markerele canonical-contact.
- CTA principal: accent portocaliu, text alb, focus vizibil, target cel puțin 44–50 px în componentele principale.
- Cardurile: suprafață albă, border, rază mare, umbră mică și lift de 2 px; stările nu depind numai de culoare.
- Banner/program slide: navy/gradient, imagine din `assets/hero`, badge status, titlu, rezumat, CTA; homepage nu autorotește.

### Template pagină program

Nu există încă un singur template universal. Sunt trei straturi:

1. `tools/generate-program-pages.js` generează majoritatea paginilor din `seo-programs.json`, cu renderere speciale pe familie/rută;
2. `tools/generate-2026-program-pages.js` conține `PAGE_CONTENT` hardcodat pentru patru pagini showcase;
3. `config/program-page-template.json` + `sync-program-page-template.js` aplică pilotul `p1_11` numai pe `/afir-autoconsum-agroalimentar`.

Invarianta este păstrarea structurii semantice: breadcrumb, H1 unic, status factual, answer-first, eligibilitate, finanțare/riscuri, documente/pași, surse, FAQ vizibil și CTA contextual.

## Date hardcodate sau duplicate

1. Statusurile sunt materializate în registry, approval registry, `official-guides.json`, `banners.json`, `partials/global-header.html`, homepage, pagini și `llms.txt`.
2. În 184 fișiere HTML există 4.183 apariții `data-program-status` și 4.236 apariții `data-program-id`, în principal din headerul global repetat.
3. Există 54 perechi fizice ale aceleiași rute; 51 au conținut diferit înainte ca build-ul să le sincronizeze în `dist/`.
4. Listele care decid sursa canonică sunt duplicate în cel puțin trei unelte.
5. `tools/generate-2026-program-pages.js` păstrează text, valori și FAQ în `PAGE_CONTENT`, în paralel cu registry-ul factual.
6. `tools/generate-program-pages.js` păstrează keyword maps și renderere speciale cu conținut/rute explicite, pe lângă `seo-programs.json`.
7. `editorial-pages.json` și `editorial-governance.json` pot descrie aceeași pagină; structured-data-utils acordă prioritate guvernanței complete.
8. Footerul și multe linkuri/contacte sunt duplicate în HTML; sync-ul reduce, dar nu elimină, riscul.
9. README descrie încă bannere editabile direct/runtime și GitHub Pages, în timp ce adminul și build-ul actual le tratează drept artefact generat, iar producția expune `release.json` Cloudflare.

## Candidați source-of-truth

| Domeniu | Candidat de păstrat |
|---|---|
| Identitate/fapte/status program | `config/seo-programs.json#programs`; taxonomia definește vocabularul, iar approval registry păstrează dovada aprobării |
| Conținut pagină | `config/seo-programs.json#pages`, până la o consolidare explicită a showcase/pilot |
| Surse oficiale publice | Derivate din registry în `official-guides.json`; registry-ul rămâne autoritatea factuală |
| Homepage/carousel/nav | `program.presentation`; config-urile componentelor păstrează numai comportament și copy de componentă |
| Familie/catalog | `program.discovery`; `program-family-hubs.json` păstrează taxonomia și conținutul huburilor, nu liste de programe |
| Metadata/entități | `schema-helpers.js` + `editorial-governance.json` pentru freshness |
| Canonical inventory | `collectSiteState()` din `generate-sitemap.js`, nu liste manuale noi |
| Header/nav | `main-navigation.json` → `partials/global-header.html` |
| Design | `design-system.json`; variantele existente rămân documentate până la rollout aprobat |
| Legal/NAP | `legal-identity.json` |
| Contact | `contact-triage.json` + schema payload + worker |
| Calculator SO | `calculator-so-methodology.json` |
| Redirects | `_redirects` + politica explicită din worker; fără reguli ad-hoc în HTML nou |

## Zone de risc SEO/AEO/GEO

- variante fizice divergente pentru același canonical;
- liste canonice duplicate între build/generator/schema;
- status/freshness materializat pe mii de suprafețe;
- taxonomie curentă prea largă pentru stările obligatorii viitoare;
- șase linkuri interne către rute redirectate raportate de validator;
- test funcțional cu așteptare stale de 91 URL-uri față de 104 reale;
- 78 URL-uri fără `lastmod` verificabil, omis intenționat;
- JSON-LD Article nealiniat cu răspunsul vizibil pe pilotul AFIR autoconsum;
- `blog.json` și `official-guides.json` introduc dependențe CSR pentru suprafețe secundare;
- README și rapoarte istorice descriu arhitecturi/deploy-uri vechi;
- lipsa unui gate de consimțământ vizibil pentru Clarity poate afecta încrederea și conformitatea, nu doar analytics.

## Starea Git la începutul Task 00

- Branch curent: `main`.
- Înainte de fetch: `main` era la `1e0bed6` și aliniat cu `origin/main`; `master` local era la `d47bbf3`, cu 4 commituri în urmă.
- După `git fetch origin --prune`: `origin/main` și `origin/master` indicau ambele `1e0bed6`; divergență remote `0/0`.
- `master` local a rămas în urmă și nu a fost modificat în timpul inspecției.
- Remote: `origin = https://github.com/florincaciur/atelierdeconsultanta.git`.
- Worktree-ul conținea fișiere neversionate în `outreach/`, `reports/` și `scripts/`; acestea aparțin utilizatorului și nu au fost șterse, ascunse, editate sau incluse în task.

## Freeze de arhitectură pentru taskurile următoare

Până la o decizie explicită, taskurile următoare trebuie să păstreze:

1. site static și URL-urile canonice actuale;
2. npm/Node și build-ul existent;
3. `config/seo-programs.json#programs` ca autoritate factuală;
4. HTML critic pre-randat, fără conținut exclusiv pentru boți;
5. headerul, footerul, design tokens, breakpoints și stările de focus existente;
6. sitemap-ul determinist și `lastmod` numai din update editorial verificat;
7. FAQ vizibil egal cu schema FAQPage;
8. formularul canonical, protecția PII și secretele numai în Cloudflare;
9. redirecturi 301 într-un singur hop, fără schimbări de URL neaprobate;
10. `release.json` ca dovadă a SHA-ului live.

Orice remediere trebuie să reducă sursele paralele fără a rescrie simultan arhitectura, designul și conținutul.

## Arhitectura după Task 03

`config/seo-programs.json#programs` este registrul logic unic pentru fiecare program. Înregistrarea conține explicit `id` stabil, `slug`, `pageUrl` canonical, identitate editorială, statusul canonic și compatibilitatea legacy, justificarea statusului, faptele financiare disponibile, taxonomia de discovery, decizia de indexare, rolurile surselor oficiale și selecțiile pentru banner/catalog/hero/navigare.

Maparea semantică păstrează convențiile existente: `name` este denumirea oficială, `shortName`/`presentation.pageTitle` acoperă numele de afișare, `sourceName` este autoritatea, `grantSummary` conține grantul și bugetul disponibile, `cofinancingSummary` conține intensitatea/contribuția, `eligibleApplicants` rezumă solicitanții, iar `discovery.regions`, `presentation.carousel` și `discovery.listed` reprezintă regiunea, `bannerEnabled` și `catalogEnabled`. Schema acceptă opțional `displayName`, `acronym`, `fund`, `documentStage`, `extensionData`, `officialSourceUpdatedAt`, `nextReviewAt`, `caenApplicability`, `soRequirement`, `eligibleApplicantSummary` și `relatedProgramIds`; lipsa unei informații oficiale nu obligă publicarea unui placeholder.

Config-urile complementare nu mai atribuie fapte per program:

- `program-status-taxonomy.json` definește cele 13 stări și tranzițiile, fără `programAssignments`;
- `program-source-registry.json` este catalog pentru surse oficiale suplimentare, fără listă paralelă de programe;
- `homepage-programs.json` păstrează numai comportamentul caruselului/gridului;
- `main-navigation.json` păstrează structura navigării, nu liste de ID-uri de program;
- `banners.json`, HTML-ul homepage, headerul global, family hubs, paginile programelor, JSON-LD, ghidurile și `llms.txt` sunt outputs materializate din registry și sunt controlate prin sync/check.

Schema `config/program-registry.schema.json`, validatorul `tools/program-factual-governance.js` și reconcilierea din `tools/validate-program-registry.js` impun unicitatea ID/slug/canonical, taxonomia de status, validitatea relațiilor, paritatea registry–pagină–banner și dovada de sesiune pentru `OPEN`. Programul regional retras din catalog este declarat explicit `indexable=false`; celelalte înregistrări indexabile trebuie să aibă pagină canonical 200 cu același `data-program-id`.
