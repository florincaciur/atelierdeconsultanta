# Audit limbă și entități JSON-LD — 2026-07-13

## Rezultat

Auditul și remedierea au fost aplicate pe toate cele 102 URL-uri indexabile din `sitemap.xml` și pe toate cele 180 de fișiere HTML locale pentru validarea sintaxei JSON-LD.

- 0 blocuri JSON-LD invalide;
- 0 probleme pe paginile indexabile;
- 1 singură variantă canonică a entității `Organization` FABER;
- 0 FAQ schema fără întrebare și răspuns vizibile;
- 0 breadcrumb-uri cu fragmente interne;
- maximum 3 niveluri breadcrumb pe paginile interne;
- homepage-ul are o singură intrare breadcrumb: „Acasă”;
- 0 valori JSON-LD cu variante românești evident nenormalizate conform normalizatorului;
- 91 `FAQPage`, cu 641 perechi întrebare–răspuns sincronizate semantic cu pagina;
- tipurile de conținut sunt exclusive: `Article`, `Service`, `WebApplication` sau doar `WebPage`, după rolul paginii.

Raportul tehnic complet este în `reports/structured-data-audit.json`.

## Variante eliminate și valori canonice

| Înainte | După |
|---|---|
| `Atelier de Consultanta` / descrieri FABER diferite | `FABER - Atelier de Consultanță`, cu o singură descriere canonică |
| `Romania` | `România` |
| `Romanian`, `ro` sau `română` în `inLanguage`/`availableLanguage` | `ro-RO` |
| obiecte `Organization` parțiale ori duplicate | referință `https://atelierdeconsultanta.ro/#organization` sau obiectul canonic integral |
| `#localbusiness` și combinații `LocalBusiness` + `ProfessionalService` | `https://atelierdeconsultanta.ro/#professional-service`, tip unic `ProfessionalService` |
| breadcrumb homepage cu 13 secțiuni și ancore | o singură intrare „Acasă” |
| breadcrumb-uri interne lungi sau cu fragmente | `Acasă -> hub tematic -> pagina curentă`, maximum 3 niveluri canonice |
| `GovernmentService` + `Article` + `Service` pe aceeași pagină | un singur tip de conținut justificat semantic |
| `dateModified` suprascris cu data verificării/buildului | data editorială stabilă; revizuirea este păstrată separat în `lastReviewed` |
| `Pot verifică` | `Pot verifica` |
| `Când este utila` | `Când este utilă` |
| `finantarea`, `functie`, `cofinantare`, `investitie`, `inainte`, `pregatite` | `finanțarea`, `funcție`, `cofinanțare`, `investiție`, `înainte`, `pregătite` |

## Sursa unică de adevăr

`tools/schema-helpers.js` centralizează acum:

- numele, descrierea, variantele de nume și identificatorii FABER;
- `Organization`, `WebSite` și `ProfessionalService`;
- logo, imagine, e-mail, telefoane, `areaServed`, `knowsAbout` și limba `ro-RO`;
- clasificarea tipului de pagină;
- breadcrumb-urile canonice;
- serializarea JSON-LD deterministă.

`tools/sync-structured-data.js` aplică aceste entități pe inventarul indexabil și este inclus în `npm run build`. Modul `--check` detectează orice abatere fără să scrie fișiere.

Normalizarea din `tools/normalize-copy-ro.js` localizează blocurile `application/ld+json`, le parsează cu `JSON.parse`, normalizează recursiv numai valorile textuale permise și le serializează determinist. URL-urile, `@id`, cheile, codurile, datele și numerele rămân protejate.

## Fișiere-sursă modificate

- `tools/schema-helpers.js`
- `tools/structured-data-utils.js`
- `tools/sync-structured-data.js`
- `tools/normalize-copy-ro.js`
- `tools/audit-structured-data.js`
- `scripts/verify-structured-data.js`
- `tools/generate-program-pages.js`
- `tools/generate-programmatic-seo.js`
- `tools/generate-project-design-pages.js`
- `tools/generate-seo-blog-article.js`
- `tools/generate-seo-hubs.js`
- `tools/priority-aeo.js`
- `tools/sync-program-heroes.js`
- `config/seo-programs.json`
- `config/seo-programmatic-pages.json`
- `config/priority-pages.json`
- `config/editorial-pages.json`
- `package.json`

JSON-LD a fost sincronizat în cele 102 fișiere HTML indexabile enumerate în `sitemap.xml`. Corecțiile FAQ vizibile au fost aplicate în paginile afectate, pentru ca textul din schemă să rămână identic semantic cu textul public. Fișierele HTML exacte și rezultatul fiecăruia sunt enumerate în `reports/structured-data-audit.json`.

## Teste executate

| Comandă | Rezultat |
|---|---|
| `npm run generate:program-pages` | PASS — 60 pagini regenerate |
| `npm run generate:programmatic-seo` | PASS — 10 pagini și 6 fallback-uri regenerate |
| `npm run check:structured-data-sync` | PASS — 102 pagini, 0 abateri |
| `npm run audit:structured-data` | PASS — 102 indexabile, 0 probleme, 1 variantă Organization |
| `node scripts/verify-structured-data.js --live` | PASS — 6 pagini prioritare și surse live verificate |
| `npm run verify:seo` | PASS — 179/179 fișiere |
| `npm run verify:seo-local` | PASS — 102 URL-uri și 10.018 linkuri interne |
| `npm run test:functional` | PASS — navigarea funcțională |
| `npm run verify:visual` | PASS — 26/26 verificări |
| `npm run build` | PASS — 102 URL-uri canonice și 165 fișiere Cloudflare |
| `npm run validate:cloudflare` | PASS |
| `git diff --check` | PASS |

La verificarea live, 10 surse oficiale au răspuns HTTP 200. Două URL-uri `legislatie.just.ro` au răspuns temporar HTTP 502; verificatorul raportează erorile 5xx ca avertismente tranzitorii, dar continuă să trateze erorile 4xx și URL-urile invalide drept eșecuri.

## Concluzie

Datele structurate FABER folosesc acum o singură identitate, limbă română normalizată, breadcrumb-uri canonice, FAQ exclusiv vizibil și tipuri de pagină fără suprapuneri nejustificate. Buildul reaplică automat sincronizarea, iar auditul blochează reapariția variantelor lingvistice sau de entitate.
