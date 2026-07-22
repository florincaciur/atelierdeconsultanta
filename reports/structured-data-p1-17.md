# P1.17 — audit și guvernanță JSON-LD

Data auditului: **2026-07-22**  
Inventar: **95 URL-uri canonice/indexabile**, fiecare cu un singur bloc JSON-LD determinist.

## Rezultat înainte / după

| Control | Înainte | După |
|---|---:|---:|
| URL-uri auditate | 95 | 95 |
| Identificatori FABER | `#organization`, `#professional-service` | numai `https://atelierdeconsultanta.ro/#organization` |
| Organization top-level | 95 | 95 |
| ProfessionalService top-level | 1 nod separat | 95, ca al doilea tip al aceleiași entități |
| WebSite | 95 | 95 |
| WebPage | 95 | 95 |
| BreadcrumbList | 94 | 94 |
| Article | 44 | 30, numai pe pagini clasificate editorial/program cu analiză |
| WebApplication | 2 | 1, exclusiv `/calculator-soc` |
| FAQPage | 77 | 77, numai din întrebări și răspunsuri vizibile |
| URL-uri cu `dateModified` | 92 | 17, exclusiv din `lastMeaningfulUpdate` verificat |
| Oferte `price=0` generate automat | 2 | 0 |
| Tipuri top-level moștenite (`Blog`, `ItemList`, `LegalService`) | 5 | 0 |

## Entitatea canonică publicată

Entitatea combină `Organization` și `ProfessionalService` în același nod. Valorile provin din `config/legal-identity.json`, aprobat la 2026-07-22:

- brand: FABER – Atelier de Consultanță;
- denumire juridică: FABER PUBLISHING S.R.L.;
- CUI: 35339809;
- email: atelier.consultanta@gmail.com;
- telefon: +40-769-828-338;
- sediu structurat: Str. Principală, nr. 88, Gorbănești, Botoșani, RO;
- profil oficial: Instagram FABER aprobat.

Generatorul refuză să transforme sediul într-un `PostalAddress` dacă structura aprobată nu mai poate fi interpretată fără pierderi.

## Reguli aplicate pe template-uri

| Template | Noduri controlate | Validare |
|---|---|---|
| Homepage | Organization + ProfessionalService, WebSite, WebPage, FAQPage vizibil | un singur `@id`, identitate exactă |
| Pagină internă | Organization + ProfessionalService, WebSite, WebPage, BreadcrumbList | canonical și breadcrumb identic cu HTML |
| Analiză/program editorial | cele de mai sus + Article | Article numai din clasificarea controlată; fără autor/reviewer fictiv |
| Serviciu | cele de pagină + Service | provider este entitatea canonică; fără oferte numerice moștenite |
| Calculator SO | cele de pagină + WebApplication | numai pe `/calculator-soc`; H1/meta vizibile, `BusinessApplication`, fără rating/ofertă inventată |
| Program verificat | cele de pagină + DefinedTerm factual | statusul și sursa provin din registrul programelor |
| FAQ | FAQPage opțional | întrebare și răspuns identice cu HTML-ul vizibil |

## Proprietăți eliminate sau restricționate

- Eliminat nodul separat `#professional-service`.
- Eliminate din entitatea FABER proprietățile redundante sau largi: `alternateName`, `description`, `image`, `knowsAbout`, `contactPoint` și `areaServed`.
- Eliminate `AggregateRating`, `Review`, `award`, `employee` și variantele lor oriunde ar reapărea.
- Eliminate ofertele automate cu preț zero din WebApplication și ofertele moștenite din Service.
- Eliminate tipurile istorice necontrolate `GovernmentService`, `BlogPosting`, `NewsArticle`, `LocalBusiness`, `Blog`, `LegalService` și `ItemList`.
- `dateModified` nu mai poate proveni din data build-ului, din data publicării sau dintr-un timestamp global.
- `Article.author` și `Article.reviewedBy` se publică numai ca `Person` cu nume aprobat, acord, URL oficial și profil vizibil în pagină.

## DE_VALIDAT_UMAN

Nu există încă profile publice de autor/reviewer aprobate cu toate elementele cerute (nume, rol, acord, fotografie/profil și URL oficial). Prin urmare, **nu este publicat niciun nod Person și niciun author/reviewer nominal în Article**. `publisher`/`provider` indică entitatea FABER, iar sursele oficiale rămân citate separat.

Pentru activarea unui autor sunt necesare: aprobarea numelui, acordul de publicare, rolul vizibil, URL-ul profilului de autor din site și profilul profesional oficial, dacă este publicat.

## Teste și release gate

`npm run test:structured-data` blochează build-ul dacă:

- JSON-LD nu este valid sau există mai mult de un bloc determinist;
- entitatea diferă de registrul juridic ori apare un al doilea `@id` FABER;
- un URL intern din JSON-LD nu corespunde unei rute canonice/200 sau unui asset public;
- `dateModified` nu corespunde `lastMeaningfulUpdate`;
- o sursă nu corespunde registrului editorial;
- un autor/reviewer nu este un profil Person vizibil;
- WebApplication apare în afara Calculatorului SO;
- FAQPage diferă de conținutul vizibil;
- reapare o proprietate sau un tip interzis.

Inventarul tehnic detaliat se regenerează în `reports/structured-data-audit.json`.
