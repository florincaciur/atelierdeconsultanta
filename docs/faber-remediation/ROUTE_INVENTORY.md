# Inventar exhaustiv al rutelor publice FABER

Data inventarului: **2026-08-22**.

Generator: `tools/generate-route-inventory.js`. Autoritatea pentru setul canonical este `collectSiteState()` din generatorul de sitemap; aceasta este reconciliată cu toate fișierele HTML, registrele, homepage-ul, bannerele, navigația, footerul, sitemap-urile, redirecturile și suprafețele copiate de build.

Snapshot live: nu a fost cerut la această regenerare; vezi ultima secțiune versionată sau rulează `npm run generate:route-inventory`.

## Rezumat verificabil

- Rute HTML publice, self-canonical, indexabile, așteptate cu HTTP 200: **105**; în sitemap: **104**; excluse prin politică: **1**.
- Entități de program în registry: **25**; programe listate în catalog: **23**; bannere active: **23**.
- Definiții de pagină în registry: **62**; definiții care indică o sursă de redirect: **6**.
- Redirecturi exacte: **127** reguli / **127** surse distincte; redirecturi dinamice de normalizare: **9**.
- Canonical declarate de mai multe fișiere HTML: **52** grupuri; acestea sunt inventariate separat și nu sunt confundate cu duplicate în setul publicat.
- Rute indexabile fără incoming links: **0**; rute indexabile lipsă din sitemap: **1** (`/gdpr`); URL-uri sitemap fără rută: **0**.
- Fragmente/fișiere HTML fără canonical descoperite de scanarea repo: **4**; trei sunt servite live ca HTML 200 și indexabile neintenționat.

Tipurile sunt derivate din registry, `data-analytics-page-type`, schema și forma rutei:

| Tip | Număr |
|---|---:|
| article/guide | 24 |
| program | 24 |
| hub | 18 |
| page | 11 |
| service | 7 |
| landing CAEN | 4 |
| resource | 4 |
| answer page | 3 |
| legal | 3 |
| landing local | 2 |
| article hub | 1 |
| contact | 1 |
| homepage | 1 |
| tool | 1 |
| tools | 1 |

## Acoperirea suprafețelor obligatorii

Lipsa unei rute standalone nu este tratată automat ca defect atunci când suprafața există semantic într-o pagină canonical sau ca destinație externă legitimă.

| Suprafață | URL/rută reală | Relație |
|---|---|---|
| Homepage | / | rută proprie |
| Fiecare program | vezi tabelul «Reconcilierea programelor» | 25 entități registry; 23 listate/bannere |
| Familii/categorii | /afir; /fonduri-regionale; /fonduri-europene-digitalizare; /finantari-panouri-fotovoltaice; /fonduri-europene-imm | 5 huburi din registry |
| Analiză eligibilitate | /verificare-eligibilitate-fonduri-europene | rută proprie |
| Consultanță | /consultanta-fonduri-europene | rută proprie |
| Proiectare | /proiectare-fonduri-europene | rută proprie |
| Implementare | /management-proiecte-fonduri-europene | rută proprie |
| Calculator SO | /calculator-soc | rută proprie; /calculator-so-afir este alias 301 |
| Contact | /contact | rută proprie |
| Despre FABER | /despre-faber | rută proprie |
| Echipa | /despre-faber#about-team-title | secțiune; profilurile rămân blocate până la dovezi |
| Metodologie | /metodologie-verificare-eligibilitate | rută proprie |
| Studii de caz | /studii-de-caz-fonduri-europene | rută canonical; /studii-de-caz, /portofoliu și /testimoniale sunt 301 |
| Date companie | /despre-faber#about-public-data | secțiune din ruta About |
| GDPR | /gdpr | rută proprie |
| Privacy | /politica-de-confidentialitate | rută proprie |
| Cookies | /politica-de-confidentialitate#cookies | secțiune; nu există rută /cookies |
| Terms | /termeni-si-conditii | rută proprie |
| ANPC | https://anpc.ro și https://anpc.ro/ce-este-sal | linkuri externe în homepage/GDPR/Terms; nu există rută locală /anpc |
| Articole/ghiduri | /blog; /ghiduri și rutele article/guide din inventar | HTML canonical pre-randat + blog.json |
| Landing pages locale | /fonduri-europene-nord-est; /fonduri-europene-bucuresti | Iași/Suceava/Bacău sunt aliasuri 301 către Nord-Est |
| 404 | fallback pentru orice rută inexistentă | ruta explicită /404 răspunde 200/noindex; un URL inexistent răspunde 404 |

## Inventarul rutelor canonical 200/indexabile

`Incoming` este numărul de rute canonical distincte care trimit intern către destinație. `Nav/Footer` arată dacă destinația apare în componentele globale. `FAQ v/s` reprezintă numărul aproximativ de blocuri vizibile / entități `mainEntity` din FAQPage.

| Rută / canonical URL | Sursă rută | Tip | HTTP / index | Title | H1 | Canonical declarat | Sitemap | Nav/Footer | Incoming | Structured data | Breadcrumb | FAQ v/s | Registry | Banner | Familie | Status / note |
|---|---|---|---|---|---|---|---|---|---:|---|---|---:|---|---|---|---|
| [`/`](https://atelierdeconsultanta.ro/)<br><small>https://atelierdeconsultanta.ro/</small> | `index.html` | homepage | 200 / da | Consultanță și proiectare fonduri europene \| FABER | Consultanță și proiectare pentru proiecte cu fonduri europene | self | da | da/nu | 104 | Organization, ProfessionalService, WebPage, WebSite | nu | 0/0 | — | — | — | rută publică/indexabilă |
| [`/acte-necesare-fonduri-europene-nerambursabile`](https://atelierdeconsultanta.ro/acte-necesare-fonduri-europene-nerambursabile)<br><small>https://atelierdeconsultanta.ro/acte-necesare-fonduri-europene-nerambursabile</small> | `acte-necesare-fonduri-europene-nerambursabile/index.html` | article/guide | 200 / da | Acte necesare pentru fonduri europene - checklist dosar | Acte necesare pentru fonduri europene nerambursabile | self | da | nu/nu | 14 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 4/4 | page:acte-necesare-fonduri-europene-nerambursabile | — | — | rută publică/indexabilă |
| [`/afir`](https://atelierdeconsultanta.ro/afir)<br><small>https://atelierdeconsultanta.ro/afir</small> | `afir/index.html` | hub | 200 / da | AFIR \| calculator SO, DR12, DR14 și GAL | Programe AFIR și finanțări pentru agricultură | self | da | da/da | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 5/5 | page:afir | — | hub:afir-agricultura | rută publică/indexabilă |
| [`/afir-autoconsum-agroalimentar`](https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar)<br><small>https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar</small> | `afir-autoconsum-agroalimentar/index.html` | program | 200 / da | AFIR Autoconsum 2026: fotovoltaice, stocare, ghid \| FABER | AFIR Autoconsum Agroalimentar | self | da | da/da | 104 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | program:afir-energie-autoconsum, page:afir-autoconsum-agroalimentar | slide-afir-autoconsum | afir-energie | apel_inchis — Apel închis – sesiunea s-a încheiat la 14 august 2026 |
| [`/apeluri-gal`](https://atelierdeconsultanta.ro/apeluri-gal)<br><small>https://atelierdeconsultanta.ro/apeluri-gal</small> | `apeluri-gal/index.html` | program | 200 / da | Apeluri GAL: ghid local, criterii și documente | Apeluri GALFinanțări locale | self | da | nu/nu | 3 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/10 | program:apeluri-gal, page:apeluri-gal | slide-apeluri-gal | afir-leader | calendar_estimativ — Apeluri locale active – statutul și termenul se verifică pentru fiecare GAL |
| [`/autoconsum-public-fotovoltaice-institutii-publice`](https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice)<br><small>https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice</small> | `autoconsum-public-fotovoltaice-institutii-publice/index.html` | program | 200 / da | Autoconsum pentru instituții publice \| FABER | Autoconsum din surse regenerabile pentru instituții publice | self | da | nu/da | 3 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/10 | program:autoconsum-institutii-publice, page:autoconsum-public-fotovoltaice-institutii-publice | slide-autoconsum-publici | energie-public | apel_inchis — Apel finalizat în MySMIS – depunerea nu este deschisă |
| [`/blog`](https://atelierdeconsultanta.ro/blog)<br><small>https://atelierdeconsultanta.ro/blog</small> | `blog/index.html` | article hub | 200 / da | Blog fonduri europene, AFIR și granturi IMM \| FABER | Blog despre fonduri europene, finanțări nerambursabile și programe pentru beneficiari reali | self | da | nu/da | 10 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 5/5 | — | — | — | rută publică/indexabilă |
| [`/blog-afir-fotovoltaice-ferme-2026`](https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026)<br><small>https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026</small> | `blog-afir-fotovoltaice-ferme-2026.html` | article/guide | 200 / da | AFIR fotovoltaice ferme \| autoconsum | AFIR fotovoltaice pentru ferme: autoconsum și verificări | self | da | nu/nu | 2 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 5/5 | — | — | — | rută publică/indexabilă |
| [`/calculator-soc`](https://atelierdeconsultanta.ro/calculator-soc)<br><small>https://atelierdeconsultanta.ro/calculator-soc</small> | `calculator-soc.html` | article/guide | 200 / da | Calculator SO AFIR 2026 pentru DR12 și DR14 \| FABER | Calculator SO/SOC pentru AFIR DR12 și DR14 | self | da | da/nu | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebApplication, WebPage, WebSite | da | 12/11 | — | — | — | rută publică/indexabilă |
| [`/calendar-fonduri-europene`](https://atelierdeconsultanta.ro/calendar-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/calendar-fonduri-europene</small> | `calendar-fonduri-europene/index.html` | hub | 200 / da | Calendar fonduri europene \| pregătire | Calendar fonduri europene: pregătire fără grabă | self | da | nu/da | 18 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:calendar-fonduri-europene | — | — | rută publică/indexabilă |
| [`/cand-merita-consultant-fonduri-europene`](https://atelierdeconsultanta.ro/cand-merita-consultant-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/cand-merita-consultant-fonduri-europene</small> | `cand-merita-consultant-fonduri-europene.html` | article/guide | 200 / da | când merită consultant fonduri europene \| consultanță fonduri | Când merită să lucrezi cu un consultant pentru fonduri europene | self | da | nu/nu | 1 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/cat-costa-consultanta-fonduri-europene`](https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene</small> | `cat-costa-consultanta-fonduri-europene/index.html` | hub | 200 / da | Cât costa consultanță fonduri europene - factori și etape | Cât costa consultanță pentru fonduri europene | self | da | nu/nu | 4 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:cat-costa-consultanta-fonduri-europene | — | — | rută publică/indexabilă |
| [`/cat-costa-consultanta-fonduri-europene-ghid`](https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene-ghid)<br><small>https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene-ghid</small> | `cat-costa-consultanta-fonduri-europene-ghid.html` | article/guide | 200 / da | cât costa consultanță fonduri europene \| consultanță fonduri | Ghid: cât costă consultanța pentru fonduri europene | self | da | nu/nu | 2 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/ce-acte-sunt-necesare-fonduri-europene`](https://atelierdeconsultanta.ro/ce-acte-sunt-necesare-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/ce-acte-sunt-necesare-fonduri-europene</small> | `ce-acte-sunt-necesare-fonduri-europene.html` | article/guide | 200 / da | Checklist acte fonduri europene 2026 \| ghid dosar | Ce acte sunt necesare pentru fonduri europene? | self | da | nu/nu | 1 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/cheltuieli-eligibile-digitalizare-imm`](https://atelierdeconsultanta.ro/cheltuieli-eligibile-digitalizare-imm)<br><small>https://atelierdeconsultanta.ro/cheltuieli-eligibile-digitalizare-imm</small> | `cheltuieli-eligibile-digitalizare-imm.html` | article/guide | 200 / da | Cheltuieli pentru Digitalizare IMM: software și hardware \| FABER | Cheltuieli pentru Digitalizare IMM: ce justifici înainte de buget | self | da | nu/nu | 5 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/cheltuieli-eligibile-pocidif-21`](https://atelierdeconsultanta.ro/cheltuieli-eligibile-pocidif-21)<br><small>https://atelierdeconsultanta.ro/cheltuieli-eligibile-pocidif-21</small> | `cheltuieli-eligibile-pocidif-21/index.html` | article/guide | 200 / da | Cheltuieli eligibile PoCIDIF 2.1: hardware și software \| FABER | Cheltuieli eligibile PoCIDIF 2.1 – hardware, software și servicii CDI | self | da | nu/nu | 3 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | page:cheltuieli-eligibile-pocidif-21 | — | — | rută publică/indexabilă |
| [`/cod-caen-start-up-nation-2026`](https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026)<br><small>https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026</small> | `cod-caen-start-up-nation-2026/index.html` | article/guide | 200 / da | Cod CAEN Start Up Nation 2026 - verificare activitate | Cod CAEN Start Up Nation 2026: cum verifici activitatea eligibilă | self | da | nu/nu | 6 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/10 | page:cod-caen-start-up-nation-2026 | — | — | rută publică/indexabilă |
| [`/consultant-fonduri-europene-imm`](https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm)<br><small>https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm</small> | `consultant-fonduri-europene-imm/index.html` | service | 200 / da | Consultant fonduri europene IMM - verificare și dosar | Consultant fonduri europene pentru IMM-uri | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 6/6 | page:consultant-fonduri-europene-imm | — | — | rută publică/indexabilă |
| [`/consultanta-afir`](https://atelierdeconsultanta.ro/consultanta-afir)<br><small>https://atelierdeconsultanta.ro/consultanta-afir</small> | `consultanta-afir/index.html` | service | 200 / da | Consultanță AFIR - DR12, DR14 și proiecte agricole | Consultanță AFIR | self | da | nu/nu | 13 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 6/6 | page:consultanta-afir | — | — | rută publică/indexabilă |
| [`/consultanta-fonduri-europene`](https://atelierdeconsultanta.ro/consultanta-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/consultanta-fonduri-europene</small> | `consultanta-fonduri-europene/index.html` | service | 200 / da | Consultanță fonduri europene: eligibilitate și dosar \| FABER | Consultanță pentru fonduri europene, de la eligibilitate la dosar | self | da | da/da | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 7/6 | page:consultanta-fonduri-europene | — | — | rută publică/indexabilă |
| [`/consultanta-fonduri-europene-bucuresti`](https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti)<br><small>https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti</small> | `consultanta-fonduri-europene-bucuresti/index.html` | page | 200 / da | Consultanță fonduri europene București | Consultanță fonduri europene București | self | da | nu/nu | 2 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 12/12 | — | — | — | rută publică/indexabilă |
| [`/consultanta-pnrr-digitalizare`](https://atelierdeconsultanta.ro/consultanta-pnrr-digitalizare)<br><small>https://atelierdeconsultanta.ro/consultanta-pnrr-digitalizare</small> | `consultanta-pnrr-digitalizare/index.html` | service | 200 / da | Consultanță PNRR Digitalizare \| verificare proiect IMM | Consultanță PNRR digitalizare | self | da | nu/nu | 15 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 6/6 | page:consultanta-pnrr-digitalizare | — | — | rută publică/indexabilă |
| [`/consultanta-start-up-nation-2026`](https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026)<br><small>https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026</small> | `consultanta-start-up-nation-2026/index.html` | service | 200 / da | Consultanță Start-Up Nation 2026 \| verificare dosar | Consultanță Start-Up Nation 2026: CAEN, plan și dosar | self | da | nu/nu | 13 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 8/8 | page:consultanta-start-up-nation-2026 | — | — | rută publică/indexabilă |
| [`/contact`](https://atelierdeconsultanta.ro/contact)<br><small>https://atelierdeconsultanta.ro/contact</small> | `contact/index.html` | contact | 200 / da | Contact FABER: trimite proiectul pentru verificare | Trimite proiectul. Îți spunem ce trebuie verificat. | self | da | da/da | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 8/7 | — | — | — | rută publică/indexabilă |
| [`/cum-alegi-consultant-fonduri-europene`](https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene</small> | `cum-alegi-consultant-fonduri-europene/index.html` | hub | 200 / da | Cum alegi consultant fonduri europene - criterii utile | Cum alegi un consultant pentru fonduri europene | self | da | nu/nu | 3 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:cum-alegi-consultant-fonduri-europene | — | — | rută publică/indexabilă |
| [`/cum-alegi-programul-potrivit-fonduri-europene-2026`](https://atelierdeconsultanta.ro/cum-alegi-programul-potrivit-fonduri-europene-2026)<br><small>https://atelierdeconsultanta.ro/cum-alegi-programul-potrivit-fonduri-europene-2026</small> | `cum-alegi-programul-potrivit-fonduri-europene-2026.html` | article/guide | 200 / da | fonduri europene 2026 \| ghid FABER | Cum alegi programul potrivit de fonduri europene în 2026 | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 8/7 | — | — | — | rută publică/indexabilă |
| [`/cum-se-calculeaza-cofinantarea-fonduri-europene`](https://atelierdeconsultanta.ro/cum-se-calculeaza-cofinantarea-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/cum-se-calculeaza-cofinantarea-fonduri-europene</small> | `cum-se-calculeaza-cofinantarea-fonduri-europene.html` | article/guide | 200 / da | cofinanțare fonduri europene \| ghid FABER | Cum se calculează cofinanțarea la fonduri europene | self | da | nu/nu | 11 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/cum-se-verifica-eligibilitatea-fonduri-europene`](https://atelierdeconsultanta.ro/cum-se-verifica-eligibilitatea-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/cum-se-verifica-eligibilitatea-fonduri-europene</small> | `cum-se-verifica-eligibilitatea-fonduri-europene.html` | article/guide | 200 / da | verificare eligibilitate fonduri europene \| ghid FABER | Cum se verifică eligibilitatea pentru fonduri europene | self | da | nu/nu | 2 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/despre-faber`](https://atelierdeconsultanta.ro/despre-faber)<br><small>https://atelierdeconsultanta.ro/despre-faber</small> | `despre-faber/index.html` | page | 200 / da | Despre FABER: operator, metodă și limite | Consultanță prudentă înainte de dosar | self | da | da/da | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 7/6 | — | — | — | rută publică/indexabilă |
| [`/diaspora-investeste-acasa`](https://atelierdeconsultanta.ro/diaspora-investeste-acasa)<br><small>https://atelierdeconsultanta.ro/diaspora-investeste-acasa</small> | `diaspora-investeste-acasa/index.html` | program | 200 / da | Diaspora Investește Acasă: condiții anunțate \| FABER | Diaspora Investește Acasă | self | da | da/nu | 104 | BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/10 | program:diaspora-investeste-acasa | slide-diaspora-investeste-acasa | antreprenoriat | calendar_estimativ — Program anunțat – mecanismul de aplicare nu este publicat |
| [`/digitalizare-imm`](https://atelierdeconsultanta.ro/digitalizare-imm)<br><small>https://atelierdeconsultanta.ro/digitalizare-imm</small> | `digitalizare-imm/index.html` | program | 200 / da | Digitalizare IMM: apel închis și sursă MIPE \| FABER | Digitalizarea IMM-urilor | self | da | da/nu | 104 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 13/10 | program:digitalizare-imm, page:digitalizare-imm | slide-digitalizare-imm | digitalizare | apel_inchis — Apel închis – depunerea nu este deschisă |
| [`/digitalizare-imm-erp-crm-cloud`](https://atelierdeconsultanta.ro/digitalizare-imm-erp-crm-cloud)<br><small>https://atelierdeconsultanta.ro/digitalizare-imm-erp-crm-cloud</small> | `digitalizare-imm-erp-crm-cloud.html` | article/guide | 200 / da | digitalizare IMM ERP CRM cloud \| ghid digitalizare | ERP, CRM și cloud în proiectele de digitalizare IMM | self | da | nu/nu | 3 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/digitalizare-imm-pnrr`](https://atelierdeconsultanta.ro/digitalizare-imm-pnrr)<br><small>https://atelierdeconsultanta.ro/digitalizare-imm-pnrr</small> | `digitalizare-imm-pnrr/index.html` | hub | 200 / da | Digitalizare IMM PNRR \| pagină aplicată pentru proiecte digitale | Digitalizare IMM / PNRR: pagină aplicată pentru proiecte digitale | self | da | nu/nu | 4 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | page:digitalizare-imm-pnrr | — | — | rută publică/indexabilă |
| [`/documente-punctaj-pocidif-21`](https://atelierdeconsultanta.ro/documente-punctaj-pocidif-21)<br><small>https://atelierdeconsultanta.ro/documente-punctaj-pocidif-21</small> | `documente-punctaj-pocidif-21/index.html` | article/guide | 200 / da | Documente și punctaj PoCIDIF 2.1: ghid practic \| FABER | Documente și punctaj PoCIDIF 2.1 – dosar, indicatori și evaluare | self | da | nu/nu | 2 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | page:documente-punctaj-pocidif-21 | — | — | rută publică/indexabilă |
| [`/dr-12-afir-instalarea-tinerilor-fermieri`](https://atelierdeconsultanta.ro/dr-12-afir-instalarea-tinerilor-fermieri)<br><small>https://atelierdeconsultanta.ro/dr-12-afir-instalarea-tinerilor-fermieri</small> | `dr-12-afir-instalarea-tinerilor-fermieri.html` | article/guide | 200 / da | DR12 AFIR și instalarea tinerilor fermieri: diferențe | DR12 AFIR și instalarea tinerilor fermieri: diferențe | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 3/3 | — | — | — | rută publică/indexabilă |
| [`/dr-14-afir-conditii-eligibilitate-greseli-frecvente`](https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente)<br><small>https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente</small> | `dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` | article/guide | 200 / da | DR 14 AFIR ferme mici \| eligibilitate și greșeli | DR14 AFIR: condiții, eligibilitate și greșeli frecvente | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 3/3 | — | — | — | rută publică/indexabilă |
| [`/dr12-afir`](https://atelierdeconsultanta.ro/dr12-afir)<br><small>https://atelierdeconsultanta.ro/dr12-afir</small> | `dr12-afir/index.html` | program | 200 / da | DR 12 AFIR 2026: eligibilitate și pregătirea dosarului \| FABER | DR 12 AFIR 2026 – investiții pentru tineri fermieri și fermieri până la 45 de ani | self | da | da/nu | 104 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 10/8 | program:dr12-afir, page:dr12-afir | slide-dr12-afir | afir-agricultura | consultare_publica — Ghid consultativ publicat – consultarea s-a încheiat; depunerea nu este deschisă. C… |
| [`/dr12-vs-dr14`](https://atelierdeconsultanta.ro/dr12-vs-dr14)<br><small>https://atelierdeconsultanta.ro/dr12-vs-dr14</small> | `dr12-vs-dr14.html` | article/guide | 200 / da | DR 12 vs DR 14: încadrare și investiții \| FABER | DR 12 vs DR 14: cum diferă încadrarea și investiția | self | da | nu/nu | 5 | Article, BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 2/0 | — | — | — | rută publică/indexabilă |
| [`/dr14`](https://atelierdeconsultanta.ro/dr14)<br><small>https://atelierdeconsultanta.ro/dr14</small> | `dr14/index.html` | program | 200 / da | DR 14 AFIR 2026: depuneri 1 sept.–31 oct., 50.000 € \| FABER | DR 14 AFIR 2026 – investiții în fermele de mici dimensiuni | self | da | da/nu | 104 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 15/10 | program:dr14-afir, page:dr14 | slide-dr14-afir | afir-agricultura | ghid_aprobat_nedeschis — Sesiune anunțată – depuneri 1 septembrie–31 octombrie 2026 |
| [`/dr18`](https://atelierdeconsultanta.ro/dr18)<br><small>https://atelierdeconsultanta.ro/dr18</small> | `dr18/index.html` | program | 200 / da | DR 18 AFIR: sesiune 1 septembrie–31 octombrie 2026 \| FABER | DR 18 AFIR 2026 – investiții în floricultură, plante medicinale și aromatice | self | da | da/nu | 104 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 17/11 | program:dr18-afir, page:dr18 | slide-dr18-afir | afir-agricultura | ghid_aprobat_nedeschis — Sesiune anunțată – depuneri 1 septembrie–31 octombrie 2026 |
| [`/e-drive`](https://atelierdeconsultanta.ro/e-drive)<br><small>https://atelierdeconsultanta.ro/e-drive</small> | `e-drive/index.html` | program | 200 / da | e-DRIVE: vehicule electrice pentru transport \| FABER | Programul e-DRIVE | self | da | da/nu | 104 | BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/10 | program:e-drive | slide-e-drive | mobilitate-energie | ghid_aprobat_nedeschis — Schemă actualizată – depunerea nu este deschisă |
| [`/e-mobility`](https://atelierdeconsultanta.ro/e-mobility)<br><small>https://atelierdeconsultanta.ro/e-mobility</small> | `e-mobility/index.html` | program | 200 / da | e-Mobility RO: stații de reîncărcare \| FABER | Programul e-Mobility RO | self | da | da/nu | 104 | BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/10 | program:e-mobility-ro | slide-e-mobility-ro | mobilitate-energie | ghid_aprobat_nedeschis — Schemă actualizată – depunerea nu este deschisă |
| [`/e-move`](https://atelierdeconsultanta.ro/e-move)<br><small>https://atelierdeconsultanta.ro/e-move</small> | `e-move/index.html` | program | 200 / da | e-MOVE RO: stații de încărcare și condiții \| FABER | Programul e-MOVE RO | self | da | nu/da | 9 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/10 | program:e-move-ro, page:e-move | slide-e-move | mobilitate-energie | ghid_aprobat_nedeschis — Schemă actualizată – depunerea nu este deschisă |
| [`/eligibilitate-fonduri-europene`](https://atelierdeconsultanta.ro/eligibilitate-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/eligibilitate-fonduri-europene</small> | `eligibilitate-fonduri-europene/index.html` | hub | 200 / da | Eligibilitate fonduri europene: criterii și checklist \| FABER | Eligibilitate pentru fonduri europene: criterii și checklist | self | da | nu/nu | 9 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | page:eligibilitate-fonduri-europene | — | — | rută publică/indexabilă |
| [`/eligibilitate-pocidif-21`](https://atelierdeconsultanta.ro/eligibilitate-pocidif-21)<br><small>https://atelierdeconsultanta.ro/eligibilitate-pocidif-21</small> | `eligibilitate-pocidif-21/index.html` | article/guide | 200 / da | Eligibilitate PoCIDIF 2.1: IMM TIC, CAEN și condiții \| FABER | Eligibilitate PoCIDIF 2.1 – IMM TIC, coduri CAEN și parteneriate | self | da | nu/nu | 2 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:eligibilitate-pocidif-21 | — | — | rută publică/indexabilă |
| [`/femeia-antreprenor-2026`](https://atelierdeconsultanta.ro/femeia-antreprenor-2026)<br><small>https://atelierdeconsultanta.ro/femeia-antreprenor-2026</small> | `femeia-antreprenor-2026/index.html` | program | 200 / da | Femeia Antreprenor: apel 2024 închis \| FABER | Programul Femeia Antreprenor | self | da | nu/da | 7 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/10 | program:femeia-antreprenor, page:femeia-antreprenor-2026 | slide-femeia-antreprenor | antreprenoriat | apel_inchis — Apel 2024 închis – este publicată ordinea finală la evaluare |
| [`/femeia-antreprenor-2026-conditii-idei-afaceri`](https://atelierdeconsultanta.ro/femeia-antreprenor-2026-conditii-idei-afaceri)<br><small>https://atelierdeconsultanta.ro/femeia-antreprenor-2026-conditii-idei-afaceri</small> | `femeia-antreprenor-2026-conditii-idei-afaceri.html` | article/guide | 200 / da | Femeia Antreprenor 2026 \| condiții și idei | Condiții și idei de afaceri pentru Femeia Antreprenor 2026 | self | da | nu/nu | 3 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 3/3 | — | — | — | rută publică/indexabilă |
| [`/finantari-panouri-fotovoltaice`](https://atelierdeconsultanta.ro/finantari-panouri-fotovoltaice)<br><small>https://atelierdeconsultanta.ro/finantari-panouri-fotovoltaice</small> | `finantari-panouri-fotovoltaice/index.html` | hub | 200 / da | Finantari panouri fotovoltaice - autoconsum și energie | Finanțări pentru energie și eficiență energetică | self | da | da/nu | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 5/5 | page:finantari-panouri-fotovoltaice | — | hub:energie | rută publică/indexabilă |
| [`/firma-consultanta-fonduri-europene`](https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene</small> | `firma-consultanta-fonduri-europene/index.html` | service | 200 / da | Firmă consultanță fonduri europene - criterii și servicii | Firmă de consultanță pentru fonduri europene | self | da | nu/nu | 4 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 6/6 | page:firma-consultanta-fonduri-europene | — | — | rută publică/indexabilă |
| [`/fondul-de-modernizare`](https://atelierdeconsultanta.ro/fondul-de-modernizare)<br><small>https://atelierdeconsultanta.ro/fondul-de-modernizare</small> | `fondul-de-modernizare/index.html` | program | 200 / da | Fondul pentru Modernizare: apeluri și statut \| FABER | Fondul pentru Modernizare | self | da | nu/nu | 2 | BreadcrumbList, DefinedTerm, Organization, ProfessionalService, WebPage, WebSite | da | 1/0 | program:fondul-de-modernizare, page:fondul-de-modernizare | slide-fondul-de-modernizare | energie | calendar_estimativ — Program în implementare – statutul se verifică pentru fiecare apel în MySMIS |
| [`/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum`](https://atelierdeconsultanta.ro/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum)<br><small>https://atelierdeconsultanta.ro/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum</small> | `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum/index.html` | program | 200 / da | Fondul pentru Modernizare: energie și autoconsum | Fondul de Modernizare: proiecte de fotovoltaice și autoconsum | self | da | nu/nu | 6 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/10 | program:fondul-modernizare-autoconsum, page:fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum | slide-fondul-modernizare-autoconsum | energie | apel_inchis — Apeluri finalizate în MySMIS – depunerea nu este deschisă |
| [`/fondul-modernizare-energie-regenerabila-2026`](https://atelierdeconsultanta.ro/fondul-modernizare-energie-regenerabila-2026)<br><small>https://atelierdeconsultanta.ro/fondul-modernizare-energie-regenerabila-2026</small> | `fondul-modernizare-energie-regenerabila-2026/index.html` | program | 200 / da | Fondul pentru Modernizare: energie regenerabilă | Fondul pentru ModernizareEnergie regenerabilă | self | da | nu/nu | 3 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 7/6 | program:fondul-modernizare-regenerabile, page:fondul-modernizare-energie-regenerabila-2026 | slide-fond-modernizare-regenerabila | energie | apel_inchis — Apeluri finalizate în MySMIS – depunerea nu este deschisă |
| [`/fondul-modernizare-pc1-stocare`](https://atelierdeconsultanta.ro/fondul-modernizare-pc1-stocare)<br><small>https://atelierdeconsultanta.ro/fondul-modernizare-pc1-stocare</small> | `fondul-modernizare-pc1-stocare/index.html` | program | 200 / da | PC1 stocare stand-alone: ghid aprobat \| FABER | Fondul pentru Modernizare – PC1 Stocare stand-alone | self | da | da/nu | 104 | BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/10 | program:fondul-modernizare-pc1-stocare | slide-fondul-modernizare-pc1-stocare | energie | ghid_aprobat_nedeschis — Ghid aprobat la 17 august 2026 – perioada de depunere nu este anunțată |
| [`/fonduri-europene`](https://atelierdeconsultanta.ro/fonduri-europene)<br><small>https://atelierdeconsultanta.ro/fonduri-europene</small> | `fonduri-europene/index.html` | hub | 200 / da | Fonduri europene: programe și trasee de verificare \| FABER | Fonduri europene: alege traseul potrivit investiției | self | da | da/da | 104 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | page:fonduri-europene | — | — | rută publică/indexabilă |
| [`/fonduri-europene-agricultura`](https://atelierdeconsultanta.ro/fonduri-europene-agricultura)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-agricultura</small> | `fonduri-europene-agricultura/index.html` | hub | 200 / da | Fonduri europene pentru agricultură - AFIR, ferme și utilaje | Fonduri europene pentru agricultură | self | da | nu/nu | 2 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 8/8 | page:fonduri-europene-agricultura | — | — | rută publică/indexabilă |
| [`/fonduri-europene-bucuresti`](https://atelierdeconsultanta.ro/fonduri-europene-bucuresti)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-bucuresti</small> | `fonduri-europene-bucuresti/index.html` | landing local | 200 / da | Fonduri europene București | Fonduri europene București | self | da | nu/nu | 2 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 14/13 | — | — | — | rută publică/indexabilă |
| [`/fonduri-europene-caen/0111-culturi-cereale`](https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale</small> | `fonduri-europene-caen/0111-culturi-cereale/index.html` | landing CAEN | 200 / da | Fonduri europene pentru CAEN 0111 - culturi de cereale | Fonduri europene pentru CAEN 0111 - culturi de cereale | self | da | nu/nu | 1 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 13/12 | — | — | — | rută publică/indexabilă |
| [`/fonduri-europene-caen/4321-instalatii-electrice`](https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice</small> | `fonduri-europene-caen/4321-instalatii-electrice/index.html` | landing CAEN | 200 / da | Fonduri europene pentru CAEN 4321 - instalații electrice | Fonduri europene pentru CAEN 4321 - instalații electrice | self | da | nu/nu | 1 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 13/12 | — | — | — | rută publică/indexabilă |
| [`/fonduri-europene-caen/5610-restaurante`](https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante</small> | `fonduri-europene-caen/5610-restaurante/index.html` | landing CAEN | 200 / da | Fonduri europene pentru CAEN 5610 - restaurante și servicii alimentare | Fonduri europene pentru CAEN 5610 - restaurante și servicii alimentare | self | da | nu/nu | 1 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 13/12 | — | — | — | rută publică/indexabilă |
| [`/fonduri-europene-caen/6201-dezvoltare-software`](https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software</small> | `fonduri-europene-caen/6201-dezvoltare-software/index.html` | landing CAEN | 200 / da | Fonduri europene pentru CAEN 6201 - dezvoltare software | Fonduri europene pentru CAEN 6201 - dezvoltare software | self | da | nu/nu | 1 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 13/12 | — | — | — | rută publică/indexabilă |
| [`/fonduri-europene-digitalizare`](https://atelierdeconsultanta.ro/fonduri-europene-digitalizare)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-digitalizare</small> | `fonduri-europene-digitalizare/index.html` | hub | 200 / da | Fonduri europene pentru digitalizare - IMM, PNRR, software | Programe pentru digitalizare și inovare | self | da | da/nu | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 5/5 | page:fonduri-europene-digitalizare | — | hub:digitalizare-inovare | rută publică/indexabilă |
| [`/fonduri-europene-femei-antreprenor`](https://atelierdeconsultanta.ro/fonduri-europene-femei-antreprenor)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-femei-antreprenor</small> | `fonduri-europene-femei-antreprenor/index.html` | hub | 200 / da | Fonduri europene pentru femei antreprenor \| hub IMM | Fonduri europene pentru femei antreprenor: hub de orientare | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:fonduri-europene-femei-antreprenor | — | — | rută publică/indexabilă |
| [`/fonduri-europene-imm`](https://atelierdeconsultanta.ro/fonduri-europene-imm)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-imm</small> | `fonduri-europene-imm/index.html` | hub | 200 / da | Fonduri europene pentru IMM-uri - investiții, digitalizare, energie | Programe pentru antreprenoriat și inițiative GAL | self | da | da/nu | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 5/5 | page:fonduri-europene-imm | — | hub:antreprenoriat-gal | rută publică/indexabilă |
| [`/fonduri-europene-nerambursabile-2026`](https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026</small> | `fonduri-europene-nerambursabile-2026/index.html` | hub | 200 / da | Fonduri europene nerambursabile 2026 | Fonduri europene nerambursabile 2026 | self | da | nu/nu | 3 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 13/12 | page:fonduri-europene-nerambursabile-2026 | — | — | rută publică/indexabilă |
| [`/fonduri-europene-nord-est`](https://atelierdeconsultanta.ro/fonduri-europene-nord-est)<br><small>https://atelierdeconsultanta.ro/fonduri-europene-nord-est</small> | `fonduri-europene-nord-est/index.html` | landing local | 200 / da | Fonduri europene Nord-Est: programe regionale, AFIR și IMM \| FABER | Fonduri europene în regiunea Nord-Est | self | da | nu/nu | 3 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 13/12 | — | — | — | rută publică/indexabilă |
| [`/fonduri-nerambursabile`](https://atelierdeconsultanta.ro/fonduri-nerambursabile)<br><small>https://atelierdeconsultanta.ro/fonduri-nerambursabile</small> | `fonduri-nerambursabile/index.html` | hub | 200 / da | Fonduri nerambursabile: grant, cash-flow și obligații \| FABER | Fonduri nerambursabile: ce acoperă grantul și ce plătește beneficiarul | self | da | nu/da | 4 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | page:fonduri-nerambursabile | — | — | rută publică/indexabilă |
| [`/fonduri-pentru-ferme`](https://atelierdeconsultanta.ro/fonduri-pentru-ferme)<br><small>https://atelierdeconsultanta.ro/fonduri-pentru-ferme</small> | `fonduri-pentru-ferme/index.html` | hub | 200 / da | Fonduri pentru ferme - AFIR, DR12, DR14 și utilaje | Fonduri pentru ferme | self | da | nu/nu | 2 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:fonduri-pentru-ferme | — | — | rută publică/indexabilă |
| [`/fonduri-pentru-utilaje-agricole`](https://atelierdeconsultanta.ro/fonduri-pentru-utilaje-agricole)<br><small>https://atelierdeconsultanta.ro/fonduri-pentru-utilaje-agricole</small> | `fonduri-pentru-utilaje-agricole/index.html` | hub | 200 / da | Fonduri pentru utilaje agricole - eligibilitate și buget | Fonduri pentru utilaje agricole | self | da | nu/nu | 2 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | page:fonduri-pentru-utilaje-agricole | — | — | rută publică/indexabilă |
| [`/fonduri-regionale`](https://atelierdeconsultanta.ro/fonduri-regionale)<br><small>https://atelierdeconsultanta.ro/fonduri-regionale</small> | `fonduri-regionale/index.html` | program | 200 / da | Fonduri regionale 2021–2027 și ADR-uri \| FABER | Programe regionale și apeluri ADR | self | da | da/nu | 104 | BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/5 | program:fonduri-regionale | — | regional-adr | calendar_estimativ — Programe active – statutul și calendarul se verifică pentru fiecare apel |
| [`/gal-afir`](https://atelierdeconsultanta.ro/gal-afir)<br><small>https://atelierdeconsultanta.ro/gal-afir</small> | `gal-afir/index.html` | program | 200 / da | GAL-AFIR: proiecte LEADER și implementare | LEADER / DR-36 prin Grupuri de Acțiune Locală | self | da | nu/da | 10 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/10 | program:gal-afir-leader, page:gal-afir | slide-gal-afir | afir-leader | calendar_estimativ — Apeluri locale active – statutul și termenul se verifică pentru fiecare GAL |
| [`/gdpr`](https://atelierdeconsultanta.ro/gdpr)<br><small>https://atelierdeconsultanta.ro/gdpr</small> | `gdpr.html` | legal | 200 / da | Politica GDPR \| FABER – Atelier de Consultanță | Politica GDPR | self | nu | nu/da | 7 | BreadcrumbList, LegalService, Organization, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă; lipsește din sitemap: duplicate_policy_pending_legal_consolidation |
| [`/ghiduri`](https://atelierdeconsultanta.ro/ghiduri)<br><small>https://atelierdeconsultanta.ro/ghiduri</small> | `ghiduri/index.html` | resource | 200 / da | Ghiduri fonduri europene \| bibliotecă FABER | Ghiduri și resurse pentru fonduri europene | self | da | nu/da | 43 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 7/7 | page:ghiduri | — | — | rută publică/indexabilă |
| [`/glosar-fonduri-europene`](https://atelierdeconsultanta.ro/glosar-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/glosar-fonduri-europene</small> | `glosar-fonduri-europene/index.html` | page | 200 / da | Glosar fonduri europene: termeni explicati simplu | Glosar fonduri europene: termeni explicati simplu | self | da | nu/nu | 10 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 4/4 | — | — | — | rută publică/indexabilă |
| [`/greseli-fonduri-europene`](https://atelierdeconsultanta.ro/greseli-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/greseli-fonduri-europene</small> | `greseli-fonduri-europene/index.html` | hub | 200 / da | Greșeli fonduri europene - ce verifici înainte | Greșeli frecvente la fonduri europene | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:greseli-fonduri-europene | — | — | rută publică/indexabilă |
| [`/idei-afaceri-fonduri-europene`](https://atelierdeconsultanta.ro/idei-afaceri-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/idei-afaceri-fonduri-europene</small> | `idei-afaceri-fonduri-europene.html` | page | 200 / da | Idei de afaceri cu fonduri europene | Idei de afaceri cu fonduri europene | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 4/4 | — | — | — | rută publică/indexabilă |
| [`/instrumente`](https://atelierdeconsultanta.ro/instrumente)<br><small>https://atelierdeconsultanta.ro/instrumente</small> | `instrumente/index.html` | tools | 200 / da | Instrumente fonduri europene - calculatoare și checklisturi | Instrumente interactive pentru fonduri europene | self | da | nu/nu | 13 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 4/4 | page:instrumente | — | — | rută publică/indexabilă |
| [`/intrebari-frecvente`](https://atelierdeconsultanta.ro/intrebari-frecvente)<br><small>https://atelierdeconsultanta.ro/intrebari-frecvente</small> | `intrebari-frecvente/index.html` | hub | 200 / da | Întrebări frecvente despre fonduri europene | Întrebări frecvente despre fonduri europene | self | da | nu/da | 2 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:intrebari-frecvente | — | — | rută publică/indexabilă |
| [`/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm`](https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm)<br><small>https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm</small> | `intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html` | answer page | 200 / da | Raspuns rapid: Ce cheltuieli sunt eligibile la Digitalizare IMM? | Raspuns rapid: Ce cheltuieli sunt eligibile la Digitalizare IMM? | self | da | nu/nu | 1 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/11 | — | — | — | rută publică/indexabilă |
| [`/intrebari/ce-documente-sunt-necesare-pentru-dr12`](https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12)<br><small>https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12</small> | `intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html` | answer page | 200 / da | Raspuns rapid: Ce documente sunt necesare pentru DR12? | Raspuns rapid: Ce documente sunt necesare pentru DR12? | self | da | nu/nu | 1 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/11 | — | — | — | rută publică/indexabilă |
| [`/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene`](https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene</small> | `intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html` | answer page | 200 / da | Raspuns rapid: Cum se calculează cofinanțarea la fonduri europene? | Raspuns rapid: Cum se calculează cofinanțarea la fonduri europene? | self | da | nu/nu | 1 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/11 | — | — | — | rută publică/indexabilă |
| [`/investitii-modernizarea-microintreprinderilor-apel-2`](https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2)<br><small>https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2</small> | `investitii-modernizarea-microintreprinderilor-apel-2/index.html` | program | 200 / da | Modernizarea microîntreprinderilor – Apel 2 Nord-Est \| FABER | Investiții pentru modernizarea microîntreprinderilor – Apel 2 | self | da | da/da | 104 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 11/10 | program:modernizare-microintreprinderi-ne-2, page:investitii-modernizarea-microintreprinderilor-apel-2 | slide-micro-apel-2 | regional-adr | consultare_publica — Consultare publică închisă – apelul nu este deschis |
| [`/management-proiecte-fonduri-europene`](https://atelierdeconsultanta.ro/management-proiecte-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/management-proiecte-fonduri-europene</small> | `management-proiecte-fonduri-europene/index.html` | page | 200 / da | Management proiecte cu fonduri europene \| FABER | Managementul proiectelor finanțate din fonduri europene | self | da | da/da | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 5/5 | — | — | — | rută publică/indexabilă |
| [`/metodologie-verificare-eligibilitate`](https://atelierdeconsultanta.ro/metodologie-verificare-eligibilitate)<br><small>https://atelierdeconsultanta.ro/metodologie-verificare-eligibilitate</small> | `metodologie-verificare-eligibilitate/index.html` | tool | 200 / da | Metodologia FABER pentru verificarea eligibilității la fonduri europene | Metodologia FABER pentru verificarea eligibilității la fonduri europene | self | da | da/nu | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 3/3 | — | — | — | rută publică/indexabilă |
| [`/plan-de-afaceri-fonduri-europene`](https://atelierdeconsultanta.ro/plan-de-afaceri-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/plan-de-afaceri-fonduri-europene</small> | `plan-de-afaceri-fonduri-europene/index.html` | page | 200 / da | Plan de afaceri pentru fonduri europene \| FABER | Plan de afaceri pentru proiecte finanțate | self | da | nu/nu | 3 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 5/5 | — | — | — | rută publică/indexabilă |
| [`/pnrr`](https://atelierdeconsultanta.ro/pnrr)<br><small>https://atelierdeconsultanta.ro/pnrr</small> | `pnrr/index.html` | program | 200 / da | PNRR: componente, apeluri și stadiul implementării \| FABER | Planul Național de Redresare și Reziliență | self | da | nu/nu | 2 | BreadcrumbList, DefinedTerm, Organization, ProfessionalService, WebPage, WebSite | da | 1/0 | program:pnrr, page:pnrr | slide-pnrr | pnrr | calendar_estimativ — Program în implementare – statutul se verifică pentru fiecare componentă și apel |
| [`/pnrr-digitalizare-imm-cheltuieli-eligibile`](https://atelierdeconsultanta.ro/pnrr-digitalizare-imm-cheltuieli-eligibile)<br><small>https://atelierdeconsultanta.ro/pnrr-digitalizare-imm-cheltuieli-eligibile</small> | `pnrr-digitalizare-imm-cheltuieli-eligibile.html` | article/guide | 200 / da | pnrr digitalizare \| ghid digitalizare | PNRR Digitalizare IMM: cheltuieli eligibile | self | da | nu/nu | 2 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 3/3 | — | — | — | rută publică/indexabilă |
| [`/pocidif-21`](https://atelierdeconsultanta.ro/pocidif-21)<br><small>https://atelierdeconsultanta.ro/pocidif-21</small> | `pocidif-21/index.html` | program | 200 / da | PoCIDIF 2.1: inovare digitală pentru IMM TIC \| FABER | PoCIDIF – Acțiunea 2.1 Dezvoltarea de noi servicii, aplicații și produse prin inovare și adoptarea de tehnolo… | self | da | nu/da | 9 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/10 | program:pocidif-21, page:pocidif-21 | slide-pocidif-21 | digitalizare-inovare | apel_deschis — Apel deschis – depuneri 30 iunie–30 septembrie 2026 |
| [`/politica-de-confidentialitate`](https://atelierdeconsultanta.ro/politica-de-confidentialitate)<br><small>https://atelierdeconsultanta.ro/politica-de-confidentialitate</small> | `politica-de-confidentialitate.html` | legal | 200 / da | Politica de Confidențialitate \| FABER | Politica de Confidențialitate | self | da | nu/da | 12 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/pro-infra`](https://atelierdeconsultanta.ro/pro-infra)<br><small>https://atelierdeconsultanta.ro/pro-infra</small> | `pro-infra/index.html` | program | 200 / da | PRO INFRA: schemă aprobată, apel nedeschis \| FABER | PRO INFRA – eficiență energetică pentru producătorii din infrastructura de transport | self | da | da/nu | 104 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 12/9 | program:pro-infra, page:pro-infra | slide-pro-infra | energie | ghid_aprobat_nedeschis — Schemă aprobată, în revizuire – depunerea nu este deschisă |
| [`/programul-tranzitie-justa`](https://atelierdeconsultanta.ro/programul-tranzitie-justa)<br><small>https://atelierdeconsultanta.ro/programul-tranzitie-justa</small> | `programul-tranzitie-justa/index.html` | program | 200 / da | Programul Tranziție Justă: apeluri și statut \| FABER | Programul Tranziție Justă | self | da | nu/nu | 3 | BreadcrumbList, DefinedTerm, Organization, ProfessionalService, WebPage, WebSite | da | 1/0 | program:programul-tranzitie-justa | slide-programul-tranzitie-justa | tranzitie-justa | calendar_estimativ — Program în implementare – statutul se verifică pentru fiecare apel în MySMIS |
| [`/programul-tranzitie-justa-intrebari-documente`](https://atelierdeconsultanta.ro/programul-tranzitie-justa-intrebari-documente)<br><small>https://atelierdeconsultanta.ro/programul-tranzitie-justa-intrebari-documente</small> | `programul-tranzitie-justa-intrebari-documente/index.html` | article/guide | 200 / da | Programul Tranziție Justă: întrebări și documente pentru verificare | Programul Tranziție Justă: întrebări și documente pentru verificare | self | da | nu/nu | 4 | Article, BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | — | — | — | rută publică/indexabilă |
| [`/proiectare-fonduri-europene`](https://atelierdeconsultanta.ro/proiectare-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/proiectare-fonduri-europene</small> | `proiectare-fonduri-europene/index.html` | page | 200 / da | Proiectare fonduri europene: SF, DALI și planuri \| FABER | Proiectare pentru investiții finanțate din fonduri europene | self | da | da/da | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 5/5 | — | — | — | rută publică/indexabilă |
| [`/resurse`](https://atelierdeconsultanta.ro/resurse)<br><small>https://atelierdeconsultanta.ro/resurse</small> | `resurse/index.html` | resource | 200 / da | Resurse descarcabile fonduri europene - PDF și Excel | Resurse descarcabile pentru pregătirea dosarului | self | da | nu/nu | 22 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 4/4 | page:resurse | — | — | rută publică/indexabilă |
| [`/resurse-utile`](https://atelierdeconsultanta.ro/resurse-utile)<br><small>https://atelierdeconsultanta.ro/resurse-utile</small> | `resurse-utile/index.html` | page | 200 / da | Resurse oficiale pentru fonduri europene \| FABER | Resurse utile pentru proiecte cu fonduri europene | self | da | nu/nu | 1 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/start-up-nation-2026`](https://atelierdeconsultanta.ro/start-up-nation-2026)<br><small>https://atelierdeconsultanta.ro/start-up-nation-2026</small> | `start-up-nation-2026/index.html` | program | 200 / da | Start-Up Nation: apel închis la 29 mai 2026 \| FABER | Programul Start-Up Nation | self | da | nu/da | 18 | Article, BreadcrumbList, DefinedTerm, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | program:start-up-nation, page:start-up-nation-2026 | slide-startup-nation | antreprenoriat | apel_inchis — Apel închis – înscrierile persoanelor juridice s-au încheiat la 29 mai 2026, ora 20:00 |
| [`/start-up-nation-2026-cheltuieli-eligibile`](https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile)<br><small>https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile</small> | `start-up-nation-2026-cheltuieli-eligibile/index.html` | article/guide | 200 / da | Start Up Nation 2026 cheltuieli eligibile - buget | Start Up Nation 2026: cheltuieli eligibile | self | da | nu/nu | 5 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | page:start-up-nation-2026-cheltuieli-eligibile | — | — | rută publică/indexabilă |
| [`/start-up-nation-2026-conditii`](https://atelierdeconsultanta.ro/start-up-nation-2026-conditii)<br><small>https://atelierdeconsultanta.ro/start-up-nation-2026-conditii</small> | `start-up-nation-2026-conditii/index.html` | article/guide | 200 / da | Start-Up Nation 2026 condiții \| checklist | Start-Up Nation 2026: checklist de condiții | self | da | nu/nu | 7 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | page:start-up-nation-2026-conditii | — | — | rută publică/indexabilă |
| [`/start-up-nation-2026-idei-afaceri`](https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri)<br><small>https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri</small> | `start-up-nation-2026-idei-afaceri/index.html` | article/guide | 200 / da | Start Up Nation 2026 idei de afaceri - CAEN și buget | Start Up Nation 2026: idei de afaceri | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 9/8 | page:start-up-nation-2026-idei-afaceri | — | — | rută publică/indexabilă |
| [`/start-up-nation-2026-plan-de-afaceri`](https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri)<br><small>https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri</small> | `start-up-nation-2026-plan-de-afaceri/index.html` | resource | 200 / da | Start Up Nation 2026 plan de afaceri - structura | Start Up Nation 2026: plan de afaceri | self | da | nu/nu | 6 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 6/6 | page:start-up-nation-2026-plan-de-afaceri | — | — | rută publică/indexabilă |
| [`/studii-de-caz-fonduri-europene`](https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene</small> | `studii-de-caz-fonduri-europene/index.html` | page | 200 / da | Studii de caz anonimizate: proiecte pregătite pentru fonduri europene | Studii de caz anonimizate: proiecte pregătite pentru fonduri europene | self | da | da/nu | 104 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 5/5 | — | — | — | rută publică/indexabilă |
| [`/studiu-fezabilitate-fonduri-europene`](https://atelierdeconsultanta.ro/studiu-fezabilitate-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/studiu-fezabilitate-fonduri-europene</small> | `studiu-fezabilitate-fonduri-europene/index.html` | page | 200 / da | Studiu de fezabilitate pentru fonduri europene \| FABER | Studiu de fezabilitate pentru proiecte cu fonduri europene | self | da | nu/nu | 3 | BreadcrumbList, FAQPage, Organization, ProfessionalService, Service, WebPage, WebSite | da | 5/5 | — | — | — | rută publică/indexabilă |
| [`/surse-oficiale-fonduri-europene`](https://atelierdeconsultanta.ro/surse-oficiale-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/surse-oficiale-fonduri-europene</small> | `surse-oficiale-fonduri-europene/index.html` | page | 200 / da | Surse oficiale pentru fonduri europene și finanțări nerambursabile | Surse oficiale pentru fonduri europene și finanțări nerambursabile | self | da | nu/nu | 29 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 4/4 | — | — | — | rută publică/indexabilă |
| [`/termeni-si-conditii`](https://atelierdeconsultanta.ro/termeni-si-conditii)<br><small>https://atelierdeconsultanta.ro/termeni-si-conditii</small> | `termeni-si-conditii.html` | legal | 200 / da | Termeni și Condiții \| FABER – Atelier de Consultanță | Termeni și Condiții | self | da | nu/da | 4 | BreadcrumbList, Organization, ProfessionalService, WebPage, WebSite | da | 0/0 | — | — | — | rută publică/indexabilă |
| [`/verificare-eligibilitate-fonduri-europene`](https://atelierdeconsultanta.ro/verificare-eligibilitate-fonduri-europene)<br><small>https://atelierdeconsultanta.ro/verificare-eligibilitate-fonduri-europene</small> | `verificare-eligibilitate-fonduri-europene/index.html` | service | 200 / da | Verificare inițială eligibilitate proiecte \| FABER | Verificare inițială a eligibilității proiectului | self | da | da/da | 104 | BreadcrumbList, Organization, ProfessionalService, Service, WebPage, WebSite | da | 0/0 | page:verificare-eligibilitate-fonduri-europene | — | — | rută publică/indexabilă |
| [`/webinarii`](https://atelierdeconsultanta.ro/webinarii)<br><small>https://atelierdeconsultanta.ro/webinarii</small> | `webinarii/index.html` | resource | 200 / da | Webinarii fonduri europene - evenimente, ghiduri și rezumate | Webinarii și evenimente despre fonduri europene | self | da | nu/nu | 1 | BreadcrumbList, FAQPage, Organization, ProfessionalService, WebPage, WebSite | da | 4/4 | page:webinarii | — | — | rută publică/indexabilă |

## Reconcilierea programelor: registry vs pagină vs homepage/catalog/banner

Statusul este redat exact în taxonomia existentă din registry. Nu este reinterpretat într-o stare mai optimistă. Taxonomia mai granulară solicitată rămâne problema `T00-005` și nu este migrată în Task 01.

| ID / program | pageUrl → rută finală | Familie | Status registry | Catalog | Homepage | Banner | Definiție pagină | Probleme |
|---|---|---|---|---|---|---|---|---|
| `program-regional-nord-est`<br>Programul Regional Nord-Est 2021–2027 | `/por-adr-nord-est` → `/investitii-modernizarea-microintreprinderilor-apel-2` | regional-adr | `calendar_estimativ` | nu | nu | — | por-adr-nord-est | pageUrl redirectează la /investitii-modernizarea-microintreprinderilor-apel-2 |
| `fonduri-regionale`<br>Programele regionale 2021–2027 | `/fonduri-regionale` | regional-adr | `calendar_estimativ` | nu | nu | — | — | — |
| `dr12-afir`<br>DR-12 Investiții în consolidarea exploatațiilor tinerilor fermieri instalați și a fermierilor cu vârsta de pâ… | `/dr12-afir` | afir-agricultura | `consultare_publica` | da | da | slide-dr12-afir | dr12-afir | — |
| `dr14-afir`<br>DR-14 Investiții în fermele de mici dimensiuni | `/dr14` | afir-agricultura | `ghid_aprobat_nedeschis` | da | da | slide-dr14-afir | dr14 | — |
| `dr18-afir`<br>DR-18 Investiții în floricultură, plante medicinale și aromatice | `/dr18` | afir-agricultura | `ghid_aprobat_nedeschis` | da | da | slide-dr18-afir | dr18 | — |
| `start-up-nation`<br>Programul Start-Up Nation | `/start-up-nation-2026` | antreprenoriat | `apel_inchis` | da | da | slide-startup-nation | start-up-nation-2026 | — |
| `femeia-antreprenor`<br>Programul Femeia Antreprenor | `/femeia-antreprenor-2026` | antreprenoriat | `apel_inchis` | da | da | slide-femeia-antreprenor | femeia-antreprenor-2026 | — |
| `digitalizare-imm`<br>Digitalizarea IMM-urilor | `/digitalizare-imm` | digitalizare | `apel_inchis` | da | da | slide-digitalizare-imm | digitalizare-imm | — |
| `modernizare-microintreprinderi-ne-2`<br>Investiții pentru modernizarea microîntreprinderilor – Apel 2 | `/investitii-modernizarea-microintreprinderilor-apel-2` | regional-adr | `consultare_publica` | da | da | slide-micro-apel-2 | investitii-modernizarea-microintreprinderilor-apel-2 | — |
| `fondul-modernizare-autoconsum`<br>Fondul pentru Modernizare – energie și autoconsum | `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum` | energie | `apel_inchis` | da | da | slide-fondul-modernizare-autoconsum | fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum | — |
| `fondul-modernizare-regenerabile`<br>Fondul pentru Modernizare – energie regenerabilă | `/fondul-modernizare-energie-regenerabila-2026` | energie | `apel_inchis` | da | da | slide-fond-modernizare-regenerabila | fondul-modernizare-energie-regenerabila-2026 | — |
| `afir-energie-autoconsum`<br>Schema de ajutor privind sprijinirea investițiilor în noi capacități de producere a energiei electrice din su… | `/afir-autoconsum-agroalimentar` | afir-energie | `apel_inchis` | da | da | slide-afir-autoconsum | afir-autoconsum-agroalimentar | — |
| `autoconsum-institutii-publice`<br>Autoconsum din surse regenerabile pentru instituții publice | `/autoconsum-public-fotovoltaice-institutii-publice` | energie-public | `apel_inchis` | da | da | slide-autoconsum-publici | autoconsum-public-fotovoltaice-institutii-publice | — |
| `pro-infra`<br>Schema de ajutor de stat PRO INFRA | `/pro-infra` | energie | `ghid_aprobat_nedeschis` | da | da | slide-pro-infra | pro-infra | — |
| `apeluri-gal`<br>Apeluri locale LEADER prin Grupuri de Acțiune Locală | `/apeluri-gal` | afir-leader | `calendar_estimativ` | da | da | slide-apeluri-gal | apeluri-gal | — |
| `gal-afir-leader`<br>LEADER / DR-36 prin Grupuri de Acțiune Locală | `/gal-afir` | afir-leader | `calendar_estimativ` | da | da | slide-gal-afir | gal-afir | — |
| `e-move-ro`<br>Programul e-MOVE RO | `/e-move` | mobilitate-energie | `ghid_aprobat_nedeschis` | da | da | slide-e-move | e-move | — |
| `pocidif-21`<br>PoCIDIF – Acțiunea 2.1 Dezvoltarea de noi servicii, aplicații și produse prin inovare și adoptarea de tehnolo… | `/pocidif-21` | digitalizare-inovare | `apel_deschis` | da | da | slide-pocidif-21 | pocidif-21 | — |
| `pnrr`<br>Planul Național de Redresare și Reziliență | `/pnrr` | pnrr | `calendar_estimativ` | da | da | slide-pnrr | pnrr | — |
| `diaspora-investeste-acasa`<br>Diaspora Investește Acasă | `/diaspora-investeste-acasa` | antreprenoriat | `calendar_estimativ` | da | da | slide-diaspora-investeste-acasa | — | — |
| `e-drive`<br>Programul e-DRIVE | `/e-drive` | mobilitate-energie | `ghid_aprobat_nedeschis` | da | da | slide-e-drive | — | — |
| `e-mobility-ro`<br>Programul e-Mobility RO | `/e-mobility` | mobilitate-energie | `ghid_aprobat_nedeschis` | da | da | slide-e-mobility-ro | — | — |
| `fondul-modernizare-pc1-stocare`<br>Fondul pentru Modernizare – PC1 Stocare stand-alone | `/fondul-modernizare-pc1-stocare` | energie | `ghid_aprobat_nedeschis` | da | da | slide-fondul-modernizare-pc1-stocare | — | — |
| `programul-tranzitie-justa`<br>Programul Tranziție Justă | `/programul-tranzitie-justa` | tranzitie-justa | `calendar_estimativ` | da | da | slide-programul-tranzitie-justa | — | — |
| `fondul-de-modernizare`<br>Fondul pentru Modernizare | `/fondul-de-modernizare` | energie | `calendar_estimativ` | da | da | slide-fondul-de-modernizare | fondul-de-modernizare | — |

### Reconciliere cu baseline-ul istoric de 19 entități

Toate cele 19 entități istorice au corespondent în registry-ul curent. Nu a fost găsită o eliminare; aliasurile istorice sunt păstrate prin redirecturi. Cele **6 entități suplimentare** față de listă sunt: `program-regional-nord-est`, `fonduri-regionale`, `dr18-afir`, `pnrr`, `programul-tranzitie-justa` și `fondul-de-modernizare`.

| Entitate istorică | ID registry actual | Rută canonical actuală | Status registry | Rezultat |
|---|---|---|---|---|
| DR12 AFIR | `dr12-afir` | `/dr12-afir` | `consultare_publica` | regăsit |
| DR14 AFIR | `dr14-afir` | `/dr14` | `ghid_aprobat_nedeschis` | regăsit |
| AFIR Autoconsum Agroalimentar | `afir-energie-autoconsum` | `/afir-autoconsum-agroalimentar` | `apel_inchis` | regăsit |
| Autoconsum instituții publice | `autoconsum-institutii-publice` | `/autoconsum-public-fotovoltaice-institutii-publice` | `apel_inchis` | regăsit |
| Digitalizare IMM | `digitalizare-imm` | `/digitalizare-imm` | `apel_inchis` | regăsit |
| Femeia Antreprenor | `femeia-antreprenor` | `/femeia-antreprenor-2026` | `apel_inchis` | regăsit |
| PRO INFRA | `pro-infra` | `/pro-infra` | `ghid_aprobat_nedeschis` | regăsit |
| Start-Up Nation | `start-up-nation` | `/start-up-nation-2026` | `apel_inchis` | regăsit |
| Modernizarea microîntreprinderilor – Apel 2 | `modernizare-microintreprinderi-ne-2` | `/investitii-modernizarea-microintreprinderilor-apel-2` | `consultare_publica` | regăsit |
| Fondul pentru Modernizare – energie regenerabilă | `fondul-modernizare-regenerabile` | `/fondul-modernizare-energie-regenerabila-2026` | `apel_inchis` | regăsit |
| Apeluri GAL | `apeluri-gal` | `/apeluri-gal` | `calendar_estimativ` | regăsit |
| e-MOVE RO | `e-move-ro` | `/e-move` | `ghid_aprobat_nedeschis` | regăsit |
| GAL-AFIR / LEADER | `gal-afir-leader` | `/gal-afir` | `calendar_estimativ` | regăsit |
| Fondul pentru Modernizare – autoconsum | `fondul-modernizare-autoconsum` | `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum` | `apel_inchis` | regăsit |
| Diaspora Investește Acasă | `diaspora-investeste-acasa` | `/diaspora-investeste-acasa` | `calendar_estimativ` | regăsit |
| e-DRIVE | `e-drive` | `/e-drive` | `ghid_aprobat_nedeschis` | regăsit |
| e-Mobility RO | `e-mobility-ro` | `/e-mobility` | `ghid_aprobat_nedeschis` | regăsit |
| PC1 Stocare stand-alone | `fondul-modernizare-pc1-stocare` | `/fondul-modernizare-pc1-stocare` | `ghid_aprobat_nedeschis` | regăsit |
| PoCIDIF 2.1 | `pocidif-21` | `/pocidif-21` | `apel_deschis` | regăsit |

Diferențe de suprafață:

- Cele 23 programe `listed=true` au `presentation.carousel=true` în registrul unic și câte un banner generat activ; nu există banner fără program și nici program listat fără banner.
- `program-regional-nord-est` și `fonduri-regionale` au `listed=false`; primul folosește `/por-adr-nord-est`, care redirecționează la pagina Apelului 2, iar al doilea este hubul canonical `/fonduri-regionale`.
- Sitemap-ul `programs` conține 26 URL-uri: cele 23 programe listate, hubul `/fonduri-regionale` și două ghiduri DR12/DR14 clasificate editorial în familia sitemap `programs`.

### Definiții de pagină care indică rute retrase/redirectate

| Slug config | Tip | Sursă 301 | Destinație canonical |
|---|---|---|---|
| `dr14-afir-ferme-mici` | program | `/dr14-afir-ferme-mici` | `/dr14` |
| `por-adr-nord-est` | program | `/por-adr-nord-est` | `/investitii-modernizarea-microintreprinderilor-apel-2` |
| `studii-de-caz` | trust | `/studii-de-caz` | `/studii-de-caz-fonduri-europene` |
| `portofoliu` | trust | `/portofoliu` | `/studii-de-caz-fonduri-europene` |
| `testimoniale` | trust | `/testimoniale` | `/studii-de-caz-fonduri-europene` |
| `granturi-digitalizare-imm` | hub | `/granturi-digitalizare-imm` | `/digitalizare-imm` |

## Duplicate canonical fizice

Acestea sunt fișiere sursă multiple care declară același canonical. Verificarea nouă eșuează pentru duplicate în setul canonical publicat sau pentru sluguri duplicate în registre, dar raportează separat aliasurile fizice cunoscute deoarece build-ul le sincronizează în `dist/`.

| Canonical | Fișiere | Identice byte-for-byte |
|---|---|---|
| https://atelierdeconsultanta.ro/acte-necesare-fonduri-europene-nerambursabile | `acte-necesare-fonduri-europene-nerambursabile/index.html`, `acte-necesare-fonduri-europene-nerambursabile.html` | nu |
| https://atelierdeconsultanta.ro/afir | `afir/index.html`, `afir.html` | nu |
| https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar | `afir-autoconsum-agroalimentar/index.html`, `afir-autoconsum-agroalimentar.html` | nu |
| https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice | `autoconsum-public-fotovoltaice-institutii-publice/index.html`, `autoconsum-public-fotovoltaice-institutii-publice.html`, `autoconsum-publici.html` | nu |
| https://atelierdeconsultanta.ro/blog | `blog/index.html`, `blog.html` | nu |
| https://atelierdeconsultanta.ro/calculator-soc | `calculator-so-afir.html`, `calculator-soc.html` | nu |
| https://atelierdeconsultanta.ro/calendar-fonduri-europene | `calendar-fonduri-europene/index.html`, `calendar-fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | `cat-costa-consultanta-fonduri-europene/index.html`, `cat-costa-consultanta-fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/cheltuieli-eligibile-pocidif-21 | `cheltuieli-eligibile-pocidif-21/index.html`, `cheltuieli-eligibile-pocidif-21.html` | nu |
| https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | `cod-caen-start-up-nation-2026/index.html`, `cod-caen-startup-nation.html` | nu |
| https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | `consultant-fonduri-europene-imm/index.html`, `consultant-fonduri-europene-imm.html` | nu |
| https://atelierdeconsultanta.ro/consultanta-afir | `consultanta-afir/index.html`, `consultanta-afir.html` | nu |
| https://atelierdeconsultanta.ro/consultanta-fonduri-europene | `consultanta-fonduri-europene/index.html`, `consultanta-fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/consultanta-pnrr-digitalizare | `consultanta-pnrr-digitalizare/index.html`, `consultanta-pnrr-digitalizare.html` | nu |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | `consultanta-start-up-nation/index.html`, `consultanta-start-up-nation-2026/index.html`, `consultanta-start-up-nation.html` | nu |
| https://atelierdeconsultanta.ro/contact | `contact/index.html`, `contact.html` | nu |
| https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | `cum-alegi-consultant-fonduri-europene/index.html`, `cum-alegi-consultant-fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/digitalizare-imm | `digitalizare-imm/index.html`, `digitalizare-imm.html` | nu |
| https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | `digitalizare-imm-pnrr/index.html`, `digitalizare-imm-pnrr.html`, `pnrr-digitalizare-imm/index.html`, `pnrr-digitalizare-imm.html` | nu |
| https://atelierdeconsultanta.ro/documente-punctaj-pocidif-21 | `documente-punctaj-pocidif-21/index.html`, `documente-punctaj-pocidif-21.html` | nu |
| https://atelierdeconsultanta.ro/dr12-afir | `dr12-afir/index.html`, `dr12-afir-tineri-fermieri.html`, `dr12-afir.html` | nu |
| https://atelierdeconsultanta.ro/dr14 | `dr14/index.html`, `dr14-afir-ferme-mici/index.html`, `dr14-afir-ferme-mici.html`, `dr14.html` | nu |
| https://atelierdeconsultanta.ro/eligibilitate-fonduri-europene | `eligibilitate-fonduri-europene/index.html`, `eligibilitate-fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/eligibilitate-pocidif-21 | `eligibilitate-pocidif-21/index.html`, `eligibilitate-pocidif-21.html` | nu |
| https://atelierdeconsultanta.ro/femeia-antreprenor-2026 | `femeia-antreprenor-2026/index.html`, `femeia-antreprenor-2026.html` | nu |
| https://atelierdeconsultanta.ro/finantari-panouri-fotovoltaice | `finantari-panouri-fotovoltaice/index.html`, `finantari-panouri-fotovoltaice.html` | nu |
| https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene | `firma-consultanta-fonduri-europene/index.html`, `firma-consultanta-fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/fondul-de-modernizare | `fondul-de-modernizare/index.html`, `fondul-de-modernizare.html` | nu |
| https://atelierdeconsultanta.ro/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum | `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum/index.html`, `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html` | nu |
| https://atelierdeconsultanta.ro/fondul-modernizare-energie-regenerabila-2026 | `fondul-modernizare-energie-regenerabila-2026/index.html`, `fondul-modernizare-energie-regenerabila-2026.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-europene | `fonduri-europene/index.html`, `fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-europene-agricultura | `fonduri-europene-agricultura/index.html`, `fonduri-europene-agricultura.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-europene-digitalizare | `fonduri-europene-digitalizare/index.html`, `fonduri-europene-digitalizare.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-europene-femei-antreprenor | `fonduri-europene-femei-antreprenor/index.html`, `fonduri-europene-femei-antreprenor.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-europene-imm | `fonduri-europene-imm/index.html`, `fonduri-europene-imm.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | `fonduri-europene-herambursabile-2026/index.html`, `fonduri-europene-herambursabile-2026.html`, `fonduri-europene-nerambursabile-2026/index.html`, `fonduri-europene-nerambursabile-2026.html`, `fonduri-nerambursabile.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | `consultanta-fonduri-europene-bacau/index.html`, `consultanta-fonduri-europene-iasi/index.html`, `consultanta-fonduri-europene-suceava/index.html`, `fonduri-europene-bacau/index.html`, `fonduri-europene-iasi/index.html`, `fonduri-europene-nord-est/index.html`, `fonduri-europene-suceava/index.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-pentru-ferme | `fonduri-pentru-ferme/index.html`, `fonduri-pentru-ferme.html` | nu |
| https://atelierdeconsultanta.ro/fonduri-pentru-utilaje-agricole | `fonduri-pentru-utilaje-agricole/index.html`, `fonduri-pentru-utilaje-agricole.html` | nu |
| https://atelierdeconsultanta.ro/ghiduri | `ghiduri/index.html`, `ghiduri.html` | nu |
| https://atelierdeconsultanta.ro/granturi-digitalizare-imm | `granturi-digitalizare-imm/index.html`, `granturi-digitalizare-imm.html` | nu |
| https://atelierdeconsultanta.ro/greseli-fonduri-europene | `greseli-fonduri-europene/index.html`, `greseli-fonduri-europene.html` | nu |
| https://atelierdeconsultanta.ro/intrebari-frecvente | `intrebari-frecvente/index.html`, `intrebari-frecvente.html` | nu |
| https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2 | `investitii-modernizarea-microintreprinderilor-apel-2/index.html`, `investitii-modernizarea-microintreprinderilor-apel-2.html` | nu |
| https://atelierdeconsultanta.ro/pnrr | `pnrr/index.html`, `pnrr.html` | nu |
| https://atelierdeconsultanta.ro/start-up-nation-2026 | `start-up-nation/index.html`, `start-up-nation-2026/index.html`, `start-up-nation-2026.html`, `start-up-nation.html` | nu |
| https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | `cheltuieli-eligibile-startup-nation.html`, `start-up-nation-2026-cheltuieli-eligibile/index.html`, `start-up-nation-2026-cheltuieli-eligibile.html` | nu |
| https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | `start-up-nation-2026-conditii/index.html`, `start-up-nation-2026-conditii.html`, `startup-nation-2026-conditii.html` | nu |
| https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | `start-up-nation-2026-idei-afaceri/index.html`, `start-up-nation-2026-idei-afaceri-plan.html`, `start-up-nation-2026-idei-afaceri.html` | nu |
| https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri | `start-up-nation-2026-plan-de-afaceri/index.html`, `start-up-nation-2026-plan-de-afaceri.html` | nu |
| https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | `studii-de-caz/index.html`, `studii-de-caz-fonduri-europene/index.html`, `studii-de-caz.html` | nu |
| https://atelierdeconsultanta.ro/testimoniale | `testimoniale/index.html`, `testimoniale.html` | nu |

## Rute legacy și redirecturi exacte

Pentru aceste rute, title/H1/canonical/schema/breadcrumb/FAQ nu se aplică: răspunsul așteptat este redirect și ruta nu trebuie indexată ori inclusă în sitemap. Incoming este urmărit de auditurile de linkuri; validatorul SEO baseline raportează încă linkuri interne către câteva surse de redirect (`T00-017`).

| Sursă | Destinație | HTTP | Indexabilă | Sursă regulă | Sitemap |
|---|---|---:|---|---|---|
| `/index.html` | / | 301 | nu | `_redirects` | nu |
| `/granturi-digitalizare-imm` | https://atelierdeconsultanta.ro/digitalizare-imm | 301 | nu | `_redirects` | nu |
| `/granturi-digitalizare-imm/` | https://atelierdeconsultanta.ro/digitalizare-imm | 301 | nu | `_redirects` | nu |
| `/granturi-digitalizare-imm.html` | https://atelierdeconsultanta.ro/digitalizare-imm | 301 | nu | `_redirects` | nu |
| `/granturi-digitalizare-imm/index.html` | https://atelierdeconsultanta.ro/digitalizare-imm | 301 | nu | `_redirects` | nu |
| `/testimoniale` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/testimoniale/` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/testimoniale.html` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/testimoniale/index.html` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/portofoliu` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/portofoliu/` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/portofoliu.html` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/portofoliu/index.html` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/dr12-afir.html` | https://atelierdeconsultanta.ro/dr12-afir | 301 | nu | `_redirects` | nu |
| `/dr12-afir/index.html` | https://atelierdeconsultanta.ro/dr12-afir | 301 | nu | `_redirects` | nu |
| `/dr14.html` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr14/index.html` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr14-afir-ferme-mici` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr14-afir-ferme-mici/` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr14-afir-ferme-mici.html` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr14-afir-ferme-mici/index.html` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/por-adr-nord-est` | https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2 | 301 | nu | `_redirects` | nu |
| `/por-adr-nord-est/` | https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2 | 301 | nu | `_redirects` | nu |
| `/por-adr-nord-est.html` | https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2 | 301 | nu | `_redirects` | nu |
| `/por-adr-nord-est/index.html` | https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2 | 301 | nu | `_redirects` | nu |
| `/afir-autoconsum-agroalimentar.html` | https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar | 301 | nu | `_redirects` | nu |
| `/afir-autoconsum-agroalimentar/index.html` | https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar | 301 | nu | `_redirects` | nu |
| `/pro-infra.html` | https://atelierdeconsultanta.ro/pro-infra | 301 | nu | `_redirects` | nu |
| `/pocidif-21.html` | https://atelierdeconsultanta.ro/pocidif-21 | 301 | nu | `_redirects` | nu |
| `/studii-de-caz` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/studii-de-caz/` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/studii-de-caz.html` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/studii-de-caz/index.html` | https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | 301 | nu | `_redirects` | nu |
| `/calculator-so-afir` | https://atelierdeconsultanta.ro/calculator-soc | 301 | nu | `_redirects` | nu |
| `/calculator-so-afir.html` | https://atelierdeconsultanta.ro/calculator-soc | 301 | nu | `_redirects` | nu |
| `/calculator-so-afir/` | https://atelierdeconsultanta.ro/calculator-soc | 301 | nu | `_redirects` | nu |
| `/dr12-afir-tineri-fermieri` | https://atelierdeconsultanta.ro/dr12-afir | 301 | nu | `_redirects` | nu |
| `/dr12-afir-tineri-fermieri.html` | https://atelierdeconsultanta.ro/dr12-afir | 301 | nu | `_redirects` | nu |
| `/startup-nation-2026-conditii` | https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | 301 | nu | `_redirects` | nu |
| `/startup-nation-2026-conditii.html` | https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | 301 | nu | `_redirects` | nu |
| `/startup-nation-2026-conditii/` | https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | 301 | nu | `_redirects` | nu |
| `/start-up-nation` | https://atelierdeconsultanta.ro/start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/start-up-nation/` | https://atelierdeconsultanta.ro/start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/start-up-nation.html` | https://atelierdeconsultanta.ro/start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/consultanta-start-up-nation` | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/consultanta-start-up-nation/` | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/consultanta-start-up-nation.html` | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-imm` | https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-imm/` | https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-imm.html` | https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-iasi` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-iasi/` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-iasi.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-iasi/index.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-iasi` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-iasi/` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-iasi.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-iasi/index.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-suceava` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-suceava/` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-suceava.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-suceava/index.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-suceava` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-suceava/` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-suceava.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-suceava/index.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-bacau` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-bacau/` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-bacau.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-bacau/index.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-bacau` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-bacau/` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-bacau.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/consultanta-fonduri-europene-bacau/index.html` | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | 301 | nu | `_redirects` | nu |
| `/pnrr-digitalizare-imm` | https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | 301 | nu | `_redirects` | nu |
| `/pnrr-digitalizare-imm/` | https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | 301 | nu | `_redirects` | nu |
| `/pnrr-digitalizare-imm.html` | https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | 301 | nu | `_redirects` | nu |
| `/pnrr-digitalizare-imm/index.html` | https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-herambursabile-2026` | https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-herambursabile-2026/` | https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-herambursabile-2026.html` | https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | 301 | nu | `_redirects` | nu |
| `/fonduri-europene-herambursabile-2026/index.html` | https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | 301 | nu | `_redirects` | nu |
| `/autoconsum-publici` | https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice | 301 | nu | `_redirects` | nu |
| `/autoconsum-publici/` | https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice | 301 | nu | `_redirects` | nu |
| `/autoconsum-publici.html` | https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice | 301 | nu | `_redirects` | nu |
| `/dr14-afir` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr14-afir/` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr14-afir.html` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr-14-afir` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr-14-afir/` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/dr-14-afir.html` | https://atelierdeconsultanta.ro/dr14 | 301 | nu | `_redirects` | nu |
| `/start-up-nation-2026-idei-afaceri-plan` | https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | 301 | nu | `_redirects` | nu |
| `/start-up-nation-2026-idei-afaceri-plan/` | https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | 301 | nu | `_redirects` | nu |
| `/start-up-nation-2026-idei-afaceri-plan.html` | https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | 301 | nu | `_redirects` | nu |
| `/idei-afaceri-start-up-nation-2026` | https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | 301 | nu | `_redirects` | nu |
| `/idei-afaceri-start-up-nation-2026/` | https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | 301 | nu | `_redirects` | nu |
| `/plan-afaceri-start-up-nation-2026` | https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri | 301 | nu | `_redirects` | nu |
| `/plan-afaceri-start-up-nation-2026/` | https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri | 301 | nu | `_redirects` | nu |
| `/blog/safir-fotovoltaice-ferme-2026.html` | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | 301 | nu | `_redirects` | nu |
| `/blog/safir-fotovoltaice-ferme-2026` | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | 301 | nu | `_redirects` | nu |
| `/blog/safir-fotovoltaice-ferme-2026/` | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | 301 | nu | `_redirects` | nu |
| `/intrebari/ce-documente-sunt-necesare-pentru-afir` | https://atelierdeconsultanta.ro/afir | 301 | nu | `_redirects` | nu |
| `/intrebari/ce-documente-sunt-necesare-pentru-afir/` | https://atelierdeconsultanta.ro/afir | 301 | nu | `_redirects` | nu |
| `/intrebari/ce-documente-sunt-necesare-pentru-afir.html` | https://atelierdeconsultanta.ro/afir | 301 | nu | `_redirects` | nu |
| `/intrebari/ce-documente-sunt-necesare-pentru-afir/index.html` | https://atelierdeconsultanta.ro/afir | 301 | nu | `_redirects` | nu |
| `/dr12-afir-tineri-fermieri/` | https://atelierdeconsultanta.ro/dr12-afir | 301 | nu | `_redirects` | nu |
| `/dr12-afir-tineri-fermieri/index.html` | https://atelierdeconsultanta.ro/dr12-afir | 301 | nu | `_redirects` | nu |
| `/calculator-so-afir/index.html` | https://atelierdeconsultanta.ro/calculator-soc | 301 | nu | `_redirects` | nu |
| `/startup-nation-2026-conditii/index.html` | https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | 301 | nu | `_redirects` | nu |
| `/cod-caen-startup-nation` | https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/cod-caen-startup-nation.html` | https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/cod-caen-startup-nation/` | https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/cod-caen-startup-nation/index.html` | https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/cheltuieli-eligibile-startup-nation` | https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | 301 | nu | `_redirects` | nu |
| `/cheltuieli-eligibile-startup-nation.html` | https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | 301 | nu | `_redirects` | nu |
| `/cheltuieli-eligibile-startup-nation/` | https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | 301 | nu | `_redirects` | nu |
| `/cheltuieli-eligibile-startup-nation/index.html` | https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | 301 | nu | `_redirects` | nu |
| `/consultanta-start-up-nation/index.html` | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/start-up-nation/index.html` | https://atelierdeconsultanta.ro/start-up-nation-2026 | 301 | nu | `_redirects` | nu |
| `/emove` | https://atelierdeconsultanta.ro/e-move | 301 | nu | `_redirects` | nu |
| `/emove/` | https://atelierdeconsultanta.ro/e-move | 301 | nu | `_redirects` | nu |
| `/e-move-ro` | https://atelierdeconsultanta.ro/e-move | 301 | nu | `_redirects` | nu |
| `/e-move-ro/` | https://atelierdeconsultanta.ro/e-move | 301 | nu | `_redirects` | nu |
| `/gal-leader` | https://atelierdeconsultanta.ro/gal-afir | 301 | nu | `_redirects` | nu |
| `/gal-leader/` | https://atelierdeconsultanta.ro/gal-afir | 301 | nu | `_redirects` | nu |
| `/leader-afir` | https://atelierdeconsultanta.ro/gal-afir | 301 | nu | `_redirects` | nu |
| `/leader-afir/` | https://atelierdeconsultanta.ro/gal-afir | 301 | nu | `_redirects` | nu |

### Reguli dinamice de normalizare

| Pattern | Destinație | HTTP |
|---|---|---:|
| `/:slug/index.html` | https://atelierdeconsultanta.ro/:slug | 301 |
| `/:section/:slug/index.html` | https://atelierdeconsultanta.ro/:section/:slug | 301 |
| `/:section/:category/:slug/index.html` | https://atelierdeconsultanta.ro/:section/:category/:slug | 301 |
| `/:slug.html` | https://atelierdeconsultanta.ro/:slug | 301 |
| `/:section/:slug.html` | https://atelierdeconsultanta.ro/:section/:slug | 301 |
| `/:section/:category/:slug.html` | https://atelierdeconsultanta.ro/:section/:category/:slug | 301 |
| `/:slug/` | https://atelierdeconsultanta.ro/:slug | 301 |
| `/:section/:slug/` | https://atelierdeconsultanta.ro/:section/:slug | 301 |
| `/:section/:category/:slug/` | https://atelierdeconsultanta.ro/:section/:category/:slug | 301 |

Workerul de domeniu normalizează suplimentar HTTP→HTTPS, `www`→apex, `.html`, `/index.html`, slash final, query-ul istoric de căutare și query-urile de contact. `_redirects` rămâne fallback-ul static reviewable.

## Suprafețe HTML publice necanonice / noindex

| Rută | Sursă | HTTP | Indexabilitate | Metadata/schema | Problemă |
|---|---|---:|---|---|---|
| `/404` | `404.html` | 200 când este cerut explicit; 404 ca fallback pentru URL inexistent | nu (meta + X-Robots-Tag) | title/H1/canonical `/404`, fără sitemap | Comportament intenționat; testul real de 404 folosește o rută inexistentă. |
| `/admin` | `admin/index.html` | 200 | nu (meta + X-Robots-Tag) | title/H1, fără sitemap | Panou client-side public; nu este o zonă autentificată server-side. Necesită review separat de securitate/operare. |
| `/google8bbb9999c523a3bd` | `google8bbb9999c523a3bd.html` | 200 | tehnic; header de verificat pe ruta curată | lipsesc canonical/metadata/schema de pagină | Fișier de verificare; normalizarea globală redirecționează forma .html. |
| `/partials/global-header` | `partials/global-header.html` | 200 | da (neintenționat) | lipsesc canonical/metadata/schema de pagină | Fișier copiat de build și servit public fără document HTML complet, canonical sau noindex. |
| `/templates/dr14-final-content` | `templates/dr14-final-content.html` | 200 | da (neintenționat) | lipsesc canonical/metadata/schema de pagină | Fișier copiat de build și servit public fără document HTML complet, canonical sau noindex. |
| `/templates/dr18-final-content` | `templates/dr18-final-content.html` | 200 | da (neintenționat) | lipsesc canonical/metadata/schema de pagină | Fișier copiat de build și servit public fără document HTML complet, canonical sau noindex. |

## Endpointuri și fișiere publice non-page

Activele CSS/JS/imagini nu sunt enumerate individual; tabelul include endpointurile tehnice, feed-urile și descărcările care fac parte din suprafața publică funcțională/crawlable.

| Rută | Tip | HTTP așteptat | Indexabilitate |
|---|---|---|---|
| `/robots.txt` | robots policy | 200 | nu |
| `/sitemap.xml` | sitemap index | 200 | nu (X-Robots-Tag) |
| `/sitemap-programs.xml` | sitemap urlset | 200 | nu |
| `/sitemap-guides.xml` | sitemap urlset | 200 | nu |
| `/sitemap-core.xml` | sitemap urlset | 200 | nu |
| `/feed.xml` | feed XML | 200 | nu |
| `/llms.txt` | crawler/LLM index | 200 | nu (X-Robots-Tag) |
| `/blog.json` | date blog runtime | 200 | nu |
| `/official-guides.json` | surse oficiale runtime | 200 | nu (X-Robots-Tag) |
| `/site.webmanifest` | web manifest | 200 | nu |
| `/release.json` | artefact build/SHA | 200 | nu (X-Robots-Tag) |
| `/indexnow-key.txt` | cheie publică IndexNow | 200 | nu |
| `/a54d3e71f7854ddd9b9fc4cb91c7d681.txt` | token verificare | 200 | nu |
| `/google8bbb9999c523a3bd.html` | token Google legacy | 301 spre forma fără .html | nu |
| `/resurse/descarcari/checklist-documente-fonduri-europene.pdf` | download | 200 | nu |
| `/resurse/descarcari/checklist-afir-dr12-dr14.pdf` | download | 200 | nu |
| `/resurse/descarcari/calendar-pregatire-depunere.xlsx` | download | 200 | nu |
| `/resurse/descarcari/buget-digitalizare-imm.xlsx` | download | 200 | nu |
| `/api/contact-triage` | API formular; POST | GET 405; POST 200/4xx/5xx | nu; /api blocat în robots |
| `/api/crm/qualified-lead` | API server-side; POST autentificat | GET 405; POST 202/4xx/5xx | nu; /api blocat în robots |

## Diferențe repo vs sitemap vs homepage vs catalog

- Repo public vs sitemap local: **1 rute repo lipsă din sitemap** (`/gdpr`) și **0 URL-uri sitemap fără rută**.
- Orfane indexabile după scanarea linkurilor din cele 105 surse canonical: **0**.
- Homepage/catalog: **23** programe configurate pe homepage, **23** listate și **23** bannere active.
- Bannere fără program: **0**; programe listate fără banner: **0**.
- Suprafețe publice servite dar intenționat în afara sitemap-ului: redirecturile, `/404`, `/admin`, endpointurile tehnice și fișierele non-page.
- Suprafețe HTML publice neintenționat indexabile și fără canonical: `/partials/global-header`, `/templates/dr14-final-content`, `/templates/dr18-final-content`. Acestea provin din politica de copiere a build-ului, nu din router sau sitemap.

## Verificare live

Nu s-a executat verificarea live în această regenerare.

## Probleme și priorități rămase (fără remediere în Task 01)

- **P0 existent:** `/contact` păstrează inconsistența de stare legală, iar Clarity nu are un gate de consent identificabil (`T00-003`, `T00-004`).
- **P1:** cele trei fragmente `/partials/*` și `/templates/*` sunt HTML 200 indexabil, fără canonical/noindex și fără rol de pagină publică. Politica build trebuie să le excludă sau să le protejeze într-un task separat.
- **P1:** registry-ul de pagini conține definiții pentru rute care sunt acum 301; trebuie consolidat fără pierderea URL equity.
- **P1:** `/gdpr` este 200/self-canonical/indexabil, dar lipsește intenționat din sitemap prin `duplicate_policy_pending_legal_consolidation`; consolidarea juridică și SEO este încă neaprobată.
- **P1 existent:** fișierele fizice duplicate și listele de precedență canonical rămân surse paralele (`T00-007`, `T00-008`).
- **P1 existent:** validatorul SEO raportează linkuri interne către surse de redirect (`T00-017`).
- **P1:** `/admin` este o suprafață publică protejată doar prin UI/localStorage, nu o zonă autentificată server-side; rolul ei operațional și expunerea trebuie revizuite separat.
- **P2:** `/cookies`, `/echipa`, `/date-companie` și `/anpc` nu există ca rute standalone; conținutul/destinația există în paginile canonical sau extern și nu justifică automat URL-uri noi.
- **P2:** forma explicită `/404` răspunde 200, în timp ce fallback-ul real răspunde corect 404; documentația/testele trebuie să folosească o rută inexistentă pentru status.

## Verificarea automată adăugată

`npm run test:route-inventory` validează unicitatea rutelor/canonicalelor publicate, slugurile de program/pagină, ID-urile de banner, paritatea sitemap, acoperirea bannerelor și lipsa rutelor orfane. Duplicatele fizice intenționate sunt enumerate în raport și rămân vizibile pentru review.
