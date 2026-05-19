# Audit initial SEO + AI visibility

Data audit: 2026-05-20  
Proiect: `atelierdeconsultanta.ro`  
Scope: inspectie locala a structurii si a HTML-ului existent. Nu am modificat codul sau continutul public in acest pas.

## Rezumat executiv

- Site-ul este un proiect static HTML, fara framework frontend detectat. Exista un set de tool-uri Node.js care genereaza pagini SEO, sitemap, llms.txt si asset-uri pentru Cloudflare Pages.
- Am detectat 128 fisiere HTML, dintre care 83 par indexabile si 45 sunt pagini tehnice/noindex/redirect fallback.
- `sitemap.xml` contine 82 URL-uri. Diferenta fata de cele 83 pagini indexabile detectate vine din fisierul tehnic `google8bbb9999c523a3bd.html`, care nu are meta/canonical si nu pare pagina de continut.
- Exista acoperire buna pentru `robots.txt`, `llms.txt`, canonical, FAQPage si SpeakableSpecification.
- Riscurile majore pentru AI visibility sunt: surse oficiale randate doar prin JavaScript pe unele pagini, lipsa reviewerului pe toate paginile indexabile, lipsa autorului pe majoritatea paginilor, template-uri repetate masiv si pagini locale cu continut local minimal.
- Worktree-ul era deja modificat inainte de audit; raportul de fata trateaza starea curenta a fisierelor din workspace.

## 1. Stack detectat

### Framework / generator / CMS

- Framework frontend: nu am detectat React/Vite/Next/Astro/Hugo/Jekyll. Site-ul este static HTML.
- Generator local: Node.js custom scripts in `tools/` si `scripts/`.
- CMS: nu exista CMS headless. Exista un admin static in `admin/index.html` care editeaza prin GitHub API fisiere ca `banners.json`, `blog.json` si `official-guides.json`.
- Deploy:
  - `wrangler.jsonc` indica Cloudflare Pages/Workers Assets cu `dist` si build command.
  - `netlify.toml` publica radacina proiectului.
  - `README.md` mentioneaza istoric GitHub Pages.
  - `CNAME` indica domeniul custom.

### Foldere si fisiere relevante

- Pagini statice:
  - radacina: multe fisiere `*.html`, de exemplu `index.html`, `dr12-afir.html`, `digitalizare-imm.html`.
  - directoare cu `index.html`: `consultanta-fonduri-europene/`, `fonduri-europene/`, `pnrr/`, `afir/`, `fonduri-europene-caen/**`, `intrebari/**` etc.
- Pagini locale:
  - `fonduri-europene-iasi/`, `fonduri-europene-suceava/`, `fonduri-europene-bacau/`, `fonduri-europene-bucuresti/`.
  - `consultanta-fonduri-europene-iasi/`, `consultanta-fonduri-europene-suceava/`, `consultanta-fonduri-europene-bacau/`, `consultanta-fonduri-europene-bucuresti/`.
- Date/config:
  - `banners.json`
  - `blog.json`
  - `official-guides.json`
  - `config/seo-programs.json`
  - `config/seo-programmatic-pages.json`
  - `config/seo-blog-article.example.json`
- Tool-uri generare/verificare:
  - `tools/generate-program-pages.js`
  - `tools/generate-programmatic-seo.js`
  - `tools/generate-seo-hubs.js`
  - `tools/generate-seo-blog-article.js`
  - `tools/extract-source-facts.js`
  - `tools/audit-content-depth.js`
  - `tools/audit-site-links.js`
  - `scripts/verify-seo-integrity.js`
  - `scripts/visual-integrity-check.js`
- Asset-uri SEO/AI:
  - `assets/official-guides.js`
  - `assets/official-guides.min.js`
  - `assets/seo-hub.css`
  - `assets/seo-tools.js`
  - `assets/program-scoring.js`
- Crawl/discovery:
  - `robots.txt`
  - `sitemap.xml`
  - `llms.txt`
  - `_redirects`

### Comenzi detectate

Din `package.json`:

- Build:
  - `npm run build` -> `node tools/build-cloudflare-assets.js`
  - `npm run deploy`
  - `npm run deploy:pages`
- Validare/verificare:
  - `npm run verify:seo`
  - `npm run verify:visual`
  - `npm run verify:functional`
  - `npm run verify:all`
  - `npm run validate:cloudflare`
- Audit:
  - `npm run audit:content`
  - `npm run audit:program-routes`
  - `npm run audit:gsc-routes`
- Generare continut:
  - `npm run generate:program-pages`
  - `npm run generate:programmatic-seo`
  - `npm run generate:lead-magnets`
  - `npm run extract:sources`
- Lint/test clasic: nu exista script dedicat `lint` sau `test`.

## 2. Inventar pagini

Legenda:

- `self` la canonical inseamna `https://atelierdeconsultanta.ro` + URL-ul din prima coloana.
- Descrierile lungi sunt abreviate pentru lizibilitate; existenta si directia lor au fost verificate in fisierele HTML.
- Schema listeaza tipurile relevante, nu toate nodurile interne `Question`, `Answer` sau `ListItem`.

| URL / fisier | Tip | H1 detectat | Meta title | Meta description | Canonical | Structured data |
|---|---|---|---|---|---|---|
| `/`<br>`index.html` | homepage | Transformam ideile tale in Transformam ideile tale in proiecte finantate | Atelier de Consultanta \| Fonduri Europene si Finantari Nerambursabile | Consultanta pentru fonduri europene, AFIR, PNRR, Start-Up Nation si finantari nerambursabile... | self | LocalBusiness, ProfessionalService, WebSite, FAQPage, Organization |
| `/acte-necesare-fonduri-europene-nerambursabile`<br>`acte-necesare-fonduri-europene-nerambursabile.html` | blog/resursa | Acte necesare pentru fonduri europene nerambursabile | Acte necesare pentru fonduri europene - checklist dosar | Lista de acte necesare pentru fonduri europene: documente firma, financiare, tehnice... | self | WebPage, SpeakableSpecification, FAQPage |
| `/afir`<br>`afir/index.html` | program | AFIR: fonduri pentru fermieri si proiecte agricole | AFIR - fonduri pentru fermieri, DR12, DR14 si energie | Hub AFIR cu programe pentru fermieri: DR12, DR14, calculator SO, utilaje... | self | WebPage, SpeakableSpecification, FAQPage |
| `/afir-autoconsum-agroalimentar`<br>`afir-autoconsum-agroalimentar.html` | program | AFIR autoconsum agroalimentar: finantare pentru energie in sectorul agroalimentar | AFIR autoconsum agroalimentar - fotovoltaice, eligibilitate si dosar | Ghid AFIR autoconsum agroalimentar: panouri fotovoltaice, eligibilitate, documente... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/autoconsum-public-fotovoltaice-institutii-publice`<br>`autoconsum-public-fotovoltaice-institutii-publice.html` | program | Autoconsum public: fotovoltaice pentru institutii publice | Fotovoltaice pentru institutii publice - autoconsum si dosar | Ghid pentru finantari fotovoltaice destinate institutiilor publice: eligibilitate, documente... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/blog`<br>`blog.html` | blog/resursa | Blog despre fonduri europene, finantari nerambursabile si programe pentru antreprenori | Blog Fonduri Europene \| FABER - Atelier de Consultanta | Ghiduri despre fonduri europene 2026, AFIR, Start-Up Nation, Femeia Antreprenor... | self | Blog, Organization, FAQPage |
| `/blog-afir-fotovoltaice-ferme-2026`<br>`blog-afir-fotovoltaice-ferme-2026.html` | blog/resursa | AFIR Fotovoltaice Ferme 2026 - Ghid Complet: Pana la 500.000 Euro Nerambursabil | AFIR Fotovoltaice Ferme 2026 - Ghid Complet \| FABER | Ghid AFIR Autoconsum Agroalimentar 2026: eligibilitate, cheltuieli acoperite, pasi... | self | Article, Organization, FAQPage |
| `/calculator-soc`<br>`calculator-soc.html` | program/instrument | Calculator Standard Output (SO) | Calculator SO AFIR DR12 DR14 \| FABER | Calculator Standard Output (SO) pentru programele AFIR DR12 si DR14... | self | FAQPage, WebApplication, Organization, WebPage, SpeakableSpecification |
| `/calendar-fonduri-europene`<br>`calendar-fonduri-europene/index.html` | program/resursa | Calendar fonduri europene | Calendar fonduri europene 2026 - programe si pregatire | Calendar fonduri europene 2026: cum urmaresti programe, termene, documente, ghiduri... | self | WebPage, SpeakableSpecification, FAQPage |
| `/cat-costa-consultanta-fonduri-europene`<br>`cat-costa-consultanta-fonduri-europene/index.html` | serviciu | Cat costa consultanta pentru fonduri europene | Cat costa consultanta fonduri europene - factori si etape | Cat costa consultanta pentru fonduri europene: factori, servicii incluse, complexitatea proiectului... | self | WebPage, SpeakableSpecification, FAQPage |
| `/cod-caen-start-up-nation-2026`<br>`cod-caen-start-up-nation-2026/index.html` | program/resursa | Cod CAEN Start Up Nation 2026: cum verifici activitatea eligibila | Cod CAEN Start Up Nation 2026 - verificare activitate | Cod CAEN Start Up Nation 2026: cum verifici activitatea eligibila, autorizarea, bugetul... | self | WebPage, SpeakableSpecification, FAQPage |
| `/consultant-fonduri-europene-imm`<br>`consultant-fonduri-europene-imm/index.html` | serviciu | Consultant fonduri europene pentru IMM-uri | Consultant fonduri europene IMM - verificare si dosar | Consultant fonduri europene IMM pentru verificare eligibilitate, program potrivit, granturi IMM 2026... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/consultanta-afir`<br>`consultanta-afir/index.html` | serviciu | Consultanta AFIR | Consultanta AFIR - DR12, DR14 si proiecte agricole | Consultanta AFIR pentru DR12, DR14, ferme mici, tineri fermieri, calculator SO... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/consultanta-fonduri-europene`<br>`consultanta-fonduri-europene/index.html` | serviciu | Consultanta fonduri europene pentru firme, fermieri si antreprenori | Consultanta fonduri europene pentru firme si antreprenori | Servicii de consultanta fonduri europene: eligibilitate, program potrivit, documente, buget... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/consultanta-fonduri-europene-bacau`<br>`consultanta-fonduri-europene-bacau/index.html` | local | Consultanta fonduri europene Bacau | Consultanta fonduri europene Bacau | Consultanta pentru fonduri europene in Bacau: programe active, documente, eligibilitate... | self | WebPage, SpeakableSpecification, FAQPage |
| `/consultanta-fonduri-europene-bucuresti`<br>`consultanta-fonduri-europene-bucuresti/index.html` | local | Consultanta fonduri europene Bucuresti | Consultanta fonduri europene Bucuresti | Consultanta pentru fonduri europene in Bucuresti: programe active, documente, eligibilitate... | self | WebPage, SpeakableSpecification, FAQPage |
| `/consultanta-fonduri-europene-iasi`<br>`consultanta-fonduri-europene-iasi/index.html` | local | Consultanta fonduri europene Iasi | Consultanta fonduri europene Iasi | Consultanta pentru fonduri europene in Iasi: programe active, documente, eligibilitate... | self | WebPage, SpeakableSpecification, FAQPage |
| `/consultanta-fonduri-europene-suceava`<br>`consultanta-fonduri-europene-suceava/index.html` | local | Consultanta fonduri europene Suceava | Consultanta fonduri europene Suceava | Consultanta pentru fonduri europene in Suceava: programe active, documente, eligibilitate... | self | WebPage, SpeakableSpecification, FAQPage |
| `/consultanta-pnrr-digitalizare`<br>`consultanta-pnrr-digitalizare/index.html` | serviciu | Consultanta PNRR digitalizare | Consultanta PNRR Digitalizare - eligibilitate IMM | Consultanta PNRR Digitalizare pentru IMM: eligibilitate, software, hardware, buget, documente... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/consultanta-start-up-nation-2026`<br>`consultanta-start-up-nation-2026/index.html` | serviciu | Consultanta Start Up Nation 2026: verificare, dosar si depunere | Consultanta Start Up Nation 2026 - verificare si dosar | Consultanta Start Up Nation 2026 pentru eligibilitate, cod CAEN, buget, plan de afaceri... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/contact`<br>`contact/index.html` | contact | Contact FABER | Contact Atelier de Consultanta \| Evaluare Eligibilitate Fonduri Europene | Contacteaza Atelier de Consultanta pentru o discutie despre eligibilitatea proiectului tau... | self | LocalBusiness, Organization, ContactPage, WebSite |
| `/cum-alegi-consultant-fonduri-europene`<br>`cum-alegi-consultant-fonduri-europene/index.html` | blog/resursa | Cum alegi un consultant pentru fonduri europene | Cum alegi consultant fonduri europene - criterii utile | Cum alegi un consultant pentru fonduri europene: experienta, transparenta, servicii, contract... | self | WebPage, SpeakableSpecification, FAQPage |
| `/cum-alegi-programul-potrivit-fonduri-europene-2026`<br>`cum-alegi-programul-potrivit-fonduri-europene-2026.html` | blog/resursa | Cum alegi programul potrivit de fonduri europene in 2026 | Cum alegi fonduri europene in 2026 \| FABER | Ghid practic pentru alegerea programului potrivit de fonduri europene in 2026... | self | BlogPosting, Organization, WebPage, FAQPage |
| `/digitalizare-imm`<br>`digitalizare-imm.html` | program/serviciu | Digitalizare IMM: eligibilitate, cheltuieli si buget pentru proiect | Digitalizare IMM 2026 - cheltuieli, eligibilitate si proiect | Ghid Digitalizare IMM: software, echipamente, securitate, cloud, eligibilitate, buget... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/digitalizare-imm-pnrr`<br>`digitalizare-imm-pnrr/index.html` | program | Digitalizare IMM / PNRR | Digitalizare IMM PNRR - software, echipamente si pasi | Digitalizare IMM PNRR: eligibilitate, software, echipamente, servicii digitale, securitate... | self | WebPage, SpeakableSpecification, FAQPage |
| `/dr12-afir`<br>`dr12-afir.html` | program | DR 12 AFIR pentru tineri fermieri: eligibilitate, investitii si pasi de pregatire | DR 12 AFIR 2026 - Tineri fermieri, eligibilitate si dosar | Ghid DR 12 AFIR pentru tineri fermieri: eligibilitate, investitii, cheltuieli... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/dr14`<br>`dr14.html` | program | DR 14 AFIR pentru ferme mici: conditii, cheltuieli si pregatirea dosarului | DR 14 AFIR 2026 - Ferme mici, eligibilitate, punctaj si dosar | Ghid DR 14 AFIR pentru ferme mici: conditii de eligibilitate, investitii, cheltuieli... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/dr-12-afir-instalarea-tinerilor-fermieri`<br>`dr-12-afir-instalarea-tinerilor-fermieri.html` | blog/resursa | DR 12 AFIR si instalarea tinerilor fermieri: ce trebuie pregatit | DR 12 AFIR - Instalarea tinerilor fermieri | Ghid pentru tinerii fermieri interesati de DR 12 AFIR: eligibilitate, documente... | self | BlogPosting, Organization, WebPage, FAQPage |
| `/dr-14-afir-conditii-eligibilitate-greseli-frecvente`<br>`dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` | blog/resursa | DR 14 AFIR: conditii, eligibilitate si greseli frecvente | DR 14 AFIR - Conditii si greseli frecvente | Ghid despre DR 14 AFIR pentru ferme mici: eligibilitate, pregatirea dosarului... | self | BlogPosting, Organization, WebPage, FAQPage |
| `/eligibilitate-fonduri-europene`<br>`eligibilitate-fonduri-europene/index.html` | serviciu | Eligibilitate fonduri europene | Eligibilitate fonduri europene - firma, CAEN si proiect | Eligibilitate fonduri europene: cum verifici firma, codul CAEN, localitatea, investitia... | self | WebPage, SpeakableSpecification, FAQPage |
| `/femeia-antreprenor-2026`<br>`femeia-antreprenor-2026.html` | program | Femeia Antreprenor 2026: conditii, cheltuieli si pasi pentru dosar | Femeia Antreprenor 2026 - eligibilitate, buget si dosar | Ghid Femeia Antreprenor 2026: conditii pentru firme, actionariat, cheltuieli eligibile... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/femeia-antreprenor-2026-conditii-idei-afaceri`<br>`femeia-antreprenor-2026-conditii-idei-afaceri.html` | blog/resursa | Femeia Antreprenor 2026: conditii, idei de afaceri si pregatire | Femeia Antreprenor 2026 - Conditii si idei | Ghid pentru femeile antreprenor care vor sa pregateasca o afacere finantabila... | self | BlogPosting, Organization, WebPage, FAQPage |
| `/finantari-panouri-fotovoltaice`<br>`finantari-panouri-fotovoltaice/index.html` | program | Finantari pentru panouri fotovoltaice | Finantari panouri fotovoltaice - autoconsum si energie | Finantari pentru panouri fotovoltaice: autoconsum, energie regenerabila, Fondul pentru Modernizare... | self | WebPage, SpeakableSpecification, FAQPage |
| `/firma-consultanta-fonduri-europene`<br>`firma-consultanta-fonduri-europene/index.html` | serviciu | Firma de consultanta pentru fonduri europene | Firma consultanta fonduri europene - criterii si servicii | Cum alegi o firma de consultanta fonduri europene: servicii, verificare, diferente fata de freelancer... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/fondul-de-modernizare`<br>`fondul-de-modernizare/index.html` | program | Fondul de Modernizare: index pentru masurile de finantare | Fondul de Modernizare - energie si finantari 2026 | Fondul de Modernizare: index pentru energie regenerabila, fotovoltaice, autoconsum, eficienta energetica... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum`<br>`fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html` | program | Fondul de Modernizare: finantari pentru energie, fotovoltaice si autoconsum | Fondul de Modernizare - energie, fotovoltaice si autoconsum | Ghid Fondul de Modernizare pentru energie, fotovoltaice si autoconsum: eligibilitate, cheltuieli... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/fondul-modernizare-energie-regenerabila-2026`<br>`fondul-modernizare-energie-regenerabila-2026.html` | program | Fondul pentru Modernizare: capacitati noi de producere a energiei regenerabile | Fondul pentru Modernizare energie regenerabila 2026 - ghid proiect | Pagina pentru investitii in noi capacitati de producere a energiei electrice regenerabile... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/fonduri-europene`<br>`fonduri-europene/index.html` | program/hub | Fonduri europene in Romania | Fonduri europene in Romania - programe, eligibilitate si ghiduri | Hub despre fonduri europene: programe pentru IMM-uri, agricultura, digitalizare, energie... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-agricultura`<br>`fonduri-europene-agricultura/index.html` | program | Fonduri europene pentru agricultura | Fonduri europene pentru agricultura - AFIR, ferme si utilaje | Ghid pentru fonduri europene in agricultura: DR12, DR14, ferme, utilaje, SO... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/fonduri-europene-bacau`<br>`fonduri-europene-bacau/index.html` | local | Fonduri europene Bacau | Fonduri europene Bacau | Ghid fonduri europene pentru Bacau: programe active, regiune, IMM-uri, agricultura, digitalizare... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-bucuresti`<br>`fonduri-europene-bucuresti/index.html` | local | Fonduri europene Bucuresti | Fonduri europene Bucuresti | Ghid fonduri europene pentru Bucuresti: programe active, regiune, IMM-uri, agricultura... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-iasi`<br>`fonduri-europene-iasi/index.html` | local | Fonduri europene Iasi | Fonduri europene Iasi | Ghid fonduri europene pentru Iasi: programe active, regiune, IMM-uri, agricultura, digitalizare... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-suceava`<br>`fonduri-europene-suceava/index.html` | local | Fonduri europene Suceava | Fonduri europene Suceava | Ghid fonduri europene pentru Suceava: programe active, regiune, IMM-uri, agricultura... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-caen/0111-culturi-cereale`<br>`fonduri-europene-caen/0111-culturi-cereale/index.html` | program/CAEN | Fonduri europene pentru CAEN 0111 - culturi de cereale | Fonduri europene pentru CAEN 0111 - culturi de cereale | Ghid pentru CAEN 0111: programe posibile, investitii eligibile, documente, punctaj... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-caen/4321-instalatii-electrice`<br>`fonduri-europene-caen/4321-instalatii-electrice/index.html` | program/CAEN | Fonduri europene pentru CAEN 4321 - instalatii electrice | Fonduri europene pentru CAEN 4321 - instalatii electrice | Ghid pentru CAEN 4321: programe posibile, investitii eligibile, documente, punctaj... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-caen/5610-restaurante`<br>`fonduri-europene-caen/5610-restaurante/index.html` | program/CAEN | Fonduri europene pentru CAEN 5610 - restaurante si servicii alimentare | Fonduri europene pentru CAEN 5610 - restaurante si servicii alimentare | Ghid pentru CAEN 5610: programe posibile, investitii eligibile, documente, punctaj... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-caen/6201-dezvoltare-software`<br>`fonduri-europene-caen/6201-dezvoltare-software/index.html` | program/CAEN | Fonduri europene pentru CAEN 6201 - dezvoltare software | Fonduri europene pentru CAEN 6201 - dezvoltare software | Ghid pentru CAEN 6201: programe posibile, investitii eligibile, documente, punctaj... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-digitalizare`<br>`fonduri-europene-digitalizare/index.html` | program | Fonduri europene pentru digitalizare | Fonduri europene pentru digitalizare - IMM, PNRR, software | Hub pentru fonduri de digitalizare: Digitalizare IMM, PNRR, software, securitate, cloud... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/fonduri-europene-femei-antreprenor`<br>`fonduri-europene-femei-antreprenor/index.html` | program | Fonduri europene pentru femei antreprenor | Fonduri europene femei antreprenor 2026 - ghid | Fonduri europene pentru femei antreprenor 2026: programe, grant Femeia Antreprenor... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-europene-imm`<br>`fonduri-europene-imm/index.html` | program/serviciu | Fonduri europene pentru IMM-uri | Fonduri europene pentru IMM-uri - investitii, digitalizare, energie | Ghid pentru IMM-uri care cauta fonduri europene: programe regionale, digitalizare, energie... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/fonduri-europene-nerambursabile-2026`<br>`fonduri-europene-nerambursabile-2026/index.html` | program/hub | Fonduri europene nerambursabile 2026: programe, eligibilitate si pasi | Fonduri europene nerambursabile 2026 - programe si pasi | Revista programelor de fonduri europene nerambursabile 2026: IMM, tineri, rural... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-nerambursabile`<br>`fonduri-nerambursabile/index.html` | program/hub | Fonduri nerambursabile | Fonduri nerambursabile - programe, cofinantare si pasi | Explicatii despre fonduri nerambursabile, eligibilitate, cofinantare, documente, cheltuieli... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-pentru-ferme`<br>`fonduri-pentru-ferme/index.html` | program | Fonduri pentru ferme | Fonduri pentru ferme - AFIR, DR12, DR14 si utilaje | Fonduri pentru ferme: AFIR, DR12, DR14, calculator SO, utilaje, documente... | self | WebPage, SpeakableSpecification, FAQPage |
| `/fonduri-pentru-utilaje-agricole`<br>`fonduri-pentru-utilaje-agricole/index.html` | program | Fonduri pentru utilaje agricole | Fonduri pentru utilaje agricole - eligibilitate si buget | Fonduri pentru utilaje agricole: DR12, DR14, ferme, calculator SO, cheltuieli eligibile... | self | WebPage, SpeakableSpecification, FAQPage |
| `/gdpr`<br>`gdpr.html` | legal | Politica GDPR | Politica GDPR \| FABER - Atelier de Consultanta | Politica GDPR FABER - Atelier de Consultanta. Drepturile tale conform Regulamentului GDPR... | self | - |
| `/ghiduri`<br>`ghiduri/index.html` | blog/resursa | Ghiduri pentru fonduri europene | Ghiduri fonduri europene - documente, checklisturi si resurse | Colectie de ghiduri, checklisturi si resurse pentru fonduri europene: DR12, DR14... | self | CollectionPage, SpeakableSpecification, FAQPage |
| `/google8bbb9999c523a3bd`<br>`google8bbb9999c523a3bd.html` | tehnic | lipsa | lipsa | lipsa | lipsa | - |
| `/granturi-digitalizare-imm`<br>`granturi-digitalizare-imm/index.html` | program | Granturi pentru digitalizarea IMM-urilor | Granturi Digitalizare IMM 2026 - software si echipamente | Granturi Digitalizare IMM 2026: software, hardware, cloud, securitate, servicii, eligibilitate... | self | WebPage, SpeakableSpecification, FAQPage |
| `/greseli-fonduri-europene`<br>`greseli-fonduri-europene/index.html` | blog/resursa | Greseli frecvente la fonduri europene | Greseli fonduri europene - ce verifici inainte | Greseli frecvente la fonduri europene: eligibilitate, documente, buget, cheltuieli neeligibile... | self | WebPage, SpeakableSpecification, FAQPage |
| `/idei-afaceri-fonduri-europene`<br>`idei-afaceri-fonduri-europene.html` | blog/resursa | Idei de afaceri cu fonduri europene | Idei de afaceri cu fonduri europene | Ghid cu idei de afaceri cu fonduri europene, programe eligibile, criterii de analiza... | self | Article, Organization, WebPage, FAQPage |
| `/instrumente`<br>`instrumente/index.html` | program/instrument | Instrumente interactive pentru fonduri europene | Instrumente fonduri europene - calculatoare si checklisturi | Instrumente pentru fonduri europene: calculator cofinantare, eligibilitate rapida, buget Digitalizare IMM... | self | WebPage, SpeakableSpecification, FAQPage, WebApplication |
| `/intrebari-frecvente`<br>`intrebari-frecvente/index.html` | blog/resursa | Intrebari frecvente despre fonduri europene | Intrebari frecvente fonduri europene - eligibilitate si dosar | Intrebari frecvente despre fonduri europene: eligibilitate, documente, cofinantare, cheltuieli... | self | WebPage, SpeakableSpecification, FAQPage |
| `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm`<br>`intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html` | blog/resursa | Ce cheltuieli sunt eligibile la Digitalizare IMM? | Ce cheltuieli sunt eligibile la Digitalizare IMM? | Pot fi eligibile software, echipamente IT, servicii cloud, securitate cibernetica... | self | WebPage, SpeakableSpecification, FAQPage |
| `/intrebari/ce-documente-sunt-necesare-pentru-dr12`<br>`intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html` | blog/resursa | Ce documente sunt necesare pentru DR12? | Ce documente sunt necesare pentru DR12? | Pentru DR12 sunt importante documentele solicitantului, exploatatiei, calculul SO... | self | WebPage, SpeakableSpecification, FAQPage |
| `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene`<br>`intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html` | blog/resursa | Cum se calculeaza cofinantarea la fonduri europene? | Cum se calculeaza cofinantarea la fonduri europene? | Cofinantarea se calculeaza pornind de la valoarea eligibila, procentul nerambursabil... | self | WebPage, SpeakableSpecification, FAQPage |
| `/investitii-modernizarea-microintreprinderilor-apel-2`<br>`investitii-modernizarea-microintreprinderilor-apel-2.html` | program | Investitii pentru modernizarea microintreprinderilor - Apel 2 | Modernizarea microintreprinderilor - Apel 2: eligibilitate si dosar | Pagina pentru Apelul 2 privind modernizarea microintreprinderilor: conditii, cheltuieli eligibile... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/pnrr`<br>`pnrr/index.html` | program/hub | PNRR pentru IMM-uri si proiecte de digitalizare | PNRR pentru IMM-uri - digitalizare, documente si proiecte | Hub PNRR pentru IMM-uri: digitalizare, cheltuieli, documente, indicatori, implementare... | self | WebPage, SpeakableSpecification, FAQPage |
| `/pnrr-digitalizare-imm-cheltuieli-eligibile`<br>`pnrr-digitalizare-imm-cheltuieli-eligibile.html` | blog/resursa | PNRR Digitalizare IMM: ce poti cumpara prin finantare | PNRR Digitalizare IMM - Cheltuieli eligibile | Ghid despre digitalizarea IMM-urilor prin finantari nerambursabile: software, echipamente, securitate... | self | BlogPosting, Organization, WebPage, FAQPage |
| `/politica-de-confidentialitate`<br>`politica-de-confidentialitate.html` | legal | Politica de Confidentialitate | Politica de Confidentialitate \| FABER | Politica de confidentialitate FABER - Atelier de Consultanta. Cum colectam, utilizam si protejam datele... | self | - |
| `/por-adr-nord-est`<br>`por-adr-nord-est.html` | program | Investitii pentru modernizarea microintreprinderilor in Nord-Est | Modernizarea microintreprinderilor Nord-Est - eligibilitate si dosar | Ghid pentru investitii in modernizarea microintreprinderilor din Nord-Est: eligibilitate, cheltuieli... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/portofoliu`<br>`portofoliu/index.html` | portofoliu | Portofoliu de proiecte si domenii de finantare | Portofoliu proiecte fonduri europene - exemple publicabile | Portofoliu publicabil pentru proiecte de consultanta fonduri europene, cu exemple anonimizate... | self | CollectionPage, SpeakableSpecification, FAQPage |
| `/pro-infra`<br>`pro-infra.html` | program | PRO INFRA 2026: investitii, energie si pregatirea dosarului | PRO INFRA 2026 - energie, investitii si eligibilitate | Ghid PRO INFRA si programe energie 2026: conditii, investitii eligibile, energie verde... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/resurse`<br>`resurse/index.html` | resursa | Resurse descarcabile pentru pregatirea dosarului | Resurse descarcabile fonduri europene - PDF si Excel | Resurse descarcabile pentru fonduri europene: checklisturi PDF si Excel pentru documente, buget... | self | CollectionPage, SpeakableSpecification, FAQPage |
| `/start-up-nation-2026`<br>`start-up-nation-2026.html` | program | Start-Up Nation 2026: conditii, buget, cod CAEN si pasi de aplicare | Start-Up Nation 2026 - conditii, cheltuieli, punctaj si plan | Ghid Start-Up Nation 2026: eligibilitate, cod CAEN, cheltuieli eligibile, plan de afaceri... | self | WebPage, SpeakableSpecification, FAQPage, GovernmentService |
| `/start-up-nation-2026-cheltuieli-eligibile`<br>`start-up-nation-2026-cheltuieli-eligibile/index.html` | program | Start Up Nation 2026: cheltuieli eligibile | Start Up Nation 2026 cheltuieli eligibile - buget | Cheltuieli eligibile Start Up Nation 2026: echipamente, software, dotari, servicii, buget... | self | WebPage, SpeakableSpecification, FAQPage |
| `/start-up-nation-2026-conditii`<br>`start-up-nation-2026-conditii/index.html` | program | Start Up Nation 2026: conditii de verificat | Start Up Nation 2026 conditii - eligibilitate si CAEN | Conditii Start Up Nation 2026: solicitant, cod CAEN, buget, cheltuieli, documente... | self | WebPage, SpeakableSpecification, FAQPage |
| `/start-up-nation-2026-idei-afaceri`<br>`start-up-nation-2026-idei-afaceri/index.html` | program | Start Up Nation 2026: idei de afaceri | Start Up Nation 2026 idei de afaceri - CAEN si buget | Idei de afaceri Start Up Nation 2026: cum alegi activitatea, codul CAEN, bugetul... | self | WebPage, SpeakableSpecification, FAQPage |
| `/start-up-nation-2026-plan-de-afaceri`<br>`start-up-nation-2026-plan-de-afaceri/index.html` | program | Start Up Nation 2026: plan de afaceri | Start Up Nation 2026 plan de afaceri - structura | Plan de afaceri Start Up Nation 2026: structura, buget, piata, cheltuieli, cod CAEN... | self | WebPage, SpeakableSpecification, FAQPage |
| `/studii-de-caz`<br>`studii-de-caz/index.html` | studii de caz | Studii de caz pentru fonduri europene | Studii de caz fonduri europene - exemple anonimizate si lectii | Studii de caz anonimizate pentru proiecte cu fonduri europene: domeniu, provocare, solutie... | self | CollectionPage, SpeakableSpecification, FAQPage |
| `/termeni-si-conditii`<br>`termeni-si-conditii.html` | legal | Termeni si Conditii | Termeni si Conditii \| FABER - Atelier de Consultanta | Termeni si conditii FABER - Atelier de Consultanta. Conditiile generale de utilizare a serviciilor... | self | - |
| `/testimoniale`<br>`testimoniale/index.html` | testimoniale | Testimoniale si feedback publicabil | Testimoniale consultanta fonduri europene - opinii publicabile | Pagina pentru testimoniale veridice si aprobate despre consultanta pentru fonduri europene... | self | CollectionPage, SpeakableSpecification, FAQPage |
| `/verificare-eligibilitate-fonduri-europene`<br>`verificare-eligibilitate-fonduri-europene/index.html` | serviciu | Verificare eligibilitate fonduri europene | Verificare eligibilitate fonduri europene - analiza proiect | Verifica eligibilitatea pentru fonduri europene: firma, CAEN, regiune, investitie, documente... | self | WebPage, SpeakableSpecification, FAQPage, Service |
| `/webinarii`<br>`webinarii/index.html` | resursa/evenimente | Webinarii si evenimente despre fonduri europene | Webinarii fonduri europene - evenimente, ghiduri si rezumate | Pagina pentru webinarii si evenimente despre fonduri europene, cu program, inscriere, rezumate... | self | CollectionPage, SpeakableSpecification, FAQPage |

### Fisiere noindex / redirect fallback detectate

Acestea sunt pagini tehnice sau redirect fallback-uri HTML. In general au `meta robots="noindex, follow"` si canonical catre pagina tinta. Ele sunt utile ca protectie, dar cresc numarul de fisiere care impart acelasi canonical.

- `404.html` -> `/404`, `noindex, nofollow`.
- `admin/index.html` -> `/admin`, `noindex,nofollow`; contine adminul intern.
- Redirect fallback-uri catre canonical curat: `afir.html`, `calendar-fonduri-europene.html`, `cat-costa-consultanta-fonduri-europene.html`, `consultanta-fonduri-europene.html`, `consultanta-afir.html`, `consultanta-pnrr-digitalizare.html`, `consultanta-start-up-nation.html`, `consultanta-start-up-nation/index.html`, `contact.html`, `digitalizare-imm-pnrr.html`, `eligibilitate-fonduri-europene.html`, `finantari-panouri-fotovoltaice.html`, `firma-consultanta-fonduri-europene.html`, `fonduri-europene.html`, `fonduri-nerambursabile.html`, `fonduri-pentru-ferme.html`, `fonduri-pentru-utilaje-agricole.html`, `ghiduri.html`, `granturi-digitalizare-imm.html`, `greseli-fonduri-europene.html`, `intrebari-frecvente.html`, `pnrr.html`, `start-up-nation.html`, `start-up-nation/index.html`, `studii-de-caz.html` etc.
- Redirect-uri vechi/typo: `autoconsum-publici.html`, `fonduri-europene-herambursabile-2026.html`, `fonduri-europene-herambursabile-2026/index.html`, `start-up-nation-2026-idei-afaceri-plan.html`.
- Pagini indexabile duplicate conceptual, dar marcate noindex in unele variante: `femeia-antreprenor-2026/index.html` si `start-up-nation-2026/index.html` trimit canonical catre fisierele radacina.

### Observatii inventar

- Exista 37 grupuri de canonical cu mai mult de un fisier HTML. Majoritatea sunt intentionate, prin fallback/noindex.
- `google8bbb9999c523a3bd.html` este fisier tehnic de verificare Google. Nu are title, description, canonical sau robots. Nu este in sitemap, dar poate fi crawlabil daca este descoperit.
- Multe pagini au `FAQPage` si `SpeakableSpecification`, dar paginile legale nu au schema.

## 3. Risc de continut duplicat / template SEO

### Pagini locale

Pagini locale detectate:

- `fonduri-europene-iasi/`
- `fonduri-europene-suceava/`
- `fonduri-europene-bacau/`
- `fonduri-europene-bucuresti/`
- `consultanta-fonduri-europene-iasi/`
- `consultanta-fonduri-europene-suceava/`
- `consultanta-fonduri-europene-bacau/`
- `consultanta-fonduri-europene-bucuresti/`

Risc:

- Continutul local este in mare parte templated. Diferentele principale sunt orasul, regiunea si focusul scurt din `config/seo-programmatic-pages.json`.
- Paginile repeta aceleasi sectiuni: `Particularitati locale`, `Programe de verificat`, `Checklist local`, `Intrebari frecvente`, CTA.
- Pe paginile locale apar blocuri repetate de mai multe ori in acelasi fisier. Exemplu in `consultanta-fonduri-europene-iasi/index.html` si `fonduri-europene-iasi/index.html`: paragrafele despre potrivirea dintre solicitant, activitate, localitate, documente, investitie, buget si calendar se repeta de mai multe ori consecutiv.
- Nu am gasit dovezi clare de continut local real: birou local, exemple de proiecte locale, parteneriate locale, fotografii locale, date despre apeluri strict regionale, intrebari locale provenite din clienti.

Marcaj: `TODO_CLIENT` pentru dovezi locale reale, exemple publicabile si diferente validate pe fiecare oras/judet.

### Sectiuni text repetate

Am detectat blocuri care apar pe aproximativ 53 pagini indexabile, deci pot fi vazute ca template SEO:

- "Informatiile de pe aceasta pagina sunt construite pentru orientare practica..."
- "O eroare frecventa este pornirea de la lista de cumparaturi..."
- "Cheltuielile neeligibile sunt importante pentru cash-flow..."
- "Riscurile apar mai ales cand documentele nu spun aceeasi poveste..."
- "Cand pregatesti bugetul, evita rotunjirile agresive..."
- "Grila de selectie transforma conditiile programului in prioritati concrete..."
- "Pregatirea buna inseamna timp pentru clarificari..."
- "Un proiect bun pastreaza trasabilitate de la cerere pana la plata..."
- "Exemplele de mai jos sunt anonime si orientative..."

Acestea sunt utile ca mesaj, dar volumul repetarii dilueaza originalitatea paginilor.

### FAQ-uri repetate

Intrebari sau heading-uri repetate pe multe pagini:

- `Cui se adreseaza` - circa 53 pagini.
- `Conditii de eligibilitate` - circa 53 pagini.
- `Conditii obligatorii` - circa 53 pagini.
- `Investitii si cheltuieli eligibile` - circa 53 pagini.
- `Ce documente trebuie pregatite inainte de analiza?` - circa 24 pagini.
- `Cum se verifica un cod CAEN pentru fonduri europene?` - circa 24 pagini.
- `Verificarea garanteaza finantarea?` - circa 19 pagini.
- `Cand trebuie inceputa pregatirea?` - circa 18 pagini.
- `Ce date sunt utile pentru analiza?` - circa 18 pagini.
- `Pot compara mai multe programe?` - circa 18 pagini.

Recomandare: pastrati 1-2 FAQ-uri comune, dar transformati restul in intrebari specifice programului, tipului de beneficiar, regiunii sau documentelor concrete.

### Texte comerciale copiate identic

Multe CTA-uri sunt prudente si corecte, dar formula "Pentru o verificare initiala..." si blocurile "nu garanteaza aprobarea" apar repetitiv. Nu e o problema legala, dar pentru AI visibility poate parea continut generat in masa.

## 4. Unde sunt definite elementele SEO/AI

### `robots.txt`

- Fisier: `robots.txt`
- Permite crawl pentru user-agenti generali si AI relevanti: `OAI-SearchBot`, `ChatGPT-User`, `GPTBot`, `PerplexityBot`, `ClaudeBot`, `Claude-SearchBot`, `Claude-User`, `anthropic-ai`, `Claude-Web`, `Applebot`, `Google-Extended`, `CCBot`.
- Blocheaza `/admin/`.
- Include sitemap: `https://atelierdeconsultanta.ro/sitemap.xml`.
- Mentioneaza `llms.txt` ca fisier de context AI.

### `sitemap.xml`

- Fisier: `sitemap.xml`
- Contine 82 URL-uri, majoritatea cu `lastmod` 2026-05-19.
- Generatoare care pot actualiza sitemap:
  - `tools/generate-program-pages.js`
  - `tools/generate-programmatic-seo.js`
  - `tools/generate-seo-hubs.js`
  - `tools/generate-seo-blog-article.js`

### `llms.txt`

- Fisier: `llms.txt`
- Contine context pentru motoare AI, pagini principale, clustere tematice, note pentru modele AI si pagini noi pentru vizibilitate AI.
- `tools/generate-program-pages.js` are logica de completare a blocului "Pagini noi pentru vizibilitate AI".
- Data declarata in fisier: `Actualizat: 2026-05-03`. Sitemapul si multe pagini sunt la 2026-05-19, deci `llms.txt` pare ramas in urma.

### Schema JSON-LD

- Inline in paginile HTML: `<script type="application/ld+json">`.
- Generata in:
  - `tools/generate-program-pages.js`, functia `schemaGraph`.
  - `tools/generate-programmatic-seo.js`, functia `schema`.
  - `tools/generate-seo-hubs.js`.
  - `tools/generate-seo-blog-article.js`.
- Adminul poate edita primul script JSON-LD din pagina: `admin/index.html`.

### FAQ schema

- Detectata pe 78 pagini indexabile.
- Generata in aceleasi tool-uri de mai sus.
- Exista si FAQ vizibil in HTML pe majoritatea paginilor.

### Speakable schema

- Detectata pe 69 pagini indexabile.
- Generata in:
  - `tools/generate-program-pages.js`, cu selectorii `#speakable-summary`, `#speakable-eligibility`, `#speakable-cta`.
  - `tools/generate-programmatic-seo.js`, cu selectorii `#speakable-summary`, `#speakable-answer`.
- Exista blocuri vizibile cu `class="speakable"` si `data-speakable="true"`.

### Linkuri catre ghiduri oficiale

- Sursa de date: `official-guides.json`.
- Loader frontend: `assets/official-guides.js` si `assets/official-guides.min.js`.
- Admin: `admin/index.html` poate incarca si publica `official-guides.json`.
- Pagini care folosesc explicit `data-official-guide-key` si JS:
  - `index.html`
  - `dr-12-afir-instalarea-tinerilor-fermieri.html`
  - `dr-14-afir-conditii-eligibilitate-greseli-frecvente.html`
  - `femeia-antreprenor-2026-conditii-idei-afaceri.html`
  - `pnrr-digitalizare-imm-cheltuieli-eligibile.html`
- Problema: in aceste pagini linkul este initial `hidden` si capata `href` doar dupa fetch JS din `/official-guides.json`. Pentru AI/crawl HTML brut, sursa oficiala poate lipsi.

### `official-guides.json`

Fisier: `official-guides.json`

Chei detectate:

- `por-ne`
- `por-ne-apel-2`
- `dr12`
- `dr14`
- `digitalizare`
- `digitalizare-pnrr`
- `femeia`
- `pro-infra`
- `startup`
- `afir-autoconsum`
- `autoconsum-publici`
- `fondul-modernizare`
- `fondul-modernizare-regenerabile`
- `fonduri-europene`

Observatie: unele URL-uri sunt pagini generale de autoritate, nu ghiduri PDF precise. Este mai bine decat lipsa sursei, dar pentru citabilitate AI ar fi ideal ca fiecare claim numeric sa aiba sursa oficiala exacta, data verificarii si fragmentul/faptul extras.

## 5. Probleme critice pentru AI visibility

### Surse oficiale ascunse doar in JavaScript

Status: prezent pe pagini cheie.

- Linkurile catre ghiduri oficiale sunt populate cu JS in `index.html` si cateva articole importante.
- In HTML brut, anchor-ele au `hidden` si nu au `href`.
- Modelele AI si crawler-ele care nu executa JS pot rata sursa primara.

Prioritate: foarte mare.

### Lipsa autorului / reviewerului

Status:

- 74 din 83 pagini indexabile nu au autor detectabil in meta sau JSON-LD.
- 83 din 83 pagini indexabile nu au `reviewedBy` detectabil.
- Unele pagini de blog au `author` in `blog.json` sau `BlogPosting`, dar patternul nu este uniform.

Impact:

- Slabeste E-E-A-T si increderea LLM-urilor in continut, mai ales pentru subiect financiar/finantari publice.

Marcaj: `TODO_CLIENT` pentru nume autor/reviewer, rol, acreditari publicabile, politica editoriala si data ultimei verificari.

### Lipsa datei de actualizare

Status:

- 17 pagini indexabile nu au data de actualizare detectabila in HTML/JSON-LD.
- Exemple: paginile locale, paginile CAEN si intrebarile programatice.
- `llms.txt` este la 2026-05-03, in timp ce sitemap si pagini generate sunt la 2026-05-19.

Impact:

- Fondurile europene sunt informationale si temporale. Fara data clara, AI-ul poate evita citarea sau poate considera informatia invechita.

### Lipsa paginilor de metodologie

Status:

- Nu am gasit o pagina dedicata de metodologie editoriala, metodologie de verificare a eligibilitatii, politica de actualizare a ghidurilor sau surse folosite.

Marcaj: `TODO_CLIENT` pentru:

- cine verifica informatiile;
- cat de des se revizuiesc ghidurile;
- cum se trateaza programele inchise / in consultare / active;
- cum sunt validate sumele si procentele;
- ce inseamna "orientativ" vs "verificat in ghidul oficial".

### Lipsa studiilor de caz reale

Status:

- Exista `/studii-de-caz` si `/portofoliu`, dar continutul pare placeholder/anonimizat generic.
- Nu am gasit studii de caz concrete cu situatie initiala, program, etapa, documente, rezultat publicabil si limitari.

Marcaj: `TODO_CLIENT` pentru cazuri reale anonimizate, permisiuni client si dovezi publicabile.

### Claims nesustinute factual

Zone de risc:

- Homepage include claim-uri numerice si comerciale precum proiecte finalizate cu succes, `98%`, `10 ani`, plus sume/procente de programe.
- `blog-afir-fotovoltaice-ferme-2026.html` contine claim-uri puternice: `500.000 euro`, `90%`, reduceri de facturi `60-80%`, amortizare `3-5 ani`, crestere valoare proprietate `15-25%`.
- Unele pagini au disclaimere bune ("nu garanteaza finantarea"), dar nu toate claim-urile au sursa exacta vizibila langa ele.

Marcaj: `TODO_CLIENT` pentru dovezi interne sau reformulare prudenta acolo unde nu exista sursa oficiala/publicabila.

### Pagini locale fara continut local real

Status: prezent.

- Paginile locale contin regiunea si domeniile posibile, dar nu includ exemple locale verificabile, informatii despre autoritatea regionala relevanta, cazuri locale, evenimente locale sau particularitati economice reale.
- Bucuresti este tratat similar cu Nord-Est, desi regiunea si eligibilitatea difera mult pentru unele programe.

Impact:

- Risc de doorway pages / programmatic SEO slab.

## 6. Harta de interventie in ordinea impactului

### Quick wins

1. Faceti linkurile catre ghiduri oficiale vizibile in HTML static, nu doar prin JS.
2. Actualizati `llms.txt` la aceeasi data cu sitemapul si includeti paginile noi/canonice reale.
3. Adaugati pe fiecare pagina indexabila un bloc vizibil "Actualizat la" si "Verificat dupa surse oficiale la".
4. Adaugati `author`, `reviewedBy`, `datePublished`, `dateModified` in JSON-LD unde lipsesc.
5. Scoateti sau noindexati explicit `google8bbb9999c523a3bd.html` daca nu trebuie crawlata ca pagina publica.
6. Reduceti repetarile evidente din paginile locale, mai ales paragrafele duplicate consecutiv.
7. Pentru fiecare claim numeric major, adaugati langa text link static catre sursa oficiala sau reformulati ca orientativ.

### Modificari structurale

1. Creati un model comun de pagina "ghid citabil" care include: autor, reviewer, data verificarii, surse oficiale statice, statut program, sumar scurt, disclaimer si sectiune "ce trebuie verificat in ghidul activ".
2. Separati paginile comerciale de paginile editoriale:
   - comercial: servicii, consultanta, contact;
   - editorial/citabil: ghiduri, programe, metodologie, intrebari.
3. Creati pagini de metodologie:
   - `/metodologie-verificare-fonduri-europene`
   - `/surse-oficiale-fonduri-europene`
   - `/politica-editoriala`
4. Transformati `official-guides.json` intr-o sursa folosita si la build, astfel incat linkurile oficiale sa fie injectate static in HTML.
5. Extindeti generatorul pentru a evita repetarea paragrafului generic pe zeci de pagini.

### Modificari de continut

1. Refaceti paginile locale cu date reale:
   - programe relevante pentru regiune;
   - exemple anonimizate locale;
   - particularitati de eligibilitate;
   - intrebari primite local;
   - CTA local prudent.
2. Refaceti FAQ-urile comune in FAQ-uri specifice:
   - pentru DR12: SO, varsta, exploatatie, documente agricole;
   - pentru Start-Up Nation: CAEN, buget, plan, procedura;
   - pentru energie: avize, racordare, consum, amplasament.
3. Adaugati studii de caz reale si anonimizate.
4. Adaugati pagini cu "surse oficiale" pe cluster:
   - AFIR;
   - PNRR/digitalizare;
   - Start-Up Nation;
   - Fondul de Modernizare;
   - programe regionale.
5. Inlocuiti blocurile template repetate cu exemple, criterii si riscuri specifice fiecarei pagini.

### Modificari de schema

1. Standardizati `WebPage`/`Article`/`BlogPosting`:
   - `author`;
   - `reviewedBy`;
   - `datePublished`;
   - `dateModified`;
   - `about`;
   - `citation` sau `isBasedOn` catre surse oficiale, unde este potrivit.
2. Pentru pagini de servicii, pastrati `Service`, dar legati-o de `Organization`/`ProfessionalService`.
3. Pentru pagini program, verificati daca `GovernmentService` este mereu corect. Unele pagini sunt ghiduri private despre programe guvernamentale, nu servicii guvernamentale prestate de site.
4. Adaugati schema pentru `Person` doar daca exista autor/reviewer real publicabil. Altfel, marcati `TODO_CLIENT`.
5. Evitati FAQ schema identica pe pagini multe; FAQ schema trebuie sa reflecte intrebari vizibile si specifice.

### Modificari de internal linking

1. Construiti hub-uri clare:
   - `/fonduri-europene` -> servicii, programe, ghiduri, intrebari, metodologie;
   - `/afir` -> DR12, DR14, calculator SO, consultanta AFIR, surse AFIR;
   - `/pnrr` -> digitalizare IMM, cheltuieli eligibile, consultanta, surse;
   - `/start-up-nation-2026` -> conditii, cheltuieli, idei, plan, consultanta.
2. Adaugati linkuri reciproce intre ghidurile oficiale si paginile de metodologie.
3. Din paginile locale, trimiteti spre programul/regiunea relevanta, nu doar spre contact.
4. Din paginile de intrebari, trimiteti spre pagina program, pagina serviciu si sursa oficiala.
5. Adaugati "Ultima verificare" si "Surse folosite" ca sectiuni linkabile cu ancore stabile.

## TODO_CLIENT

- Nume autor/reviewer, roluri si acreditari publicabile.
- Dovezi pentru claim-uri comerciale: ani experienta, proiecte finalizate, procente de succes, rezultate.
- Studii de caz anonimizate cu permisiune de publicare.
- Testimoniale reale aprobate.
- Diferentiatori locali pentru Iasi, Suceava, Bacau si Bucuresti.
- Surse oficiale exacte pentru fiecare program si data ultimei verificari.
- Decizie editoriala: ce pagini sunt comerciale si ce pagini sunt surse citabile independente.
