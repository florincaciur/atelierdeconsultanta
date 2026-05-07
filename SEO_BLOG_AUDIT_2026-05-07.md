# Audit SEO si plan blog - 2026-05-07

## Rezumat executiv

Site-ul are o baza tehnica buna pentru indexare: sitemap, robots.txt, canonical-uri, JSON-LD si huburi tematice pentru fonduri europene. Problemele din Google Search Console provin in principal din reguli de redirect care puteau produce chain-uri/loop-uri pe Netlify si din variante duplicate accesibile (`/slug`, `/slug/`, `/slug/index.html`, `/index.html`).

Fix aplicat in acest audit:

- `/index.html` redirectioneaza 301 catre `/`, reducand cazul "Alternate page with proper canonical tag".
- URL-urile canonice cu trailing slash sunt servite direct din `/slug/index.html`, fara rewrite `200!` intermediar.
- Variantele fara slash, `.html` si `index.html` redirectioneaza 301 catre URL-ul canonic.
- Generatorul fallback-urilor HTML foloseste `noindex, follow` pentru paginile de redirect soft.
- `sitemap.xml` are `lastmod` actualizat la `2026-05-07`.

## Surse oficiale verificate

- AFIR DR-14, versiune consultativa publicata pe 24 aprilie 2026: https://www.afir.ro/info-la-zi/versiunea-consultativa-a-ghidului-solicitantului-dr-14/
- AFIR DR-12, consultare publica si conditii principale: https://www.afir.ro/comunicate/consultare-publica-pentru-consolidarea-exploatatiilor-tinerilor-fermieri/
- AFIR Schema de Energie 2026, autoconsum agricol/agroalimentar: https://www.afir.ro/comunicate/consultare-publica-privind-schema-de-energie/
- Portalul unic Oportunitati UE, explicat ca punct unic MIPE: https://diaspora.gov.ro/info/stiri-din-romania/480-platforma-online-https-oportunitati-ue-gov-ro-informatii-actualizate-despre-programele-de-finantare-europene-si-nationale
- Platforma MINIMIS Start Up Nation 2024, transparenta cursanti: https://minimis.imm.gov.ro/sn2024/transparenta_cursanti

## Diagnostic tehnic

Prioritate mare:

- Redirecturile trebuie mentinute pe Netlify/CDN. Daca site-ul se muta strict pe GitHub Pages, `_redirects` nu va fi aplicat si URL-urile extensionless dependente de Netlify trebuie reanalizate.
- In Search Console, `http://atelierdeconsultanta.ro/` la "Page with redirect" este normal: varianta HTTP trebuie sa ramana redirect catre HTTPS.
- URL-urile din GSC `consultanta-fonduri-europene`, `contact`, `fonduri-europene`, `fonduri-europene-imm`, `firma-consultanta-fonduri-europene` trebuie retrimise la validare dupa deploy.

Prioritate medie:

- Unele huburi indexabile au doar aproximativ 310-380 cuvinte. Sunt bune ca structura, dar slabe ca diferentiere fata de competitia SEO.
- Paginile "Crawled - currently not indexed" (`/pro-infra`, `/fonduri-nerambursabile/`) au nevoie de semnale suplimentare: continut mai util, surse oficiale, exemple concrete, intrebari frecvente si linkuri interne din articole relevante.
- Pastreaza o regula stricta: sitemap-ul trebuie sa includa doar URL-uri finale 200, nu variante redirectate.

Prioritate reputationala:

- Verifica cifrele si testimonialele comerciale de pe homepage. Daca nu exista dovezi si acorduri, inlocuieste cu formulari neutre. Pentru YMYL-ish financiar/finantari, increderea conteaza mult.
- Adauga autor/editor, data actualizarii si surse oficiale in articolele de blog. Pentru finantari, Google si utilizatorii cauta informatii actuale, nu doar text evergreen.

## Content inventory

Inventar curent:

- 59 pagini publice indexabile.
- Cele mai puternice pagini de continut depasesc 1.200-2.000 cuvinte: ghid alegere program, acte necesare, DR12, DR14 articol, homepage, blog.
- Multe huburi SEO sunt utile ca landing pages, dar sunt subtiri: `consultanta-pnrr-digitalizare`, `fonduri-pentru-ferme`, `granturi-digitalizare-imm`, `firma-consultanta-fonduri-europene`, `fonduri-nerambursabile`, `pnrr`, `start-up-nation`.

## Strategie blog recomandata

Foloseste modelul hub-and-spoke:

- Hub = pagina comerciala sau pagina-pilon (`/afir/`, `/fonduri-europene/`, `/fonduri-nerambursabile/`, `/start-up-nation/`, `/fonduri-europene-digitalizare/`).
- Spoke = articol de blog cu intentie informationala clara.
- Fiecare articol trebuie sa includa 3-6 linkuri interne catre huburi, pagina de contact si paginile de program.
- Fiecare articol trebuie actualizat cand apare ghid final, corrigendum sau calendar nou.

## Prioritati articole blog

### P0 - publicare imediata

1. `DR 14 AFIR 2026: conditii, praguri SO, investitii eligibile si greseli frecvente`
   - Intentie: fermieri care cauta ghid practic dupa consultarea din aprilie 2026.
   - Leaga catre: `/dr14`, `/afir/`, `/fonduri-europene-agricultura/`, `/consultanta-afir/`, `/calculator-soc.html`.
   - Include: tabel conditii, checklist documente, sectiune apicultura/ferme mici, FAQ.

2. `DR 12 AFIR 2026: cine poate aplica si cum pregatesti dosarul`
   - Intentie: tineri fermieri si fermieri pana la 45 de ani.
   - Leaga catre: `/dr12-afir`, `/afir/`, `/fonduri-pentru-ferme/`, `/consultanta-afir/`.
   - Include: eligibilitate, intensitati, investitii eligibile, documente si timeline.

3. `Schema Energie AFIR 2026: fotovoltaice pentru autoconsum in agricultura si industria alimentara`
   - Intentie: ferme/procesatori care cauta finantare 100% pentru solar.
   - Leaga catre: `/afir-autoconsum-agroalimentar`, `/finantari-panouri-fotovoltaice/`, `/fondul-de-modernizare/`, `/contact/`.
   - Include: 100% nerambursabil, praguri EUR/MW, stocare, locuri de productie diferite, documente tehnice.

4. `Start-Up Nation 2026: cursuri, locuri disponibile, pasi si documente`
   - Intentie: persoane care urmaresc inscrierea si pregatirea pentru program.
   - Leaga catre: `/start-up-nation-2026`, `/start-up-nation/`, `/start-up-nation-2026-conditii/`, `/consultanta-start-up-nation/`.
   - Include: stadiu platforma MINIMIS, categorii de grup tinta, pregatire firma/CAEN/buget.

5. `Fonduri nerambursabile 2026: cum alegi intre AFIR, PNRR, programe regionale si Start-Up Nation`
   - Intentie: top-of-funnel mare, util pentru linkuri catre toate huburile.
   - Leaga catre: `/fonduri-nerambursabile/`, `/fonduri-europene/`, `/eligibilitate-fonduri-europene/`, `/calendar-fonduri-europene/`.
   - Include: matrice beneficiar-program, cand nu merita aplicat, checklist rapid.

### P1 - urmatoarele 30 zile

6. `PRO INFRA 2026: ce firme pot aplica si ce investitii in materiale de constructii sunt eligibile`
   - Scop: ridica sansele de indexare pentru `/pro-infra`.

7. `Fonduri pentru digitalizare IMM 2026: ERP, CRM, securitate cibernetica si greseli de buget`
   - Scop: sustine `/fonduri-europene-digitalizare/`, `/digitalizare-imm`, `/granturi-digitalizare-imm/`.

8. `Calendar fonduri europene 2026: cum urmaresti apelurile fara sa pierzi termenul`
   - Scop: sustine `/calendar-fonduri-europene/` si capteaza cautari recurente.

9. `Cat costa consultanta pentru fonduri europene si ce ar trebui sa includa oferta`
   - Scop: capteaza intentie comerciala si sustine `/cat-costa-consultanta-fonduri-europene/`.

10. `Acte necesare pentru fonduri europene: checklist pe firma, ferma, energie si digitalizare`
   - Scop: extinde articolul deja puternic si creeaza linkuri spre huburi.

### P2 - evergreen

11. `Cum verifici eligibilitatea codului CAEN pentru fonduri europene`
12. `Cele mai frecvente motive de respingere la fonduri europene`
13. `Plan de afaceri pentru Start-Up Nation: structura, buget si greseli`
14. `Fonduri pentru panouri fotovoltaice: autoconsum, prosumator, stocare si documente`
15. `Cum alegi un consultant de fonduri europene fara promisiuni nerealiste`

## Template SEO pentru fiecare articol

- Title: 50-60 caractere, cu anul si programul cand e cazul.
- Meta description: 140-155 caractere, promite un rezultat concret.
- H1 unic, apropiat de keywordul principal.
- Intro: raspunde in primele 80-120 cuvinte cine poate aplica si ce afla cititorul.
- Cuprins: 5-8 sectiuni H2.
- Tabel: conditii / documente / cheltuieli / pasi.
- FAQ: 4-6 intrebari reale, cu raspunsuri scurte.
- Surse: minimum 2 linkuri oficiale pentru programe active.
- CTA: evaluare gratuita, dar fara promisiuni de aprobare.
- Linkuri interne: 3 spre huburi, 1 spre contact, 1 spre articol conex.

## Recomandari de interlinking

- Din fiecare articol AFIR: link catre `/afir/`, `/consultanta-afir/`, `/calculator-soc.html`, pagina programului relevant.
- Din fiecare articol Start-Up Nation: link catre `/start-up-nation/`, `/start-up-nation-2026`, `/start-up-nation-2026-plan-de-afaceri/`, `/contact/`.
- Din fiecare articol digitalizare/PNRR: link catre `/pnrr/`, `/fonduri-europene-digitalizare/`, `/consultanta-pnrr-digitalizare/`, `/digitalizare-imm`.
- Din articolele generale: link catre `/fonduri-europene/`, `/fonduri-nerambursabile/`, `/eligibilitate-fonduri-europene/`, `/calendar-fonduri-europene/`.

## Actiuni GSC dupa deploy

1. Inspecteaza si valideaza:
   - `https://atelierdeconsultanta.ro/consultanta-fonduri-europene/`
   - `https://atelierdeconsultanta.ro/fonduri-europene/`
   - `https://atelierdeconsultanta.ro/fonduri-europene-imm/`
   - `https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/`
   - `https://atelierdeconsultanta.ro/contact/`
   - `https://atelierdeconsultanta.ro/pro-infra`
   - `https://atelierdeconsultanta.ro/fonduri-nerambursabile/`
2. Retrimite sitemap-ul: `https://atelierdeconsultanta.ro/sitemap.xml`.
3. Pentru `http://atelierdeconsultanta.ro/`, nu incerca sa il faci indexabil. Redirectul HTTP -> HTTPS este corect.

