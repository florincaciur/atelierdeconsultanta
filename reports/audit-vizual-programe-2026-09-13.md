# Audit vizual și SEO — paginile de programe

Data: **13 septembrie 2026**. Stare: **remedii implementate și verificate local; nu au fost publicate în producție**.

## Rezultat

- 27 rute din sitemapul programelor: 25 pagini de program/hub și două articole asociate.
- 243 verificări de layout: 27 pagini × 9 lățimi (320, 375, 390, 430, 768, 1024, 1280, 1440, 1920 px), toate trecute după remedieri.
- 54 combinații pagină/ecran la 390 și 1440 px, fiecare verificată cu axe în starea inițială și cu secțiunile extensibile deschise: **108 analize finale, fără abateri detectate**.
- Auditul axe inițial identifica **20 de abateri de regulă, cu 56 de elemente raportate**, cumulat pe cele două dimensiuni, în **9 pagini distincte**. Acestea nu reprezintă 56 de defecte independente.
- Verificate controalele animațiilor, activarea secțiunilor prin Enter, meniul mobil și bara de contact. Nicio eroare JavaScript, imagine defectă, ancoră locală lipsă sau ID duplicat în cele 54 de combinații finale.
- Verificare suplimentară a stratului vizual comun: 237 combinații (105 rute la 320 și 1440 px, plus cele 27 pagini de programe la 390 px cu mișcare activă).
- SEO public: **105 URL-uri verificate online**, HTTP 200, canonical corect, fără meta noindex. SEO local: titluri unice, H1 și metadate valide, **0 pagini orfane și 0 linkuri interne defecte/redirecționate** în contractul tehnic.

[Galerie comparativă pentru toate paginile](audit-vizual-programe-2026-09-13.html) · [Date inițiale](program-experience-baseline-2026-09-13/audit.json) · [Date finale](program-experience-acceptance-2026-09-13/audit.json)

## Probleme remediate

| Problemă observată | Remediu implementat | Efect pentru vizitator |
|---|---|---|
| Rezumatele factuale moșteneau limita de lățime a textelor de lectură; rămânea spațiu gol în card, iar condițiile erau înghesuite | Grila folosește întreaga lățime; beneficiarii ocupă un rând complet, iar grantul, contribuția și termenele se distribuie fluid | Condiții mai ușor de citit și comparat |
| Bara mobilă de contact împărțea explicația lungă și butonul în coloane disproporționate | Un singur buton compact; bara apare după depășirea acțiunii din banner; spațiul de la final se adaptează înălțimii reale | Mai puțin conținut acoperit, fără coloană de text foarte îngustă |
| Pagina PC1 Autoconsum avea două grupuri de acțiuni în banner | Eliminat grupul suplimentar; generatorul de profil recunoaște și acțiunile șablonului showcase | O acțiune principală clară și acces la condiții |
| Textele auxiliare pentru cititoare de ecran erau afișate în subsolul ilustrațiilor | Stil comun corect pentru textul sr-only | Legături vizual concise, cu numele accesibil păstrat |
| Unele bannere amestecau alinierea centrată cu alinierea la stânga; etichetele ilustrațiilor erau foarte mici | Aliniere coerentă, etichete și surse mărite, contur de focus și spațiu pentru ancore | Lectură și navigare mai clare |
| DR14: contrast 3,67:1 la două etichete financiare; bifă de 18,4 × 18,4 px | Text alb opac, font mărit și control de minimum 24 × 24 px | Exemplu financiar lizibil și bifare mai ușoară |
| Cinci pagini showcase aveau două regiuni cu același nume | Nume distinct pentru regiunea tabelului comparativ, atât în pagini cât și în generator | Orientare mai clară pentru cititoarele de ecran |
| Cele două articole AFIR aveau bannere în afara regiunilor accesibile | Secțiuni numite accesibil | Titlul și descrierea sunt accesibile prin navigarea pe regiuni |
| Articolul DR14 afișa simultan statutul actual și unul vechi | Un singur statut extras din registrul existent | Eliminarea mesajelor contradictorii fără schimbarea faptelor aprobate |
| Indicatorul din simulatorul Micro Apel 2 nu avea nume accesibil | Adăugat numele „Punctaj estimat al proiectului” | Indicatorul poate fi identificat de tehnologiile asistive |
| Reperele animate se schimbau automat și puteau anunța fiecare schimbare | Control de pauză/reluare, actualizări automate silențioase, selecție manuală și respectarea mișcării reduse | Control asupra animației, fără anunțuri repetitive |

Modificările nu schimbă titlurile SEO, canonicalele, directivele de indexare, valorile finanțărilor, datele de verificare, dateModified sau lastmod. Schimbările comune sunt în active și generatoare; versiunile URL ale CSS/JS au fost actualizate pentru cache. Dependența axe-core este numai pentru dezvoltare, fără cereri noi în paginile publice.

## Acoperire pe fiecare pagină

„PASS layout” înseamnă verificările geometrice la toate cele nouă lățimi. „PASS accesibilitate” înseamnă regulile automate selectate la 390 și 1440 px, în ambele stări ale secțiunilor; nu este o certificare WCAG.

| Rută | Abateri axe inițiale | Layout final | Accesibilitate finală |
|---|---|---|---|
| [/digitalizare-imm](https://atelierdeconsultanta.ro/digitalizare-imm) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/dr12-afir](https://atelierdeconsultanta.ro/dr12-afir) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/dr14](https://atelierdeconsultanta.ro/dr14) | contrast insuficient; țintă tactilă prea mică | PASS | PASS |
| [/pro-infra](https://atelierdeconsultanta.ro/pro-infra) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/afir-autoconsum-agroalimentar](https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/apeluri-gal](https://atelierdeconsultanta.ro/apeluri-gal) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/autoconsum-public-fotovoltaice-institutii-publice](https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice) | regiuni cu același nume | PASS | PASS |
| [/diaspora-investeste-acasa](https://atelierdeconsultanta.ro/diaspora-investeste-acasa) | regiuni cu același nume | PASS | PASS |
| [/dr-12-afir-instalarea-tinerilor-fermieri](https://atelierdeconsultanta.ro/dr-12-afir-instalarea-tinerilor-fermieri) | banner fără regiune accesibilă | PASS | PASS |
| [/dr-14-afir-conditii-eligibilitate-greseli-frecvente](https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente) | banner fără regiune accesibilă | PASS | PASS |
| [/dr18](https://atelierdeconsultanta.ro/dr18) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/e-drive](https://atelierdeconsultanta.ro/e-drive) | regiuni cu același nume | PASS | PASS |
| [/e-mobility](https://atelierdeconsultanta.ro/e-mobility) | regiuni cu același nume | PASS | PASS |
| [/e-move](https://atelierdeconsultanta.ro/e-move) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/femeia-antreprenor-2026](https://atelierdeconsultanta.ro/femeia-antreprenor-2026) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/fondul-de-modernizare](https://atelierdeconsultanta.ro/fondul-de-modernizare) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum](https://atelierdeconsultanta.ro/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/fondul-modernizare-energie-regenerabila-2026](https://atelierdeconsultanta.ro/fondul-modernizare-energie-regenerabila-2026) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/fondul-modernizare-pc1-stocare](https://atelierdeconsultanta.ro/fondul-modernizare-pc1-stocare) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/fondul-modernizare-pc1-stocare-entitati-publice](https://atelierdeconsultanta.ro/fondul-modernizare-pc1-stocare-entitati-publice) | regiuni cu același nume | PASS | PASS |
| [/fonduri-regionale](https://atelierdeconsultanta.ro/fonduri-regionale) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/gal-afir](https://atelierdeconsultanta.ro/gal-afir) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/investitii-modernizarea-microintreprinderilor-apel-2](https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2) | indicator de punctaj fără nume | PASS | PASS |
| [/pnrr](https://atelierdeconsultanta.ro/pnrr) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/pocidif-21](https://atelierdeconsultanta.ro/pocidif-21) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/programul-tranzitie-justa](https://atelierdeconsultanta.ro/programul-tranzitie-justa) | Nicio abatere axe în starea inițială | PASS | PASS |
| [/start-up-nation-2026](https://atelierdeconsultanta.ro/start-up-nation-2026) | Nicio abatere axe în starea inițială | PASS | PASS |

## Validare și reproducere

~~~powershell
npm run audit:program-experience -- --label=local
npm run test:program-visual-integrity
node tests/contextual-cta-contract.mjs
node tools/on-page-seo-audit.js
node tests/technical-seo-contract.mjs
node tools/sync-structured-data.js --check
node tests/structured-data-entity-contract.mjs
node tests/prerender-critical-content-contract.mjs
node tools/verify-sitemap.js --live
node tools/build-cloudflare-assets.js
node tools/audit-cloudflare-program-routes.js
node tests/program-seo-logo-20260906-contract.mjs --dist
~~~

Au trecut și contractele pentru șablonul de program, linkurile contextuale, simulatorul Micro Apel 2 și navigarea la șase dimensiuni. Testul conținutului prerandat a verificat 43 de rute și descoperirea a 24 de programe din carusel fără interacțiune. Pachetul Cloudflare a fost construit în dist: 227 fișiere și 109 aliasuri HTML canonice sincronizate. Au fost verificate rutele și aliasurile din pachet. Nu s-a rulat întregul lanț npm run build; s-au rulat generatorul de active și verificările relevante enumerate, fără publicare.

## SEO: ce s-a îmbunătățit și ce mai trebuie măsurat

Remediile îmbunătățesc lizibilitatea, navigarea, accesibilitatea și controlul elementelor fixe. Ele păstrează fundația tehnică SEO care a trecut auditul. Nu demonstrează o creștere a clasării: Google folosește mai multe semnale, iar o experiență bună în pagină nu garantează poziții superioare. [Google Search Central — experiența în pagină](https://developers.google.com/search/docs/appearance/page-experience).

Priorități rămase, distincte de remediile vizuale finalizate:

1. **Reverificare editorială PC1 Autoconsum și PC1 Stocare pentru entități publice.** Auditul offline al statusurilor găsește două avertismente: data programată de 11 septembrie a trecut, iar ultima verificare din registru este 9 septembrie. Sunt necesare surse oficiale actuale pentru a confirma dacă sesiunea a început, a fost amânată sau suspendată. Nu s-a transformat automat statutul în „deschis”. Nicio eroare de severitate HIGH în auditul de status.
2. **Core Web Vitals reale.** LCP, INP și CLS din CrUX/Search Console trebuie evaluate după publicare, pe mobil și desktop. Auditul de față nu conține măsurători de teren sau scoruri Lighthouse și nu pretinde îmbunătățiri numerice de performanță. [Google Search Central — Core Web Vitals](https://developers.google.com/search/docs/appearance/core-web-vitals).
3. **Măsurarea impactului organic.** Compararea perioadelor de 28 de zile în Search Console, pe pagină, interogare și dispozitiv: impresii, clicuri, CTR și poziție, ținând cont de calendarele apelurilor. Datele Search Console și conversiile nu au fost accesate în acest audit.

## Limite

Randarea și interacțiunile au fost testate în Chromium local, cu resursele terților excluse pentru reproductibilitate. Capturile includ toate paginile la mobil și desktop; inspecția vizuală s-a concentrat pe bannere, tiparele comune și zonele cu probleme. Testele automate nu pot evalua fiecare detaliu estetic sau toate combinațiile de dispozitive și tehnologii asistive. Rezultatele axe incomplete, inclusiv evaluările de contrast care necesită verificare umană, sunt păstrate în JSON. Nu s-au trimis formulare, nu s-au modificat conturi externe și nu s-a publicat site-ul.


## Continuare PC1 — 13 septembrie 2026

Punctul de reverificare PC1 de mai sus a fost rezolvat după primirea documentelor oficiale: depunerea începe la 28.09.2026 pentru ambele apeluri. Cele cinci documente atașate coincid binar cu fișierele AFIR. Vezi [verificarea și remedierile PC1](pc1-surse-si-publicare-2026-09-13.md). Auditul de status are acum zero erori și zero avertismente.
