# Plan de dezvoltare FABER pentru citări AI, recomandări și vizibilitate organică

Data: 2 septembrie 2026
Domeniu: `https://atelierdeconsultanta.ro`
Obiectiv: creșterea probabilității ca paginile FABER să fie descoperite, înțelese, citate și recomandate pentru întrebări despre fonduri europene, fără promisiuni de poziție sau citare.

## Domeniu de lucru

Include: claritate de entitate, răspunsuri citabile, surse oficiale, metadate, structură semantică, linkare internă, IndexNow, sitemap, active editoriale pentru backlinkuri și teste anti-regresie.

Exclude: backlinkuri cumpărate, directoare fără relevanță, testimoniale sau rezultate inventate, pagini scalate fără valoare, valori financiare neconfirmate și schimbări vizuale fără motiv editorial.

## Seria de prompturi

### Prompt 1 — Conservă progresul și construiește o bază măsurabilă

> Lucrează într-un worktree curat pornit din ultimul `origin/main`. Nu modifica și nu șterge schimbările locale existente. Inventariază rutele canonice, starea Git, build-ul, sitemapurile, metadatele, linkurile, schema, politicile crawlerelor și paginile cu performanță Bing. Salvează valorile de bază și oprește implementarea dacă o schimbare ar pierde progresul existent.

Criterii: directorul original rămâne neatins; există baseline pentru 104 rute, build și rapoarte; orice abatere este reproductibilă.

### Prompt 2 — Definește FABER ca entitate verificabilă

> Unifică numele de brand, entitatea juridică aprobată, datele de contact, aria deservită, serviciile și domeniile de expertiză în toate datele structurate. Leagă Organization, ProfessionalService, WebSite și paginile editoriale prin ID-uri canonice stabile. Nu inventa persoane, premii, clienți, sedii sau profiluri sociale.

Cuvinte și entități urmărite: `FABER`, `Atelier de Consultanță`, `consultanță fonduri europene`, `AFIR`, `DR 12 AFIR`, `DR 14 AFIR`, `GAL AFIR`, `LEADER DR-36`, `calculator SO AFIR`, `Digitalizare IMM`, `Start-Up Nation`, `Programul Regional Nord-Est`, `proiectare fonduri europene`, `implementare fonduri europene`.

Criterii: schema este validă și consecventă; afirmațiile publice au dovadă; brandul și firma juridică nu sunt confundate.

### Prompt 3 — Transformă paginile prioritare în surse citabile

> Pentru fiecare pagină prioritară, adaugă un răspuns direct de 100–150 de cuvinte, un H1 aliniat interogării, subtitluri unice, tabele sau liste numai când simplifică decizia, data verificării, sursa oficială și limite explicite. Elimină cifrele și exemplele implicite când programul nu are valori confirmate. Păstrează designul și componentele existente.

Priorități: `/gal-afir`, `/calculator-soc`, `/femeia-antreprenor-2026`, `/dr12-afir`, `/dr14`, `/investitii-modernizarea-microintreprinderilor-apel-2`.

Criterii: răspunsul poate fi extras fără context înșelător; sursa este vizibilă; nu există H2 duplicat; datele structurate corespund textului vizibil.

### Prompt 4 — Aliniază snippetul la interogarea și intenția Bing

> Rescrie numai titlurile și descrierile care sunt prea lungi, ambigue sau nu corespund interogării. Păstrează titlurile sub 60 de caractere și descrierile sub 160, cu termenul principal și concluzia factuală în prima parte. Generează aceleași valori pentru Open Graph și Twitter și adaugă text alternativ imaginii sociale.

Ținte inițiale din audit: `GAL AFIR`, `Femeia Antreprenor 2026`, metodologia FABER și întrebările despre documente DR12, cheltuieli Digitalizare IMM și calculul cofinanțării.

Criterii: titluri unice, exact un H1, metadata socială completă și 0 abateri în auditul on-page.

### Prompt 5 — Creează trasee operaționale, nu pagini de umplutură

> Pe pagina GAL AFIR oferă pașii de identificare a GAL-ului competent și un link direct către platforma oficială. Pe Femeia Antreprenor separă fără echivoc ediția 2026 neconfirmată de ediția 2024 închisă. Păstrează Calculatorul SO drept activ utilitar principal și nu îl dilua cu text repetitiv. Leagă aceste pagini de serviciul și instrumentul relevant.

Criterii: utilizatorul ajunge în maximum două acțiuni la sursa sau instrumentul necesar; butoanele duc la destinații valide; nu se adaugă componente vizuale noi.

### Prompt 6 — Controlează prospețimea și descoperirea

> Publică `lastmod` numai pentru actualizări editoriale dovedite. Trimite prin IndexNow doar URL-urile adăugate, șterse ori schimbate semantic; ignoră schimbările globale de navigație, analytics, CSS și SVG. Menține robots, politicile crawlerelor AI, sitemapurile canonice și feedul sincronizate.

Criterii: sitemap fără URL-uri redirecționate sau noindex; test semantic IndexNow; cheie IndexNow accesibilă; crawlerele legitime nu sunt blocate.

### Prompt 7 — Construiește active care merită backlinkuri

> Folosește paginile și descărcările FABER drept surse pentru parteneri reali: Calculator SO și metodologia lui, checklist DR12, matrice DR14, ghid GAL/DR-36, matrice CAEN–amplasament Nord-Est și fișa AFIR Energie. Fiecare activ trebuie să aibă dată, metodologie, sursă oficială, limitări și URL canonic stabil. Nu cere ancore comerciale exacte.

Matrice recomandată:

| Activ citabil | Interogări/ancore naturale | Parteneri relevanți | URL țintă |
|---|---|---|---|
| Calculator SO + metodologie | calculator SO AFIR, dimensiune economică fermă, coeficienți SO | contabili agricoli, agronomi, cooperative, publicații agricole | `/calculator-soc` |
| Ghid GAL/DR-36 | GAL AFIR, apeluri GAL, eligibilitate LEADER | GAL-uri, ADI-uri, primării, asociații rurale, presă locală | `/gal-afir` |
| Checklist DR12 | documente DR12, eligibilitate tineri fermieri | contabili, cooperative, furnizori agricoli | `/dr12-afir` |
| Matrice DR14 | DR14 ferme mici, punctaj DR14 | veterinari, agronomi, asociații de producători | `/dr14` |
| Metodologia FABER | verificare eligibilitate fonduri europene | contabili, proiectanți, camere de comerț | `/metodologie-verificare-eligibilitate` |
| Nord-Est și microîntreprinderi | finanțări microîntreprinderi Nord-Est | arhitecți, proiectanți, patronate regionale | `/investitii-modernizarea-microintreprinderilor-apel-2` |

Criterii: fiecare mențiune provine dintr-o relație sau resursă reală; se urmăresc domeniul, pagina sursă, contextul, ancora, URL-ul țintă, data, statutul și traficul UTM. Detaliile operaționale rămân în `docs/offsite-seo-actions.md`.

### Prompt 8 — Blochează regresiile de conținut, linkuri și design

> Adaugă teste automate pentru citabilitatea paginilor prioritare, metadate sociale, schema aplicației Calculator SO, surse oficiale, H2 duplicate, exemple financiare neconfirmate, canonicale, redirecturi, linkuri și comportamentul butoanelor. Rulează testele responsive și comparațiile vizuale existente fără a schimba CSS-ul paginilor.

Criterii: build complet verde; audit on-page verde; teste funcționale, linkuri, schema, responsive și vizuale verzi; 0 erori JavaScript pe paginile verificate.

### Prompt 9 — Publică, verifică și măsoară

> Fă fetch înainte de publicare, confirmă că `origin/main` și `origin/master` nu au avansat, creează un singur commit auditabil și împinge același commit în ambele ramuri prin fast-forward. Urmărește build-ul Cloudflare până la rezultat final. După deploy, verifică live homepage, GAL AFIR, Calculator SO, Femeia Antreprenor, DR12, DR14 și contact pe desktop și mobil; verifică butoanele, linkurile, canonicalele, schema, console errors, sitemap și politici crawler.

Criterii: același SHA în `origin/main` și `origin/master`; build Cloudflare reușit; rutele prioritare răspund 200; modificările sunt vizibile live.

## Cadru de măsurare la 30/60/90 de zile

- Bing Search Performance: impresii, clicuri, CTR și poziție pentru query și pagină.
- Bing AI Performance: grounding queries, citări, pagini citate și tendința citărilor.
- Autoritate: domenii relevante noi, mențiuni de brand, mențiuni nelegate transformate natural în link și linkuri pierdute.
- Conținut: impresii și citări pentru clusterele GAL, DR12, DR14, Calculator SO, programe regionale și consultanță.
- Business: leaduri calificate din paginile citate, telefon, WhatsApp și formular, fără a confunda traficul cu eligibilitatea sau aprobarea proiectelor.

## Regula de decizie

O schimbare rămâne numai dacă îmbunătățește cel puțin unul dintre următoarele fără să slăbească altul: exactitatea, verificabilitatea, utilitatea, descoperirea, claritatea entității sau conversia. Nu se publică pagini ori afirmații create exclusiv pentru motoare sau agenți AI.
