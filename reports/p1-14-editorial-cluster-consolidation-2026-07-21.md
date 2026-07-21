# P1.14 — Consolidarea hub-urilor Fonduri, Digitalizare și Eligibilitate

Data implementării: 2026-07-21  
Stare: implementare editorială finalizată pentru URL-urile publicabile; consolidarea Digitalizare rămâne blocată de validarea factuală și aprobarea umană a redirectului.

## Sursa unică pentru copy și intenții

Copy-ul complet, title/meta, H1, răspunsurile directe, structura H2/H3, linkurile interne, CTA-urile și regulile de migrare sunt versionate în `config/editorial-clusters.json`. Generatorul `tools/sync-editorial-clusters.js` le aplică în HTML și sincronizează metadatele și JSON-LD-ul local.

## Mapping editorial și 301

| Source | Decizie | Target / rol unic | Stare tehnică |
| --- | --- | --- | --- |
| `/fonduri-europene` | KEEP | Hub pentru familii, instrumente și procesul de alegere | Publicat în HTML |
| `/fonduri-nerambursabile` | KEEP | Ghid distinct despre grant, contribuție proprie, cash-flow, plăți și obligații | Publicat în HTML |
| `/digitalizare-imm` | KEEP, candidat canonic principal | Pregătirea proiectului și, după validare, datele programului oficial | Draft pregătit; pagina rămâne `noindex`, copy-ul nou nu este publicat |
| `/granturi-digitalizare-imm` | CANDIDAT 301 | `/digitalizare-imm` | `APROBARE_UMANĂ_NECESARĂ`; redirectul nu este activ |
| `/cheltuieli-eligibile-digitalizare-imm` | KEEP | Ghid distinct despre software, hardware, cloud, securitate și justificarea bugetului | Publicat în HTML |
| `/eligibilitate-fonduri-europene` | KEEP | Ghid educațional cu criterii și checklist de autoevaluare | Publicat în HTML |
| `/verificare-eligibilitate-fonduri-europene` | KEEP | Serviciu: date necesare, proces, livrabil, limite și formular | Publicat în HTML |

Nu a fost adăugat niciun redirect. Perechea Digitalizare poate fi activată numai după:

1. validarea documentului oficial, versiunii, statusului și datei de verificare;
2. aprobarea ownerului/SEO lead pentru migrare și 301;
3. publicarea și indexabilitatea targetului `/digitalizare-imm`;
4. verificarea că targetul răspunde 200 și este self-canonical.

## Copy și structură pe URL

### `/fonduri-europene`

- H1: „Fonduri europene: alege traseul potrivit investiției”.
- Răspuns direct: orientează către familii, instrumente și proces; nu publică sume sau termene generale.
- Structură: familii de programe; instrumente; procesul de alegere; limitele hubului.
- CTA: „Vezi procesul de verificare”.
- Migrare semantică: păstrate orientarea și destinațiile utile; explicațiile financiare au fost mutate logic în ghidul `/fonduri-nerambursabile`; cardurile comerciale generice și afirmațiile numerice fără sursă au fost eliminate.

### `/fonduri-nerambursabile`

- H1: „Fonduri nerambursabile: ce acoperă grantul și ce plătește beneficiarul”.
- Răspuns direct: delimitează grantul de contribuția proprie, costurile neeligibile și finanțarea temporară.
- Structură: grant versus buget total; contribuție proprie; cash-flow; avans/plată/rambursare; obligații; checklist financiar.
- CTA: „Vezi verificarea inițială”.
- Rol eliminat: nu mai funcționează ca listă concurentă de programe și nu repetă hubul Fonduri.

### `/digitalizare-imm`

- H1 draft: „Digitalizare IMM: de la problema operațională la proiect”.
- Structură draft: problemă și obiectiv; documente de pregătit; separarea ghidului de cheltuieli de datele apelului.
- Regula de publicare: statusul, beneficiarii, valorile și calendarul rămân nepublicate până la validarea sursei oficiale.
- Stare: `pending_validation`, `render: false`, `noindex`; draftul nu a înlocuit pagina publicată existentă.

### `/granturi-digitalizare-imm`

- Nu primește un rol editorial nou doar pentru sinonimul „granturi”.
- Conținutul despre program poate migra în `/digitalizare-imm` numai după validare factuală.
- Conținutul despre software, hardware, cloud și securitate aparține ghidului distinct de cheltuieli.
- Blocurile generice de eligibilitate, pași și CTA nu se migrează.

### `/cheltuieli-eligibile-digitalizare-imm`

- H1: „Cheltuieli pentru Digitalizare IMM: ce justifici înainte de buget”.
- Rol: ghid de necesitate, dimensionare și justificare a costurilor IT; nu declară apelul deschis.
- CTA: trimite contextul proiectului, fără promisiuni și fără valori neverificate.

### `/eligibilitate-fonduri-europene`

- H1: „Eligibilitate pentru fonduri europene: criterii și checklist”.
- Răspuns direct: explică verificarea simultană a solicitantului, activității, locației, investiției, bugetului, calendarului și documentelor.
- Structură: șase niveluri; checklist; semnale de oprire; delimitarea ghidului de serviciu.
- CTA: „Vezi serviciul de verificare”.
- Elemente eliminate: procesul comercial, livrabilul serviciului și cardurile generice.

### `/verificare-eligibilitate-fonduri-europene`

- H1: „Verificare inițială a eligibilității proiectului”.
- Răspuns direct: explică datele necesare și cele trei concluzii prudente — continuare, ajustare sau amânare.
- Structură: date necesare; proces; livrabil; limite; pregătirea înainte de contact.
- CTA: „Începe verificarea proiectului”.
- Elemente eliminate: explicațiile educaționale duplicate și colecțiile de carduri fără rol în serviciu.

## Diff semantic

| Cluster | Înainte | După |
| --- | --- | --- |
| Fonduri | Două pagini care puteau concura prin definiții, programe și CTA-uri similare | Hub de navigare + ghid financiar cu teme exclusive |
| Digitalizare | Pagini apropiate, cu risc de contradicții factuale și valori nealiniate | Target canonic pregătit, ghid de cheltuieli separat, duplicatul marcat pentru aprobare; nicio valoare nouă publicată |
| Eligibilitate | Ghidul și serviciul repetau criterii, pași și blocuri comerciale | Ghid/checklist educațional + serviciu cu proces și livrabil |

În cele cinci pagini regenerate, cardurile editoriale generice din corp au scăzut de la 20, 14, 1, 14 și 26 la zero. Fiecare pagină are un singur CTA final, o singură notă de sursă și un `data-primary-intent` unic pentru QA.

## Validări și rezultate

| Verificare | Rezultat |
| --- | --- |
| Rol, intenție, topic owner, copy, meta, canonical, JSON-LD și sitemap | PASS — 7 URL-uri cu intenții distincte |
| Redirect Digitalizare neaprobat absent din `_redirects` | PASS |
| Terminologie editorială controlată | PASS — 91 URL-uri canonice, zero probleme |
| Etichete de șablon și forme din lista de control | PASS — 91 URL-uri canonice, zero apariții |
| Sitemap | PASS — 91 URL-uri canonice; paginile Digitalizare pending sunt excluse |
| Crawl linkuri și ancore | PASS — 13.021 linkuri și 1.019 fragmente verificate, zero probleme |
| Redirect map | PASS — 122 reguli, zero loop, chain sau link intern spre redirect |
| Canonical consistency | PASS — 91 pagini indexabile |
| Gate SEO global | FAIL exterior P1.14 — `/webinarii` este o pagină indexabilă orfană |

Problema `/webinarii` nu a fost remediată în P1.14 deoarece nu aparține celor trei clustere și alegerea unui părinte necesită o decizie de arhitectură separată.

## Comenzi de retest

```powershell
npm run check:editorial-clusters
npm run test:editorial-clusters
npm run test:editorial-terminology
npm run test:editorial-copy
npm run test:sitemap
npm run test:technical-seo
```

