# P1.13 — Preflight GSC pentru paginile aflate istoric în pozițiile 6–12

Data analizei: **2026-07-21**  
Stare: **BLOCAT ÎNAINTE DE MODIFICAREA PAGINILOR**  
Motiv: exportul exact de 90 de zile și asocierea query → page nu sunt disponibile în sesiunea curentă; unele pagini au porți factuale/editoriale active.

## Sursele de date disponibile

Au fost găsite local două exporturi GSC reale, generate la 2026-07-20:

- `atelierdeconsultanta.ro-Performance-on-Search-2026-07-20 (1).zip` — filtrul GSC declară exact `Last 28 days`;
- `atelierdeconsultanta.ro-Performance-on-Search-2026-07-20.zip` — filtrul GSC declară `Last 3 months`.

Al doilea export nu este etichetat de GSC drept `Last 90 days` și nu este prezentat în acest raport ca fereastră de 90 de zile. Datele lui sunt folosite numai ca referință. Browserul disponibil a ajuns la autentificarea Google, fără sesiune conectată; nu au fost solicitate sau completate credențiale.

Exporturile conțin dimensiunile `Queries`, `Pages`, `Countries` și `Devices`, dar nu o asociere query → page. Clusterele de mai jos sunt extrase după termen și sunt marcate drept ipoteze până la exportul filtrat pe fiecare pagină.

## Baseline verificat

| URL | 28 zile: clickuri / afișări / CTR / poziție | Referință „Last 3 months” | Stare tehnică/editorială | Decizie preflight |
|---|---:|---:|---|---|
| `/dr12-afir` | 6 / 588 / 1,02% / 7,71 | 35 / 1.227 / 2,85% / 7,83 | self-canonical, `noindex`, în afara sitemap-ului, `pending_validation` | Blocat de P1.12 și registrul factual |
| `/dr14` | 3 / 267 / 1,12% / 8,18 | 27 / 816 / 3,31% / 7,75 | self-canonical, `noindex`, în afara sitemap-ului, `pending_validation` | Blocat de P1.12 și registrul factual |
| `/gal-afir` | 0 / 351 / 0% / 6,06 | 0 / 632 / 0% / 5,99 | 200 local, indexabil, self-canonical, sitemap, JSON-LD valid | Nu se optimizează pentru query navigațional terț fără query → page |
| `/calculator-soc` | 7 / 2.453 / 0,29% / 8,16 | 35 / 4.526 / 0,77% / 7,99 | indexabil, self-canonical, sitemap, JSON-LD valid; guvernanță `pending_validation` | Cea mai mare oportunitate, dar sursa/versiunea trebuie aprobate |
| `/femeia-antreprenor-2026` | 13 / 1.004 / 1,29% / 8,24 | 42 / 1.930 / 2,18% / 8,29 | indexabil, self-canonical, sitemap, JSON-LD valid; `nextReviewAt=2026-07-19` | Revizuire factuală obligatorie înainte de schimbare |
| `/por-adr-nord-est` | 2 / 69 / 2,90% / 7,51 | 5 / 164 / 3,05% / 7,32 | indexabil, self-canonical, sitemap, JSON-LD valid; verificat 2026-07-20 | Eligibil după exportul exact și confirmarea query → page |
| `/afir-autoconsum-agroalimentar` | 1 / 39 / 2,56% / 13,49 | 2 / 68 / 2,94% / 11,71 | indexabil, self-canonical, sitemap, JSON-LD valid; apel verificat 2026-07-20 | Deprioritizat: poziția curentă nu mai este 6–12 |

Baseline-ul filtrabil este în `reports/p1-13-gsc-preflight-2026-07-21.csv`.

## Distribuție generală din export

### Ultimele 28 de zile

| Dispozitiv | Clickuri | Afișări | CTR | Poziție |
|---|---:|---:|---:|---:|
| Mobil | 41 | 1.918 | 2,14% | 9,32 |
| Desktop | 35 | 5.197 | 0,67% | 9,57 |
| Tabletă | 0 | 25 | 0% | 12,88 |

România are 66 clickuri, 3.073 afișări, CTR 2,15% și poziție 11,53. Exportul arată un volum mare de afișări desktop cu CTR mult sub mobil; orice test de snippet trebuie urmărit separat pe device.

### Referință „Last 3 months”

| Dispozitiv | Clickuri | Afișări | CTR | Poziție |
|---|---:|---:|---:|---:|
| Mobil | 184 | 5.236 | 3,51% | 9,04 |
| Desktop | 133 | 11.203 | 1,19% | 9,84 |
| Tabletă | 1 | 55 | 1,82% | 13,31 |

Aceste valori nu înlocuiesc fereastra cerută de 90 de zile.

## Clustere candidate și intenție

### DR 12

Interogări vizibile în exportul de 28 zile: `dr 12 afir lansare` (58 afișări, poziție 6,97), `dr 12 afir`, `afir dr 12`, `dr 12 ghid final`, `dr12 afir` și variații despre ghid/lansare.

Intenția dominantă propusă: **statusul documentului și momentul lansării**, urmate de condiții și documente. Acestea sunt exact faptele blocate de validarea umană. Nu se rescrie snippetul pentru a promite „ghid final” sau lansare.

Title candidat după aprobare: `DR 12 AFIR: statut, condiții și documente | FABER`  
Meta candidat după aprobare: `Verifică statutul documentului DR 12, cine se poate încadra, ce documente sunt necesare și ce riscuri trebuie clarificate, cu sursa AFIR și data verificării.`

### DR 14

Interogări vizibile: `dr14`, `dr 14 afir`, `dr14 afir`, variații cu anul, ghid și condiții. Query-ul generic `dr14` are în ultimele 28 de zile poziția 24,20, deși pagina agregată este la 8,18; fără export query → page nu se atribuie automat diferența acestei pagini.

Intenția dominantă propusă: **status, ferme mici, condiții și ghid**. Aplicarea rămâne blocată de P1.12.

Title candidat după aprobare: `DR 14 AFIR: statut, ferme mici și documente | FABER`  
Meta candidat după aprobare: `Verifică statutul DR 14, condițiile pentru ferme mici, documentele și riscurile care pot schimba încadrarea, cu sursa AFIR și data verificării.`

### GAL-AFIR

Clusterul este dominat de `galafir` (266 afișări, poziție 5,71, zero clickuri), `gal afir`, `gal.afir` și `galafir.ro`. Forma indică probabil o intenție navigațională către un domeniu/brand terț, nu neapărat către pagina FABER. Nu se rescrie pagina ca să imite destinația navigațională.

Intenția proprie recomandată: **cum identifici GAL-ul, apelul local și condițiile DR-36/LEADER**.

Title candidat: `GAL AFIR și LEADER: apeluri și condiții | FABER`  
Meta candidat: `Află cum identifici GAL-ul și apelul local, ce condiții și documente verifici și de ce regulile diferă între strategiile LEADER și ghidurile fiecărui GAL.`

Secțiuni candidate, numai după confirmarea query → page:

- „Cum găsești GAL-ul aferent localității”; 
- „Unde verifici apelul local și termenul”; 
- tabel GAL / strategie locală / apel / beneficiar / sursă;
- delimitare clară între pagina AFIR LEADER și regulile locale.

### Calculator SO

Clusterul include `calcul so afir 2026`, `calculator so`, `calculator so afir`, `calculator so vegetal`, `calculator so animale`, formule și coeficienți pe cultură. Intenția este în principal **instrumentală**, cu nevoie secundară de explicație și sursă.

Title candidat după aprobarea sursei: `Calculator SO AFIR: vegetal și animale | FABER`  
Meta candidat: `Calculează orientativ dimensiunea economică SO pentru culturi și animale, vezi formula și coeficienții folosiți și verifică rezultatul în documentul AFIR aplicabil.`

Secțiuni candidate:

- sursa și versiunea coeficienților, vizibile lângă calculator;
- exemple separate pentru vegetal și zootehnic;
- explicația formulei, unităților și rotunjirii;
- avertizare că rezultatul nu confirmă eligibilitatea DR 12/DR 14;
- tabel cu coeficient, unitate, sursă și data verificării.

Anul `2026` nu rămâne în title până când registrul instrumentului nu are sursa, versiunea și data aprobate.

### Femeia Antreprenor

Clusterul include program, înscriere, condiții, eligibilitate, vârstă și întrebarea „când începe”. Intenția dominantă este **statusul ediției și înscrierea**, urmată de condiții.

Title candidat după revizuire: `Femeia Antreprenor: condiții și înscriere | FABER`  
Meta candidat după revizuire: `Vezi statutul verificat al programului Femeia Antreprenor, condițiile, documentele și calendarul ediției confirmate în sursa oficială.`

Nu se introduce „2026”, o dată de înscriere sau valori până la revizuirea sursei. `nextReviewAt` a trecut la 2026-07-19.

### Programul Regional Nord-Est

Query-ul relevant vizibil este `adr nord est microintreprinderi` (18 afișări, poziție 8,67). Intenția este **apel regional pentru microîntreprinderi/IMM**, cu filtrare după județ, solicitant și investiție.

Title candidat: `Program Regional Nord-Est: finanțări IMM | FABER`  
Meta candidat: `Identifică apelurile pentru IMM și microîntreprinderi din Nord-Est și verifică județul, codul CAEN, amplasamentul, documentele și sursa ADR aplicabilă.`

Secțiuni candidate:

- tabel apel / categorie solicitant / județe / status / sursă;
- diferența dintre denumirea actuală „Program Regional” și căutarea istorică „POR”; 
- traseu către pagina distinctă a Apelului 2, fără dublarea condițiilor.

### AFIR Autoconsum Agroalimentar

Pagina are o sursă oficială și o verificare recentă, dar poziția agregată pentru ultimele 28 de zile este 13,49, iar exportul global de query-uri nu conține un cluster identificabil. Nu se completează secțiuni dintr-un șablon generic și nu se schimbă snippetul doar pe baza ferestrei istorice.

Title-ul actual are 57 de caractere și poate rămâne până la exportul filtrat pe pagină. CTA-ul trebuie să rămână contextual și să nu promită eligibilitatea.

## Author, reviewer și surse

| URL | Author / reviewer | Verificare și sursă |
|---|---|---|
| DR 12 / DR 14 | FABER — Atelier de Consultanță / Echipa editorială FABER | `DE_VALIDAT_UMAN`; pagini blocate |
| GAL-AFIR | FABER — Atelier de Consultanță / Echipa editorială FABER | 2026-05-26, AFIR LEADER/DR-36; următoarea revizuire 2026-07-25 |
| Calculator SO | FABER — Atelier de Consultanță / Echipa editorială FABER | sursă, versiune și dată `DE_VALIDAT_UMAN` |
| Femeia Antreprenor | FABER — Atelier de Consultanță / Echipa editorială FABER | verificare 2026-05-20; revizuire expirată la 2026-07-19 |
| Program Regional Nord-Est | FABER — Atelier de Consultanță / Echipa editorială FABER | verificat 2026-07-20, ADR Nord-Est |
| AFIR Autoconsum | FABER — Atelier de Consultanță / Echipa editorială FABER | verificat 2026-07-20, Ghidul V7 — iunie 2026 |

Nu se publică nume personale; registrul folosește atribuirea organizațională.

## Ținte propuse pentru monitorizare

Țintele se activează numai după publicarea unei modificări aprobate și după salvarea baseline-ului exact de 90 de zile. Nu reprezintă garanții.

| Pagini eligibile | 28 zile după publicare | 56 zile după publicare |
|---|---|---|
| Calculator SO, după validarea sursei | CTR ≥ 0,60%; poziție ≤ 7,8; afișări fără scădere >10% | CTR ≥ 0,90%; poziție ≤ 7,4; afișări ≥ baseline |
| Femeia Antreprenor, după revizuire | CTR ≥ 1,60%; poziție ≤ 7,9; afișări fără scădere >10% | CTR ≥ 1,90%; poziție ≤ 7,5; afișări ≥ baseline |
| Program Regional Nord-Est | CTR ≥ 3,20%; poziție ≤ 7,2 | CTR ≥ 3,50%; poziție ≤ 6,9 |
| GAL-AFIR, doar pentru query-uri informaționale | baseline separat fără `galafir` navigațional; CTR ≥ baseline +0,30 pp | CTR ≥ baseline +0,50 pp; poziție fără regresie >0,5 |
| AFIR Autoconsum | fără țintă înainte de query → page; monitorizare | reevaluare dacă revine în pozițiile 6–12 |
| DR 12 / DR 14 | ținte suspendate cât timp paginile sunt `noindex` | se stabilesc după aprobarea P1.12 și reindexare |

Conversiile nu sunt incluse în exportul GSC disponibil. Baseline-ul și ținta de conversie trebuie preluate din analytics/CRM pe aceleași URL-uri și intervale; orice număr introdus acum ar fi inventat.

## Condiții pentru deblocare

1. Export GSC exact `Last 90 days`, cu filele Query, Page, Country și Device.
2. Pentru fiecare dintre cele șapte URL-uri: export filtrat pe pagină sau export API care asociază query → page.
3. Confirmarea P1.12 pentru DR 12 și DR 14.
4. Aprobarea sursei și versiunii Calculatorului SO.
5. Revizuirea factuală a paginii Femeia Antreprenor.
6. Baseline analytics/CRM pentru conversii.

După îndeplinirea acestor condiții, optimizarea se aplică numai URL-urilor care rămân oportunități curente, apoi se validează title/meta/H1, canonical, sitemap, JSON-LD, linkurile interne și CTA-ul.
