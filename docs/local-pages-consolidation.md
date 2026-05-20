# Local Pages Consolidation

Data audit: 2026-05-20

## Rezumat

Auditul a identificat un cluster local creat programatic pentru Iasi, Suceava, Bacau si Bucuresti:

- `fonduri-europene-[oras]`
- `consultanta-fonduri-europene-[oras]`

Paginile locale aveau 97-98% similaritate intre ele si nu includeau date locale verificabile suficiente. Strategia aplicata este consolidarea, nu extinderea volumului de pagini locale.

## Strategie aplicata

- Pastram o pagina regionala noua: `/fonduri-europene-nord-est`.
- Pastram pagina de program regional: `/por-adr-nord-est`.
- Consolidam paginile Iasi, Suceava si Bacau catre `/fonduri-europene-nord-est`.
- Consolidam Bucuresti catre paginile generale, deoarece nu exista inca date locale Bucuresti-Ilfov suficiente:
  - `/fonduri-europene-bucuresti` -> `/fonduri-europene`
  - `/consultanta-fonduri-europene-bucuresti` -> `/consultanta-fonduri-europene`
- Paginile locale vechi raman ca fallback HTML `noindex, follow`, cu canonical si redirect JS/meta catre destinatia consolidata.
- Sitemap-ul nu mai include paginile locale consolidate.
- Generatorul `tools/generate-programmatic-seo.js` nu mai regenereaza local pages cu status `consolidate`.

## Inventar si decizie

| URL | H1 | Keyword tinta | Similaritate estimata | Informatie locala reala | Recomandare | Actiune |
| --- | --- | --- | --- | --- | --- | --- |
| `/fonduri-europene-iasi` | Fonduri europene Iasi | fonduri europene Iasi | 98% | Nu. Text regional generic, fara date locale verificabile. | redirect | 301 catre `/fonduri-europene-nord-est`; fallback noindex |
| `/consultanta-fonduri-europene-iasi` | Consultanta fonduri europene Iasi | consultanta fonduri europene Iasi | 97% | Nu. Text de consultanta repetat, fara exemple locale verificabile. | redirect | 301 catre `/fonduri-europene-nord-est`; fallback noindex |
| `/fonduri-europene-suceava` | Fonduri europene Suceava | fonduri europene Suceava | 97% | Nu. Mentioneaza agricultura/turism, dar fara surse sau exemple reale. | redirect | 301 catre `/fonduri-europene-nord-est`; fallback noindex |
| `/consultanta-fonduri-europene-suceava` | Consultanta fonduri europene Suceava | consultanta fonduri europene Suceava | 97% | Nu. Text aproape identic cu celelalte pagini locale. | redirect | 301 catre `/fonduri-europene-nord-est`; fallback noindex |
| `/fonduri-europene-bacau` | Fonduri europene Bacau | fonduri europene Bacau | 98% | Nu. Mentioneaza IMM/productie/energie, dar fara detalii locale verificate. | redirect | 301 catre `/fonduri-europene-nord-est`; fallback noindex |
| `/consultanta-fonduri-europene-bacau` | Consultanta fonduri europene Bacau | consultanta fonduri europene Bacau | 97% | Nu. Text de template. | redirect | 301 catre `/fonduri-europene-nord-est`; fallback noindex |
| `/fonduri-europene-bucuresti` | Fonduri europene Bucuresti | fonduri europene Bucuresti | 97% | Nu. Nu exista pagina regionala Bucuresti-Ilfov cu date proprii. | redirect | 301 catre `/fonduri-europene`; fallback noindex |
| `/consultanta-fonduri-europene-bucuresti` | Consultanta fonduri europene Bucuresti | consultanta fonduri europene Bucuresti | 97% | Nu. Text de template pentru consultanta locala. | redirect | 301 catre `/consultanta-fonduri-europene`; fallback noindex |
| `/por-adr-nord-est` | Investitii pentru modernizarea microintreprinderilor in Nord-Est | POR ADR Nord-Est microintreprinderi | 21% fata de clusterul local | Da. Pagina de program regional cu sursa ADR Nord-Est. | pastreaza | Pastreaza ca pagina de program, legata din noua pagina regionala |
| `/fonduri-europene-nord-est` | Fonduri europene Nord-Est | fonduri europene Nord-Est | pagina noua consolidata | Partial. Include judete, diferente intre programe si surse; exemplele locale au `TODO_DATE_LOCALE`. | pastreaza / imbunatateste | Pagina regionala creata; necesita completari cu date locale reale |

## Redirecturi adaugate

### Catre `/fonduri-europene-nord-est`

- `/fonduri-europene-iasi`
- `/fonduri-europene-iasi/`
- `/fonduri-europene-iasi.html`
- `/fonduri-europene-iasi/index.html`
- `/consultanta-fonduri-europene-iasi`
- `/consultanta-fonduri-europene-iasi/`
- `/consultanta-fonduri-europene-iasi.html`
- `/consultanta-fonduri-europene-iasi/index.html`
- `/fonduri-europene-suceava`
- `/fonduri-europene-suceava/`
- `/fonduri-europene-suceava.html`
- `/fonduri-europene-suceava/index.html`
- `/consultanta-fonduri-europene-suceava`
- `/consultanta-fonduri-europene-suceava/`
- `/consultanta-fonduri-europene-suceava.html`
- `/consultanta-fonduri-europene-suceava/index.html`
- `/fonduri-europene-bacau`
- `/fonduri-europene-bacau/`
- `/fonduri-europene-bacau.html`
- `/fonduri-europene-bacau/index.html`
- `/consultanta-fonduri-europene-bacau`
- `/consultanta-fonduri-europene-bacau/`
- `/consultanta-fonduri-europene-bacau.html`
- `/consultanta-fonduri-europene-bacau/index.html`

### Catre pagini generale

- `/fonduri-europene-bucuresti` -> `/fonduri-europene`
- `/fonduri-europene-bucuresti/` -> `/fonduri-europene`
- `/fonduri-europene-bucuresti.html` -> `/fonduri-europene`
- `/fonduri-europene-bucuresti/index.html` -> `/fonduri-europene`
- `/consultanta-fonduri-europene-bucuresti` -> `/consultanta-fonduri-europene`
- `/consultanta-fonduri-europene-bucuresti/` -> `/consultanta-fonduri-europene`
- `/consultanta-fonduri-europene-bucuresti.html` -> `/consultanta-fonduri-europene`
- `/consultanta-fonduri-europene-bucuresti/index.html` -> `/consultanta-fonduri-europene`

## Pagina regionala creata

URL: `/fonduri-europene-nord-est`

Include:

- judete acoperite: Iasi, Suceava, Bacau, Botosani, Neamt, Vaslui;
- rolul ADR Nord-Est pentru Programul Regional Nord-Est;
- diferenta intre programe regionale, AFIR si programe nationale / PNRR;
- tabel de orientare: `Tip beneficiar | Program posibil | Ce verificam | Link intern`;
- CTA catre verificare eligibilitate;
- surse oficiale regionale;
- exemple locale anonimizate marcate cu `TODO_DATE_LOCALE` acolo unde lipsesc date verificate.

## Pagini care necesita rescriere manuala

- `/fonduri-europene-nord-est`: completari cu date locale reale pentru exemplele marcate `TODO_DATE_LOCALE`.
- Bucuresti-Ilfov: nu se recomanda pagina separata pana cand exista date locale reale, surse regionale specifice si exemple anonimizate verificate.
- Botosani, Neamt, Vaslui: nu se recomanda pagini separate pana cand exista continut local propriu, nu doar variatii de keyword.

## Regula editoriala pentru pagini locale viitoare

O pagina locala se publica doar daca are cel putin doua dintre urmatoarele:

- program sau apel regional localizat clar;
- sursa oficiala regionala/judeteana;
- exemplu anonimizat local verificabil;
- diferente reale de eligibilitate, documente sau calendar;
- intrebari locale specifice care nu se suprapun cu pagina regionala.

Altfel, intentia se consolideaza intr-o pagina regionala sau intr-o pagina serviciu principala.
