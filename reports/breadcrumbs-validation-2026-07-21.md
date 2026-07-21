# P1.04 — Breadcrumbs standardizate și schema sincronizată

Data auditului: 2026-07-21

Rezultat: **PASS** — 91/91 URL-uri conforme.

## Mapping pe tipuri

| Tip | Părinte canonic | Regulă |
|---|---|---|
| Program | `/fonduri-europene` → hub de familie | Ruta programului vine din registrul unic; familia din `discovery.parentHub`. |
| Ghid / întrebare | `/ghiduri` | Ghidul răspunde complet, apoi oferă următorul pas. |
| Serviciu | `/consultanta-fonduri-europene` | Landing-ul principal este rădăcină; nu se inventează o rută `/servicii`. |
| Instrument | `/instrumente` | Instrumentele rămân sub hub-ul canonic existent. |
| Despre / metodologie | `/despre-faber` | Paginile de încredere folosesc rădăcina de brand. |
| Legal / Contact | `/` | Traseu direct, fără nivel intermediar artificial. |

## Validare crawl și paritate

| URL | Rezultat | Niveluri | Părinți verificați | Probleme |
|---|---:|---:|---|---|
| `/afir-autoconsum-agroalimentar` | PASS | 4 | `/` → `/fonduri-europene` → `/afir` | — |
| `/apeluri-gal` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | — |
| `/autoconsum-public-fotovoltaice-institutii-publice` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | — |
| `/e-move` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | — |
| `/femeia-antreprenor-2026` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | — |
| `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | — |
| `/fondul-modernizare-energie-regenerabila-2026` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | — |
| `/fonduri-regionale` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/gal-afir` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | — |
| `/investitii-modernizarea-microintreprinderilor-apel-2` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-regionale` | — |
| `/pocidif-21` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-digitalizare` | — |
| `/por-adr-nord-est` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-regionale` | — |
| `/start-up-nation-2026` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | — |
| `/blog` | PASS | 3 | `/` → `/ghiduri` | — |
| `/metodologie-verificare-eligibilitate` | PASS | 3 | `/` → `/despre-faber` | — |
| `/surse-oficiale-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/acte-necesare-fonduri-europene-nerambursabile` | PASS | 3 | `/` → `/ghiduri` | — |
| `/blog-afir-fotovoltaice-ferme-2026` | PASS | 3 | `/` → `/ghiduri` | — |
| `/cat-costa-consultanta-fonduri-europene-ghid` | PASS | 3 | `/` → `/ghiduri` | — |
| `/cheltuieli-eligibile-digitalizare-imm` | PASS | 3 | `/` → `/ghiduri` | — |
| `/cheltuieli-eligibile-pocidif-21` | PASS | 3 | `/` → `/ghiduri` | — |
| `/cod-caen-start-up-nation-2026` | PASS | 3 | `/` → `/ghiduri` | — |
| `/documente-punctaj-pocidif-21` | PASS | 3 | `/` → `/ghiduri` | — |
| `/femeia-antreprenor-2026-conditii-idei-afaceri` | PASS | 3 | `/` → `/ghiduri` | — |
| `/ghiduri` | PASS | 2 | `/` | — |
| `/glosar-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/greseli-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/intrebari-frecvente` | PASS | 4 | `/` → `/ghiduri` → `/resurse` | — |
| `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm` | PASS | 3 | `/` → `/ghiduri` | — |
| `/intrebari/ce-documente-sunt-necesare-pentru-dr12` | PASS | 3 | `/` → `/ghiduri` | — |
| `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/pnrr-digitalizare-imm-cheltuieli-eligibile` | PASS | 3 | `/` → `/ghiduri` | — |
| `/programul-tranzitie-justa-intrebari-documente` | PASS | 3 | `/` → `/ghiduri` | — |
| `/resurse` | PASS | 3 | `/` → `/ghiduri` | — |
| `/resurse-utile` | PASS | 3 | `/` → `/ghiduri` | — |
| `/start-up-nation-2026-cheltuieli-eligibile` | PASS | 3 | `/` → `/ghiduri` | — |
| `/start-up-nation-2026-conditii` | PASS | 3 | `/` → `/ghiduri` | — |
| `/start-up-nation-2026-idei-afaceri` | PASS | 3 | `/` → `/ghiduri` | — |
| `/start-up-nation-2026-plan-de-afaceri` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/studii-de-caz-fonduri-europene` | PASS | 3 | `/` → `/despre-faber` | — |
| `/termeni-si-conditii` | PASS | 2 | `/` | — |
| `/webinarii` | PASS | 4 | `/` → `/ghiduri` → `/resurse` | — |
| `/` | PASS | — | — | — |
| `/consultanta-fonduri-europene` | PASS | 2 | `/` | — |
| `/fonduri-europene` | PASS | 2 | `/` | — |
| `/despre-faber` | PASS | 2 | `/` | — |
| `/afir` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/calculator-soc` | PASS | 3 | `/` → `/instrumente` | — |
| `/calendar-fonduri-europene` | PASS | 3 | `/` → `/instrumente` | — |
| `/cand-merita-consultant-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/cat-costa-consultanta-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/ce-acte-sunt-necesare-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/consultant-fonduri-europene-imm` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/consultanta-afir` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/consultanta-fonduri-europene-bucuresti` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/consultanta-pnrr-digitalizare` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/consultanta-start-up-nation-2026` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/contact` | PASS | 2 | `/` | — |
| `/cum-alegi-consultant-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/cum-alegi-programul-potrivit-fonduri-europene-2026` | PASS | 3 | `/` → `/ghiduri` | — |
| `/cum-se-calculeaza-cofinantarea-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/cum-se-verifica-eligibilitatea-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/digitalizare-imm-erp-crm-cloud` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/digitalizare-imm-pnrr` | PASS | 3 | `/` → `/ghiduri` | — |
| `/dr12-vs-dr14` | PASS | 3 | `/` → `/ghiduri` | — |
| `/eligibilitate-fonduri-europene` | PASS | 3 | `/` → `/ghiduri` | — |
| `/eligibilitate-pocidif-21` | PASS | 3 | `/` → `/ghiduri` | — |
| `/finantari-panouri-fotovoltaice` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/firma-consultanta-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/fonduri-europene-agricultura` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/fonduri-europene-bucuresti` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-europene-caen/0111-culturi-cereale` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-europene-caen/4321-instalatii-electrice` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-europene-caen/5610-restaurante` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-europene-caen/6201-dezvoltare-software` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-europene-digitalizare` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/fonduri-europene-femei-antreprenor` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/fonduri-europene-imm` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/fonduri-europene-nerambursabile-2026` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-europene-nord-est` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-nerambursabile` | PASS | 3 | `/` → `/ghiduri` | — |
| `/fonduri-pentru-ferme` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/fonduri-pentru-utilaje-agricole` | PASS | 3 | `/` → `/ghiduri` | — |
| `/idei-afaceri-fonduri-europene` | PASS | 3 | `/` → `/fonduri-europene` | — |
| `/instrumente` | PASS | 2 | `/` | — |
| `/management-proiecte-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/plan-de-afaceri-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/politica-de-confidentialitate` | PASS | 2 | `/` | — |
| `/proiectare-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/studiu-fezabilitate-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
| `/verificare-eligibilitate-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | — |
