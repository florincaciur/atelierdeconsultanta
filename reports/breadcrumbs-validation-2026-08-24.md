# Task 14 — Breadcrumbs vizibile și BreadcrumbList coerent

Data auditului: 2026-08-24

Rezultat: **PASS** — 105/105 URL-uri și 114 surse HTML verificate.

## Mapping pe tipuri

| Tip | Părinte canonic | Regulă |
|---|---|---|
| Program | `/fonduri-europene` → hub de familie | Ruta programului vine din registrul unic; familia din `discovery.parentHub`. |
| Ghid / articol / întrebare | `/resurse` | Resurse este rădăcina publică; `/ghiduri`, `/blog` și celelalte huburi rămân copii canonici. |
| Serviciu | `/consultanta-fonduri-europene` | Landing-ul principal este rădăcină și este etichetat «Servicii» când apare ca părinte. |
| Instrument | `/instrumente` | Instrumentele rămân sub hub-ul canonic existent. |
| Despre / metodologie / cazuri | `/despre-faber` | Paginile de încredere folosesc rădăcina de brand. |
| Legal / Contact | `/` | Traseu direct, fără nivel intermediar artificial. |

## Validare crawl și paritate

| URL | Rezultat | Niveluri | Părinți verificați | Surse HTML | Probleme |
|---|---:|---:|---|---|---|
| `/` | PASS | — | — | `index.html` | — |
| `/acte-necesare-fonduri-europene-nerambursabile` | PASS | 3 | `/` → `/resurse` | `acte-necesare-fonduri-europene-nerambursabile/index.html` | — |
| `/afir` | PASS | 3 | `/` → `/fonduri-europene` | `afir/index.html` | — |
| `/afir-autoconsum-agroalimentar` | PASS | 4 | `/` → `/fonduri-europene` → `/afir` | `afir-autoconsum-agroalimentar.html`<br>`afir-autoconsum-agroalimentar/index.html` | — |
| `/apeluri-gal` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | `apeluri-gal/index.html` | — |
| `/autoconsum-public-fotovoltaice-institutii-publice` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `autoconsum-public-fotovoltaice-institutii-publice.html`<br>`autoconsum-public-fotovoltaice-institutii-publice/index.html` | — |
| `/blog` | PASS | 3 | `/` → `/resurse` | `blog/index.html` | — |
| `/blog-afir-fotovoltaice-ferme-2026` | PASS | 3 | `/` → `/resurse` | `blog-afir-fotovoltaice-ferme-2026.html` | — |
| `/calculator-soc` | PASS | 3 | `/` → `/instrumente` | `calculator-soc.html` | — |
| `/calendar-fonduri-europene` | PASS | 3 | `/` → `/instrumente` | `calendar-fonduri-europene/index.html` | — |
| `/cand-merita-consultant-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `cand-merita-consultant-fonduri-europene.html` | — |
| `/cat-costa-consultanta-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `cat-costa-consultanta-fonduri-europene/index.html` | — |
| `/cat-costa-consultanta-fonduri-europene-ghid` | PASS | 3 | `/` → `/resurse` | `cat-costa-consultanta-fonduri-europene-ghid.html` | — |
| `/ce-acte-sunt-necesare-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `ce-acte-sunt-necesare-fonduri-europene.html` | — |
| `/cheltuieli-eligibile-digitalizare-imm` | PASS | 3 | `/` → `/resurse` | `cheltuieli-eligibile-digitalizare-imm.html` | — |
| `/cheltuieli-eligibile-pocidif-21` | PASS | 3 | `/` → `/resurse` | `cheltuieli-eligibile-pocidif-21/index.html` | — |
| `/cod-caen-start-up-nation-2026` | PASS | 3 | `/` → `/resurse` | `cod-caen-start-up-nation-2026/index.html` | — |
| `/consultant-fonduri-europene-imm` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `consultant-fonduri-europene-imm/index.html` | — |
| `/consultanta-afir` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `consultanta-afir/index.html` | — |
| `/consultanta-fonduri-europene` | PASS | 2 | `/` | `consultanta-fonduri-europene/index.html` | — |
| `/consultanta-fonduri-europene-bucuresti` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `consultanta-fonduri-europene-bucuresti/index.html` | — |
| `/consultanta-pnrr-digitalizare` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `consultanta-pnrr-digitalizare/index.html` | — |
| `/consultanta-start-up-nation-2026` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `consultanta-start-up-nation-2026/index.html` | — |
| `/contact` | PASS | 2 | `/` | `contact/index.html` | — |
| `/cum-alegi-consultant-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `cum-alegi-consultant-fonduri-europene/index.html` | — |
| `/cum-alegi-programul-potrivit-fonduri-europene-2026` | PASS | 3 | `/` → `/resurse` | `cum-alegi-programul-potrivit-fonduri-europene-2026.html` | — |
| `/cum-se-calculeaza-cofinantarea-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `cum-se-calculeaza-cofinantarea-fonduri-europene.html` | — |
| `/cum-se-verifica-eligibilitatea-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `cum-se-verifica-eligibilitatea-fonduri-europene.html` | — |
| `/despre-faber` | PASS | 2 | `/` | `despre-faber/index.html` | — |
| `/diaspora-investeste-acasa` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | `diaspora-investeste-acasa/index.html` | — |
| `/digitalizare-imm` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-digitalizare` | `digitalizare-imm.html`<br>`digitalizare-imm/index.html` | — |
| `/digitalizare-imm-erp-crm-cloud` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `digitalizare-imm-erp-crm-cloud.html` | — |
| `/digitalizare-imm-pnrr` | PASS | 3 | `/` → `/resurse` | `digitalizare-imm-pnrr/index.html` | — |
| `/documente-punctaj-pocidif-21` | PASS | 3 | `/` → `/resurse` | `documente-punctaj-pocidif-21/index.html` | — |
| `/dr-12-afir-instalarea-tinerilor-fermieri` | PASS | 3 | `/` → `/fonduri-europene` | `dr-12-afir-instalarea-tinerilor-fermieri.html` | — |
| `/dr-14-afir-conditii-eligibilitate-greseli-frecvente` | PASS | 3 | `/` → `/fonduri-europene` | `dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` | — |
| `/dr12-afir` | PASS | 4 | `/` → `/fonduri-europene` → `/afir` | `dr12-afir.html`<br>`dr12-afir/index.html` | — |
| `/dr12-vs-dr14` | PASS | 3 | `/` → `/resurse` | `dr12-vs-dr14.html` | — |
| `/dr14` | PASS | 4 | `/` → `/fonduri-europene` → `/afir` | `dr14.html`<br>`dr14/index.html` | — |
| `/dr18` | PASS | 4 | `/` → `/fonduri-europene` → `/afir` | `dr18/index.html` | — |
| `/e-drive` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `e-drive/index.html` | — |
| `/e-mobility` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `e-mobility/index.html` | — |
| `/e-move` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `e-move/index.html` | — |
| `/eligibilitate-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `eligibilitate-fonduri-europene/index.html` | — |
| `/eligibilitate-pocidif-21` | PASS | 3 | `/` → `/resurse` | `eligibilitate-pocidif-21/index.html` | — |
| `/femeia-antreprenor-2026` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | `femeia-antreprenor-2026.html`<br>`femeia-antreprenor-2026/index.html` | — |
| `/femeia-antreprenor-2026-conditii-idei-afaceri` | PASS | 3 | `/` → `/resurse` | `femeia-antreprenor-2026-conditii-idei-afaceri.html` | — |
| `/finantari-panouri-fotovoltaice` | PASS | 3 | `/` → `/fonduri-europene` | `finantari-panouri-fotovoltaice/index.html` | — |
| `/firma-consultanta-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `firma-consultanta-fonduri-europene/index.html` | — |
| `/fondul-de-modernizare` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `fondul-de-modernizare/index.html` | — |
| `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum/index.html` | — |
| `/fondul-modernizare-energie-regenerabila-2026` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `fondul-modernizare-energie-regenerabila-2026.html`<br>`fondul-modernizare-energie-regenerabila-2026/index.html` | — |
| `/fondul-modernizare-pc1-stocare` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `fondul-modernizare-pc1-stocare/index.html` | — |
| `/fonduri-europene` | PASS | 2 | `/` | `fonduri-europene/index.html` | — |
| `/fonduri-europene-agricultura` | PASS | 3 | `/` → `/fonduri-europene` | `fonduri-europene-agricultura/index.html` | — |
| `/fonduri-europene-bucuresti` | PASS | 3 | `/` → `/resurse` | `fonduri-europene-bucuresti/index.html` | — |
| `/fonduri-europene-caen/0111-culturi-cereale` | PASS | 3 | `/` → `/resurse` | `fonduri-europene-caen/0111-culturi-cereale/index.html` | — |
| `/fonduri-europene-caen/4321-instalatii-electrice` | PASS | 3 | `/` → `/resurse` | `fonduri-europene-caen/4321-instalatii-electrice/index.html` | — |
| `/fonduri-europene-caen/5610-restaurante` | PASS | 3 | `/` → `/resurse` | `fonduri-europene-caen/5610-restaurante/index.html` | — |
| `/fonduri-europene-caen/6201-dezvoltare-software` | PASS | 3 | `/` → `/resurse` | `fonduri-europene-caen/6201-dezvoltare-software/index.html` | — |
| `/fonduri-europene-digitalizare` | PASS | 3 | `/` → `/fonduri-europene` | `fonduri-europene-digitalizare/index.html` | — |
| `/fonduri-europene-femei-antreprenor` | PASS | 3 | `/` → `/fonduri-europene` | `fonduri-europene-femei-antreprenor/index.html` | — |
| `/fonduri-europene-imm` | PASS | 3 | `/` → `/fonduri-europene` | `fonduri-europene-imm/index.html` | — |
| `/fonduri-europene-nerambursabile-2026` | PASS | 3 | `/` → `/resurse` | `fonduri-europene-nerambursabile-2026/index.html` | — |
| `/fonduri-europene-nord-est` | PASS | 3 | `/` → `/resurse` | `fonduri-europene-nord-est/index.html` | — |
| `/fonduri-nerambursabile` | PASS | 3 | `/` → `/resurse` | `fonduri-nerambursabile/index.html` | — |
| `/fonduri-pentru-ferme` | PASS | 3 | `/` → `/fonduri-europene` | `fonduri-pentru-ferme/index.html` | — |
| `/fonduri-pentru-utilaje-agricole` | PASS | 3 | `/` → `/resurse` | `fonduri-pentru-utilaje-agricole/index.html` | — |
| `/fonduri-regionale` | PASS | 3 | `/` → `/fonduri-europene` | `fonduri-regionale/index.html` | — |
| `/gal-afir` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | `gal-afir/index.html` | — |
| `/gdpr` | PASS | 2 | `/` | `gdpr.html` | — |
| `/ghiduri` | PASS | 3 | `/` → `/resurse` | `ghiduri/index.html` | — |
| `/glosar-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `glosar-fonduri-europene/index.html` | — |
| `/greseli-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `greseli-fonduri-europene/index.html` | — |
| `/idei-afaceri-fonduri-europene` | PASS | 3 | `/` → `/fonduri-europene` | `idei-afaceri-fonduri-europene.html` | — |
| `/instrumente` | PASS | 2 | `/` | `instrumente/index.html` | — |
| `/intrebari-frecvente` | PASS | 3 | `/` → `/resurse` | `intrebari-frecvente/index.html` | — |
| `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm` | PASS | 3 | `/` → `/resurse` | `intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html` | — |
| `/intrebari/ce-documente-sunt-necesare-pentru-dr12` | PASS | 3 | `/` → `/resurse` | `intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html` | — |
| `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html` | — |
| `/investitii-modernizarea-microintreprinderilor-apel-2` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-regionale` | `investitii-modernizarea-microintreprinderilor-apel-2.html`<br>`investitii-modernizarea-microintreprinderilor-apel-2/index.html` | — |
| `/management-proiecte-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `management-proiecte-fonduri-europene/index.html` | — |
| `/metodologie-verificare-eligibilitate` | PASS | 3 | `/` → `/despre-faber` | `metodologie-verificare-eligibilitate/index.html` | — |
| `/plan-de-afaceri-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `plan-de-afaceri-fonduri-europene/index.html` | — |
| `/pnrr` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-digitalizare` | `pnrr/index.html` | — |
| `/pnrr-digitalizare-imm-cheltuieli-eligibile` | PASS | 3 | `/` → `/resurse` | `pnrr-digitalizare-imm-cheltuieli-eligibile.html` | — |
| `/pocidif-21` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-digitalizare` | `pocidif-21/index.html` | — |
| `/politica-de-confidentialitate` | PASS | 2 | `/` | `politica-de-confidentialitate.html` | — |
| `/pro-infra` | PASS | 4 | `/` → `/fonduri-europene` → `/finantari-panouri-fotovoltaice` | `pro-infra/index.html` | — |
| `/programul-tranzitie-justa` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-regionale` | `programul-tranzitie-justa/index.html` | — |
| `/programul-tranzitie-justa-intrebari-documente` | PASS | 3 | `/` → `/resurse` | `programul-tranzitie-justa-intrebari-documente/index.html` | — |
| `/proiectare-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `proiectare-fonduri-europene/index.html` | — |
| `/resurse` | PASS | 2 | `/` | `resurse/index.html` | — |
| `/resurse-utile` | PASS | 3 | `/` → `/resurse` | `resurse-utile/index.html` | — |
| `/start-up-nation-2026` | PASS | 4 | `/` → `/fonduri-europene` → `/fonduri-europene-imm` | `start-up-nation-2026.html`<br>`start-up-nation-2026/index.html` | — |
| `/start-up-nation-2026-cheltuieli-eligibile` | PASS | 3 | `/` → `/resurse` | `start-up-nation-2026-cheltuieli-eligibile/index.html` | — |
| `/start-up-nation-2026-conditii` | PASS | 3 | `/` → `/resurse` | `start-up-nation-2026-conditii/index.html` | — |
| `/start-up-nation-2026-idei-afaceri` | PASS | 3 | `/` → `/resurse` | `start-up-nation-2026-idei-afaceri/index.html` | — |
| `/start-up-nation-2026-plan-de-afaceri` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `start-up-nation-2026-plan-de-afaceri/index.html` | — |
| `/studii-de-caz-fonduri-europene` | PASS | 3 | `/` → `/despre-faber` | `studii-de-caz-fonduri-europene/index.html` | — |
| `/studiu-fezabilitate-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `studiu-fezabilitate-fonduri-europene/index.html` | — |
| `/surse-oficiale-fonduri-europene` | PASS | 3 | `/` → `/resurse` | `surse-oficiale-fonduri-europene/index.html` | — |
| `/termeni-si-conditii` | PASS | 2 | `/` | `termeni-si-conditii.html` | — |
| `/verificare-eligibilitate-fonduri-europene` | PASS | 3 | `/` → `/consultanta-fonduri-europene` | `verificare-eligibilitate-fonduri-europene/index.html` | — |
| `/webinarii` | PASS | 3 | `/` → `/resurse` | `webinarii/index.html` | — |
