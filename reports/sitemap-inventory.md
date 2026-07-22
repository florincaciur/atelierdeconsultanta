# Inventar sitemap

Generatorul include numai rute locale 200, indexabile si self-canonical. `lastmod` exista numai cand provine din `lastMeaningfulUpdate` al unei inregistrari editoriale publice si complete.

## Rezumat

- URL-uri raportate in auditul initial: 102
- URL-uri in baseline-ul repository la inceputul P0.11: 92
- URL-uri incluse acum: 95
- URL-uri cu lastmod editorial verificabil: 19
- URL-uri fara lastmod (omis intentionat): 76
- sitemap-programs.xml: 17 (Pagini de programe)
- sitemap-guides.xml: 30 (Ghiduri si continut editorial)
- sitemap-core.xml: 48 (Pagini core, servicii, instrumente si juridice)

## Excluderi dupa motiv

- duplicate_policy_pending_legal_consolidation: 1
- missing_canonical: 2
- noindex_meta: 67
- noncanonical_file_variant: 2
- redirect_source: 94

## Lista excluderilor

| Ruta/URL | Fisier sursa | Motiv | Detaliu |
|---|---|---|---|
| https://atelierdeconsultanta.ro/gdpr | gdpr.html | duplicate_policy_pending_legal_consolidation | Politica duplicata este omisa din sitemap; redirectul ramane conditionat de aprobarea juridica si SEO. |
| /google8bbb9999c523a3bd | google8bbb9999c523a3bd.html | missing_canonical | - |
| /partials/global-header | partials/global-header.html | missing_canonical | - |
| https://atelierdeconsultanta.ro/404 | 404.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/admin | admin/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/afir | afir.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice | autoconsum-publici.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/blog | blog.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/calculator-soc | calculator-so-afir.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/calendar-fonduri-europene | calendar-fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | cat-costa-consultanta-fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | cheltuieli-eligibile-startup-nation.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | cod-caen-startup-nation.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | consultant-fonduri-europene-imm.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/consultanta-afir | consultanta-afir.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/consultanta-fonduri-europene | consultanta-fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | consultanta-fonduri-europene-bacau/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | consultanta-fonduri-europene-iasi/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | consultanta-fonduri-europene-suceava/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/consultanta-pnrr-digitalizare | consultanta-pnrr-digitalizare.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | consultanta-start-up-nation.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | consultanta-start-up-nation/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/contact | contact.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | cum-alegi-consultant-fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | digitalizare-imm-pnrr.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/dr-12-afir-instalarea-tinerilor-fermieri | dr-12-afir-instalarea-tinerilor-fermieri.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente | dr-14-afir-conditii-eligibilitate-greseli-frecvente.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/dr12-afir | dr12-afir-tineri-fermieri.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/eligibilitate-fonduri-europene | eligibilitate-fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/finantari-panouri-fotovoltaice | finantari-panouri-fotovoltaice.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene | firma-consultanta-fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fondul-de-modernizare | fondul-de-modernizare.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fondul-de-modernizare | fondul-de-modernizare/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene | fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-agricultura | fonduri-europene-agricultura.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | fonduri-europene-bacau/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-digitalizare | fonduri-europene-digitalizare.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-femei-antreprenor | fonduri-europene-femei-antreprenor.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | fonduri-europene-herambursabile-2026.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | fonduri-europene-herambursabile-2026/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | fonduri-europene-iasi/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-imm | fonduri-europene-imm.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | fonduri-europene-nerambursabile-2026.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | fonduri-europene-suceava/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | fonduri-nerambursabile.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-pentru-ferme | fonduri-pentru-ferme.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/fonduri-pentru-utilaje-agricole | fonduri-pentru-utilaje-agricole.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/ghiduri | ghiduri.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/granturi-digitalizare-imm | granturi-digitalizare-imm.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/granturi-digitalizare-imm | granturi-digitalizare-imm/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/greseli-fonduri-europene | greseli-fonduri-europene.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/intrebari-frecvente | intrebari-frecvente.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/pnrr | pnrr.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/pnrr | pnrr/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | pnrr-digitalizare-imm.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | pnrr-digitalizare-imm/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/portofoliu | portofoliu/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/programul-tranzitie-justa | programul-tranzitie-justa/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026 | start-up-nation.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026 | start-up-nation/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | start-up-nation-2026-cheltuieli-eligibile.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | start-up-nation-2026-conditii.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | start-up-nation-2026-idei-afaceri.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | start-up-nation-2026-idei-afaceri-plan.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri | start-up-nation-2026-plan-de-afaceri.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | startup-nation-2026-conditii.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | studii-de-caz.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | studii-de-caz/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/testimoniale | testimoniale.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/testimoniale | testimoniale/index.html | noindex_meta | - |
| https://atelierdeconsultanta.ro/dr14 | dr14-afir-ferme-mici.html | noncanonical_file_variant | canonical route: /dr14 |
| https://atelierdeconsultanta.ro/dr14 | dr14-afir-ferme-mici/index.html | noncanonical_file_variant | canonical route: /dr14 |
| https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/calculator-soc | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/calculator-soc | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/calculator-soc | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-cheltuieli-eligibile | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/consultant-fonduri-europene-imm | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr12-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr12-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr12-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr12-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr12-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/dr14 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/e-move | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/e-move | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/e-move | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/e-move | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/fonduri-europene-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/gal-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/gal-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | _redirects | redirect_source | HTTP 301 |
| / | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/gal-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/gal-afir | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-plan-de-afaceri | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/digitalizare-imm-pnrr | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/pocidif-21 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/por-adr-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/por-adr-nord-est | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/pro-infra | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026 | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/start-up-nation-2026-conditii | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | _redirects | redirect_source | HTTP 301 |
| https://atelierdeconsultanta.ro/studii-de-caz-fonduri-europene | _redirects | redirect_source | HTTP 301 |
