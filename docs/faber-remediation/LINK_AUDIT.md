# Task 20 — Audit reproducibil al linkurilor și surselor

Generat: 2026-08-24T19:59:56.393Z

## Rezultat

- Audit structural: **PASS** — 203 fișiere, 15834 legături locale, 704 fragmente, 0 erori.
- Graph canonical: **PASS** — 104 pagini, 3301 muchii distincte, 0 pagini cu zero incoming.
- Inventar extern: **78 URL-uri unice** (73 publice, 26 surse oficiale, 9 documente publice).
- Canale speciale: 2 mailto, 2 tel, 2 WhatsApp; documente locale: 4.
- Surse oficiale confirmate 404/410: **0**.

Un răspuns blocat, un timeout sau o provocare anti-bot nu justifică eliminarea unei surse oficiale. Aceste cazuri rămân separat ca `blocked_external`/`timeout` pentru verificare umană într-un browser obișnuit.

## Clasificare HTTP externă

| Clasificare | URL-uri |
|---|---:|
| 200 | 50 |
| permanent_redirect | 2 |
| temporary_redirect | 4 |
| 404 | 0 |
| 410 | 0 |
| 5xx | 2 |
| timeout | 1 |
| blocked_external | 19 |

## Acoperirea suprafețelor

| Suprafață inspectată | Referințe/blocuri |
|---|---:|
| router | 136 |
| homepage | 151 |
| navigation | 6864 |
| footer | 541 |
| registry | 141 |
| program | 2207 |
| family | 371 |
| guide | 1103 |
| faq | 0 |
| breadcrumbs | 221 |
| schema | 2211 |
| legal | 193 |
| calculator | 94 |
| core | 5438 |
| faqBlocks | 405 |
| schemaUrls | 2211 |

FAQ-urile fără link nu sunt tratate ca eroare: toate blocurile vizibile sunt inspectate, iar orice link adăugat ulterior intră automat în inventar.

## Integritate internă și surse

- Linkuri interne rupte/redirectate: 0.
- URL-uri interne legacy: 0.
- Pagini canonice orfane: 0.
- Surse oficiale din registry: 26; surse prezente numai în registry: 5.
- Linkuri publice către documente oficiale/interne: 13; textele descriptive sunt verificate contextual.

## URL-uri externe

| Clasificare | HTTP | URL verificat | Destinație finală | Roluri | Exemplu sursă |
|---|---:|---|---|---|---|
| temporary_redirect | 200 | [https://wa.me/40769828338](https://wa.me/40769828338) | https://api.whatsapp.com/send/?phone=40769828338&text&type=phone_number&app_absent=0 | calculator, core, family, guide, homepage, legal, program | /digitalizare-imm |
| temporary_redirect | 200 | [https://wa.me/40753326229](https://wa.me/40753326229) | https://api.whatsapp.com/send/?phone=40753326229&text&type=phone_number&app_absent=0 | calculator, core, family, guide, homepage, legal, program | /digitalizare-imm |
| blocked_external | — | [https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/) | — | family, navigation, official_source, program, registry, schema | /digitalizare-imm |
| 200 | 206 | [https://schema.org](https://schema.org) | — | schema | /digitalizare-imm |
| 200 | 200 | [https://www.instagram.com/atelier.de.consultanta/](https://www.instagram.com/atelier.de.consultanta/) | — | core, legal, registry, schema | /digitalizare-imm |
| 200 | 206 | [https://schema.org/IncentiveStatusRetired](https://schema.org/IncentiveStatusRetired) | — | schema | /digitalizare-imm |
| 200 | 200 | [https://www.afir.ro/comunicate/consultare-publica-pentru-consolidarea-exploatatiilor-tinerilor-fermieri/](https://www.afir.ro/comunicate/consultare-publica-pentru-consolidarea-exploatatiilor-tinerilor-fermieri/) | — | core, family, navigation, official_source, program, registry, schema | /dr12-afir |
| 200 | 206 | [https://schema.org/IncentiveStatusInDevelopment](https://schema.org/IncentiveStatusInDevelopment) | — | schema | /dr12-afir |
| 200 | 200 | [https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/) | — | core, family, navigation, official_source, program, registry, schema | /dr14 |
| 200 | 200 | [https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/) | — | core, program | /dr14 |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/306915](https://legislatie.just.ro/Public/DetaliiDocument/306915) | — | family, navigation, official_source, program, registry, schema | /pro-infra |
| 200 | 206 | [https://www.afir.ro/media/hkfp4w0v/ghidul-solicitantului-schem%C4%83-energie-autoconsum-v7-iunie-2026.pdf](https://www.afir.ro/media/hkfp4w0v/ghidul-solicitantului-schem%C4%83-energie-autoconsum-v7-iunie-2026.pdf) | — | navigation, program | /afir-autoconsum-agroalimentar |
| 200 | 200 | [https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/) | — | family, official_source, program, registry, schema | /afir-autoconsum-agroalimentar |
| 200 | 200 | [https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-36/](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-36/) | — | navigation, program | /apeluri-gal |
| 200 | 200 | [https://gal.afir.ro/](https://gal.afir.ro/) | — | core, family, navigation, official_source, program, registry, schema | /apeluri-gal |
| 200 | 200 | [https://www.afir.ro/finantare/leader/](https://www.afir.ro/finantare/leader/) | — | core, program | /apeluri-gal |
| 200 | 200 | [https://legislatie.just.ro/public/DetaliiDocument/276306](https://legislatie.just.ro/public/DetaliiDocument/276306) | — | navigation, program | /autoconsum-public-fotovoltaice-institutii-publice |
| 200 | 200 | [https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) | — | family, official_source, program, registry, schema | /autoconsum-public-fotovoltaice-institutii-publice |
| 200 | 206 | [https://diaspora.gov.ro/info/stiri-din-romania/761-investeste-acasa.html](https://diaspora.gov.ro/info/stiri-din-romania/761-investeste-acasa.html) | — | family, official_source, program, registry, schema | /diaspora-investeste-acasa |
| temporary_redirect | 200 | [https://mfinante.gov.ro/](https://mfinante.gov.ro/) | https://mfinante.gov.ro/ro/web/site | program | /diaspora-investeste-acasa |
| 200 | 200 | [https://www.afir.ro/api/file?filename=Ghidul+solicitantului+DR+18+-+versiunea+consultativ%C4%83&filetype=pdf&url=%2Fmedia%2F4v0mpvi1%2Fghidul-solicitantului-dr-18-versiunea-consultativ%C4%83.pdf](https://www.afir.ro/api/file?filename=Ghidul+solicitantului+DR+18+-+versiunea+consultativ%C4%83&filetype=pdf&url=%2Fmedia%2F4v0mpvi1%2Fghidul-solicitantului-dr-18-versiunea-consultativ%C4%83.pdf) | — | program | /dr18 |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/313289](https://legislatie.just.ro/Public/DetaliiDocument/313289) | — | family, official_source, program, registry, schema | /e-drive |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/307361](https://legislatie.just.ro/Public/DetaliiDocument/307361) | — | program | /e-drive |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/313291](https://legislatie.just.ro/Public/DetaliiDocument/313291) | — | family, official_source, program, registry, schema | /e-mobility |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/301593](https://legislatie.just.ro/Public/DetaliiDocument/301593) | — | program | /e-mobility |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/313320](https://legislatie.just.ro/Public/DetaliiDocument/313320) | — | family, navigation, official_source, program, registry, schema | /e-move |
| blocked_external | — | [https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/comunicat-fm-consultare-publica-ghidul-solicitantului-promovarea-infrastructurii-pentru-o-mobilitate-cu-emisii-zero-in-sprijinul-intreprinderilor-si-comunitatilor-e-move-ro](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/comunicat-fm-consultare-publica-ghidul-solicitantului-promovarea-infrastructurii-pentru-o-mobilitate-cu-emisii-zero-in-sprijinul-intreprinderilor-si-comunitatilor-e-move-ro) | — | core, program | /e-move |
| blocked_external | — | [https://economie.gov.ro/pe-data-de-30-iulie-se-da-startul-inscrierilor-in-cadrul-programului-femeia-antreprenor/](https://economie.gov.ro/pe-data-de-30-iulie-se-da-startul-inscrierilor-in-cadrul-programului-femeia-antreprenor/) | — | core, navigation, program | /femeia-antreprenor-2026 |
| 200 | 200 | [https://minimis.imm.gov.ro/fa2024/ordine_evaluare](https://minimis.imm.gov.ro/fa2024/ordine_evaluare) | — | family, official_source, program, registry, schema | /femeia-antreprenor-2026 |
| 5xx | 503 | [https://energie.gov.ro/category/fondul-pentru-modernizare/](https://energie.gov.ro/category/fondul-pentru-modernizare/) | — | core, navigation, program | /fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/313464](https://legislatie.just.ro/Public/DetaliiDocument/313464) | — | family, official_source, program, registry, schema | /fondul-modernizare-pc1-stocare |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocument/294449](https://legislatie.just.ro/Public/DetaliiDocument/294449) | — | program | /fondul-modernizare-pc1-stocare |
| 200 | 200 | [https://regionordest.ro/apel-proiect/p1-investitii-pentru-modernizarea-microintreprinderilor-apel-2/](https://regionordest.ro/apel-proiect/p1-investitii-pentru-modernizarea-microintreprinderilor-apel-2/) | — | official_source, program, registry, schema | /fonduri-regionale |
| 200 | 206 | [https://adrnordest.ro/comentariiGhid/P1Microintreprinderi/Apel2/](https://adrnordest.ro/comentariiGhid/P1Microintreprinderi/Apel2/) | — | core, navigation, program | /investitii-modernizarea-microintreprinderilor-apel-2 |
| blocked_external | — | [https://pnrr.fonduri-ue.ro/ords/pnrr/r/dashboard-status-pnrr/home](https://pnrr.fonduri-ue.ro/ords/pnrr/r/dashboard-status-pnrr/home) | — | family, official_source, program, registry, schema | /pnrr |
| blocked_external | — | [https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) | — | family, guide, navigation, official_source, program, registry, schema | /pocidif-21 |
| blocked_external | — | [https://mfe.gov.ro/wp-content/uploads/2026/06/3b7daf66f17fdaad63fef93466d155e3-1.zip](https://mfe.gov.ro/wp-content/uploads/2026/06/3b7daf66f17fdaad63fef93466d155e3-1.zip) | — | guide, program | /pocidif-21 |
| blocked_external | — | [https://mfe.gov.ro/wp-content/uploads/2026/06/d6bee3673c763582ff4b4fce5be59861.pdf](https://mfe.gov.ro/wp-content/uploads/2026/06/d6bee3673c763582ff4b4fce5be59861.pdf) | — | guide, program | /pocidif-21 |
| blocked_external | — | [https://mfe.gov.ro/wp-content/uploads/2026/07/4b934c3ee5a4ddb2e0195e23d955c43b.docx](https://mfe.gov.ro/wp-content/uploads/2026/07/4b934c3ee5a4ddb2e0195e23d955c43b.docx) | — | guide, program | /pocidif-21 |
| 200 | 206 | [https://schema.org/IncentiveStatusActive](https://schema.org/IncentiveStatusActive) | — | schema | /pocidif-21 |
| blocked_external | — | [https://economie.gov.ro/participa-la-definitivarea-procedurii-de-implementare-a-programului-de-succes-start-up-nation-editia-2024/](https://economie.gov.ro/participa-la-definitivarea-procedurii-de-implementare-a-programului-de-succes-start-up-nation-editia-2024/) | — | core, guide, navigation, official_source, program, registry | /start-up-nation-2026 |
| 200 | 200 | [https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) | — | family, official_source, program, registry, schema | /start-up-nation-2026 |
| 200 | 200 | [https://www.afir.ro/](https://www.afir.ro/) | — | core, navigation | /surse-oficiale-fonduri-europene |
| blocked_external | — | [https://mfe.gov.ro/](https://mfe.gov.ro/) | — | core, guide, navigation, official_source, registry | /surse-oficiale-fonduri-europene |
| permanent_redirect | 200 | [https://adrnordest.ro/](https://adrnordest.ro/) | https://www.adrnordest.ro/ | core | /surse-oficiale-fonduri-europene |
| blocked_external | — | [https://mfe.gov.ro/pnrr/](https://mfe.gov.ro/pnrr/) | — | core | /surse-oficiale-fonduri-europene |
| blocked_external | — | [https://economie.gov.ro/](https://economie.gov.ro/) | — | core | /surse-oficiale-fonduri-europene |
| 200 | 200 | [https://legislatie.just.ro/](https://legislatie.just.ro/) | — | core | /surse-oficiale-fonduri-europene |
| blocked_external | — | [https://oportunitati-ue.gov.ro/](https://oportunitati-ue.gov.ro/) | — | core | /cat-costa-consultanta-fonduri-europene-ghid |
| 200 | 200 | [https://www.afir.ro/api/file?filename=Ghidul+Solicitantului+DR-14+VARIANTA+CONSULTATIV%C4%82&filetype=pdf&url=%2Fmedia%2Fbkmpo5fo%2Fgs-consultativ-dr-14.pdf](https://www.afir.ro/api/file?filename=Ghidul+Solicitantului+DR-14+VARIANTA+CONSULTATIV%C4%82&filetype=pdf&url=%2Fmedia%2Fbkmpo5fo%2Fgs-consultativ-dr-14.pdf) | — | core | /dr12-vs-dr14 |
| 200 | 200 | [https://ec.europa.eu/eurostat/web/agriculture/database/additional-data](https://ec.europa.eu/eurostat/web/agriculture/database/additional-data) | — | calculator, core | /dr12-vs-dr14 |
| 200 | 200 | [https://www.afir.ro/comunicare/utile/dezbatere-publica/](https://www.afir.ro/comunicare/utile/dezbatere-publica/) | — | calculator, core, official_source, registry | /dr12-vs-dr14 |
| 200 | 200 | [https://www.afir.ro/api/file?filename=Ghidul+Solicitantului+DR+12+-+versiunea+consultativ%C4%83&filetype=pdf&url=%2Fmedia%2Flm3fg4k1%2Fghidul-solicitantului-dr-12.pdf](https://www.afir.ro/api/file?filename=Ghidul+Solicitantului+DR+12+-+versiunea+consultativ%C4%83&filetype=pdf&url=%2Fmedia%2Flm3fg4k1%2Fghidul-solicitantului-dr-12.pdf) | — | core | /dr12-vs-dr14 |
| 200 | 200 | [https://www.afir.ro/api/file?url=%2Fmedia%2Fgk1nhmzi%2Fghidul-solicitantului-dr-14.pdf&filename=Ghidul%20Solicitantului%20DR%2014&filetype=pdf](https://www.afir.ro/api/file?url=%2Fmedia%2Fgk1nhmzi%2Fghidul-solicitantului-dr-14.pdf&filename=Ghidul%20Solicitantului%20DR%2014&filetype=pdf) | — | core | /dr12-vs-dr14 |
| blocked_external | — | [https://mfe.gov.ro/ghidul-specific-conditii-de-accesare-a-fondurilor-europene-aferente-planului-national-de-redresare-si-rezilienta-in-cadrul-apelului-de-proiecte-digitalizarea-imm-urilor-grant-de-pana-la-100-000-e/](https://mfe.gov.ro/ghidul-specific-conditii-de-accesare-a-fondurilor-europene-aferente-planului-national-de-redresare-si-rezilienta-in-cadrul-apelului-de-proiecte-digitalizarea-imm-urilor-grant-de-pana-la-100-000-e/) | — | core, navigation | /intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm |
| permanent_redirect | 206 | [https://commission.europa.eu/funding-tenders/find-funding/eu-funding-programmes_en](https://commission.europa.eu/funding-tenders/find-funding/eu-funding-programmes_en) | https://commission.europa.eu/funding-and-tenders/find-funding/eu-funding-programmes_en | core | /resurse-utile |
| blocked_external | — | [https://funding-tenders.ec.europa.eu/](https://funding-tenders.ec.europa.eu/) | — | core | /resurse-utile |
| blocked_external | — | [https://www.madr.ro/](https://www.madr.ro/) | — | core | /resurse-utile |
| 200 | 200 | [https://www.adrnordest.ro/](https://www.adrnordest.ro/) | — | core | /resurse-utile |
| 5xx | 503 | [https://energie.gov.ro/](https://energie.gov.ro/) | — | core | /resurse-utile |
| timeout | — | [https://eur-lex.europa.eu/eli/reg/2016/679/oj](https://eur-lex.europa.eu/eli/reg/2016/679/oj) | — | legal | /termeni-si-conditii |
| 200 | 200 | [https://www.dataprotection.ro/](https://www.dataprotection.ro/) | — | legal | /termeni-si-conditii |
| blocked_external | — | [https://anpc.ro/ce-este-sal](https://anpc.ro/ce-este-sal) | — | core, footer, homepage, legal | /termeni-si-conditii |
| blocked_external | — | [https://anpc.ro](https://anpc.ro) | — | core, footer, homepage | / |
| 200 | 200 | [https://regionordest.ro/](https://regionordest.ro/) | — | core, navigation | /consultanta-fonduri-europene |
| temporary_redirect | 206 | [https://www.afir.ro/api/file/document?filename=Lista+detaliata+a+Coeficientilor+standard+output+SOC+2020+nov+2024&filetype=pdf&url=%2Fmedia%2Fye3ppryg%2Flista-detaliata-a-coeficientilor-standard-output-soc-2020-nov-2024.pdf](https://www.afir.ro/api/file/document?filename=Lista+detaliata+a+Coeficientilor+standard+output+SOC+2020+nov+2024&filetype=pdf&url=%2Fmedia%2Fye3ppryg%2Flista-detaliata-a-coeficientilor-standard-output-soc-2020-nov-2024.pdf) | https://stportalafirprod.blob.core.windows.net/media/media/ye3ppryg/lista-detaliata-a-coeficientilor-standard-output-soc-2020-nov-2024.pdf | calculator | /calculator-soc |
| 200 | 200 | [https://www.afir.ro/info-la-zi/lista-detaliata-coeficienti-standard-output-soc-2020/](https://www.afir.ro/info-la-zi/lista-detaliata-coeficienti-standard-output-soc-2020/) | — | calculator, official_source, registry, schema | /calculator-soc |
| blocked_external | 403 | [https://so.afir.info/](https://so.afir.info/) | — | calculator | /calculator-soc |
| 200 | 200 | [https://ec.europa.eu/eurostat/statistics-explained/index.php?title=Glossary:Standard_output_(SO)](https://ec.europa.eu/eurostat/statistics-explained/index.php?title=Glossary:Standard_output_(SO)) | — | calculator | /calculator-soc |
| 200 | 200 | [https://www.adr.gov.ro/](https://www.adr.gov.ro/) | — | core | /digitalizare-imm-erp-crm-cloud |
| 200 | 200 | [https://www.adrnordest.ro/regiunea-nord-est/organizare-administrativ-teritoriala/](https://www.adrnordest.ro/regiunea-nord-est/organizare-administrativ-teritoriala/) | — | core | /fonduri-europene-nord-est |
| 200 | 200 | [https://www.dataprotection.ro](https://www.dataprotection.ro) | — | legal | /politica-de-confidentialitate |
| 200 | 200 | [https://legislatie.just.ro/Public/DetaliiDocumentAfis/185166](https://legislatie.just.ro/Public/DetaliiDocumentAfis/185166) | — | core | /proiectare-fonduri-europene |
| 200 | 200 | [https://regionordest.ro/apeluri-de-proiecte/](https://regionordest.ro/apeluri-de-proiecte/) | — | official_source, registry | config/seo-programs.json |
| 200 | 200 | [https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-18/](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-18/) | — | official_source, registry | config/program-source-registry.json |
| 200 | 200 | [https://www.afir.ro/finantare/finantare-in-agricultura/schema-de-energie/](https://www.afir.ro/finantare/finantare-in-agricultura/schema-de-energie/) | — | official_source, registry | config/program-source-registry.json |
| 200 | 200 | [https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/) | — | official_source, registry | config/program-source-registry.json |
| 200 | 200 | [https://www.afir.ro/comunicate/masuri-afir-pentru-atenuarea-efectelor-provocate-de-indisponibilitatea-sistemului-ancpi-completare/](https://www.afir.ro/comunicate/masuri-afir-pentru-atenuarea-efectelor-provocate-de-indisponibilitatea-sistemului-ancpi-completare/) | — | official_source, registry | config/program-source-registry.json |

## Blocate sau neverificabile automat

- [https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/) — blocked_external, fetch failed.
- [https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/comunicat-fm-consultare-publica-ghidul-solicitantului-promovarea-infrastructurii-pentru-o-mobilitate-cu-emisii-zero-in-sprijinul-intreprinderilor-si-comunitatilor-e-move-ro](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/comunicat-fm-consultare-publica-ghidul-solicitantului-promovarea-infrastructurii-pentru-o-mobilitate-cu-emisii-zero-in-sprijinul-intreprinderilor-si-comunitatilor-e-move-ro) — blocked_external, fetch failed.
- [https://economie.gov.ro/pe-data-de-30-iulie-se-da-startul-inscrierilor-in-cadrul-programului-femeia-antreprenor/](https://economie.gov.ro/pe-data-de-30-iulie-se-da-startul-inscrierilor-in-cadrul-programului-femeia-antreprenor/) — blocked_external, fetch failed.
- [https://pnrr.fonduri-ue.ro/ords/pnrr/r/dashboard-status-pnrr/home](https://pnrr.fonduri-ue.ro/ords/pnrr/r/dashboard-status-pnrr/home) — blocked_external, fetch failed.
- [https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) — blocked_external, fetch failed.
- [https://mfe.gov.ro/wp-content/uploads/2026/06/3b7daf66f17fdaad63fef93466d155e3-1.zip](https://mfe.gov.ro/wp-content/uploads/2026/06/3b7daf66f17fdaad63fef93466d155e3-1.zip) — blocked_external, fetch failed.
- [https://mfe.gov.ro/wp-content/uploads/2026/06/d6bee3673c763582ff4b4fce5be59861.pdf](https://mfe.gov.ro/wp-content/uploads/2026/06/d6bee3673c763582ff4b4fce5be59861.pdf) — blocked_external, fetch failed.
- [https://mfe.gov.ro/wp-content/uploads/2026/07/4b934c3ee5a4ddb2e0195e23d955c43b.docx](https://mfe.gov.ro/wp-content/uploads/2026/07/4b934c3ee5a4ddb2e0195e23d955c43b.docx) — blocked_external, fetch failed.
- [https://economie.gov.ro/participa-la-definitivarea-procedurii-de-implementare-a-programului-de-succes-start-up-nation-editia-2024/](https://economie.gov.ro/participa-la-definitivarea-procedurii-de-implementare-a-programului-de-succes-start-up-nation-editia-2024/) — blocked_external, fetch failed.
- [https://mfe.gov.ro/](https://mfe.gov.ro/) — blocked_external, fetch failed.
- [https://mfe.gov.ro/pnrr/](https://mfe.gov.ro/pnrr/) — blocked_external, fetch failed.
- [https://economie.gov.ro/](https://economie.gov.ro/) — blocked_external, fetch failed.
- [https://oportunitati-ue.gov.ro/](https://oportunitati-ue.gov.ro/) — blocked_external, fetch failed.
- [https://mfe.gov.ro/ghidul-specific-conditii-de-accesare-a-fondurilor-europene-aferente-planului-national-de-redresare-si-rezilienta-in-cadrul-apelului-de-proiecte-digitalizarea-imm-urilor-grant-de-pana-la-100-000-e/](https://mfe.gov.ro/ghidul-specific-conditii-de-accesare-a-fondurilor-europene-aferente-planului-national-de-redresare-si-rezilienta-in-cadrul-apelului-de-proiecte-digitalizarea-imm-urilor-grant-de-pana-la-100-000-e/) — blocked_external, fetch failed.
- [https://funding-tenders.ec.europa.eu/](https://funding-tenders.ec.europa.eu/) — blocked_external, fetch failed.
- [https://www.madr.ro/](https://www.madr.ro/) — blocked_external, fetch failed.
- [https://eur-lex.europa.eu/eli/reg/2016/679/oj](https://eur-lex.europa.eu/eli/reg/2016/679/oj) — timeout, This operation was aborted.
- [https://anpc.ro/ce-este-sal](https://anpc.ro/ce-este-sal) — blocked_external, fetch failed.
- [https://anpc.ro](https://anpc.ro) — blocked_external, fetch failed.
- [https://so.afir.info/](https://so.afir.info/) — blocked_external, HTTP 403.

## Reproducere

- `npm run check:links` — verificare deterministă pentru CI/build: canonicale, redirecturi, fragmente, mailto/tel/WhatsApp, documente și descrieri.
- `npm run audit:links` — repetă verificarea și probează rețeaua externă, apoi rescrie acest raport.
- Statusurile externe sunt un snapshot și trebuie interpretate împreună cu data raportului; `blocked_external` nu este echivalent cu 404.
