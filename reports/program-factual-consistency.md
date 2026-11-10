# Audit de consistență factuală a programelor

Data auditului: 2026-11-10

## Rezultat

- Programe în registrul canonic: 28
- Erori: 0
- Avertismente: 0
- Statusuri: apel_deschis=8, apel_inchis=8, calendar_estimativ=7, consultare_publica=1, ghid_aprobat_nedeschis=4
- Mod strict pentru freshness: inactiv

Auditul este local și determinist. Nu interoghează URL-urile oficiale, nu deduce statusul din răspunsuri HTTP și nu rescrie date factuale. Registrul aprobat din `config/seo-programs.json#programs` rămâne singura sursă de adevăr.

## Freshness și status

| Program | Status | Verificat | Început | Sfârșit |
|---|---|---:|---:|---:|
| Programul Regional Nord-Est | calendar_estimativ | 2026-11-03 | — | — |
| Fonduri regionale | calendar_estimativ | 2026-11-03 | — | — |
| DR12 AFIR | apel_deschis | 2026-11-04 | 2026-10-06 | 2026-12-02 |
| DR14 AFIR | apel_deschis | 2026-11-04 | 2026-09-01 | 2026-11-16 |
| DR18 AFIR | apel_deschis | 2026-11-04 | 2026-09-01 | 2026-11-16 |
| Start-Up Nation | apel_inchis | 2026-11-03 | — | 2026-05-29 |
| Femeia Antreprenor | apel_inchis | 2026-11-03 | — | — |
| Digitalizare IMM | apel_inchis | 2026-11-04 | — | — |
| Modernizarea microîntreprinderilor – Apel 2 | apel_inchis | 2026-11-04 | 2026-09-28 | 2026-10-28 |
| Fondul pentru Modernizare – autoconsum | apel_inchis | 2026-11-03 | — | — |
| Fondul pentru Modernizare – energie regenerabilă | apel_inchis | 2026-11-03 | — | — |
| AFIR Autoconsum Agroalimentar | apel_inchis | 2026-11-04 | 2026-06-15 | 2026-08-14 |
| PC1 – Autoconsum entități publice | apel_deschis | 2026-11-04 | 2026-09-28 | 2026-11-20 |
| PC1 – Stocare entități publice | apel_deschis | 2026-11-04 | 2026-09-28 | 2026-11-20 |
| PRO INFRA | ghid_aprobat_nedeschis | 2026-11-04 | — | — |
| Apeluri GAL | calendar_estimativ | 2026-11-03 | — | — |
| GAL-AFIR / LEADER | calendar_estimativ | 2026-11-03 | — | — |
| e-MOVE RO | ghid_aprobat_nedeschis | 2026-11-04 | — | — |
| PoCIDIF 2.1 | apel_inchis | 2026-11-04 | 2026-06-30 | 2026-10-30 |
| PNRR | calendar_estimativ | 2026-11-03 | — | — |
| Diaspora Investește Acasă | ghid_aprobat_nedeschis | 2026-11-04 | — | — |
| e-DRIVE | consultare_publica | 2026-11-09 | — | — |
| e-Mobility RO | apel_deschis | 2026-11-04 | 2026-09-28 | 2026-11-27 |
| PC1 Stocare stand-alone | apel_deschis | 2026-11-04 | 2026-09-01 | 2026-11-15 |
| Programul Tranziție Justă | calendar_estimativ | 2026-11-03 | — | — |
| Fondul pentru Modernizare | calendar_estimativ | 2026-11-03 | — | — |
| Digitalizare IMM Regiunea Centru – Apel 2 | ghid_aprobat_nedeschis | 2026-11-10 | 2026-12-02 | 2027-02-02 |
| SME Eco-Tech | apel_deschis | 2026-11-09 | 2026-05-26 | 2026-12-30 |

## Verificări efectuate

- identitate, sursă, `status`, `statusLabel`, `verifiedAt`, grant și cofinanțare între registru, meniu, homepage, carduri, pagină și JSON-LD;
- paritatea desktop/mobil și interdicția valorilor locale în navbar;
- existența perioadei pentru `status=apel_deschis`;
- freshness de maximum 30 de zile pentru `apel_deschis`;
- afirmații de tip „apel deschis” și valori financiare nesusținute în conținutul paginii;
- excluderea înregistrărilor `pending_validation` din suprafețele publice.

## Constatări

| Severitate | Rută | Categorie | Suprafață | Detaliu |
|---|---|---|---|---|
| — | — | — | — | Nu au fost identificate inconsistențe. |

## Workflow recomandat

1. Datele factuale se actualizează manual numai în `config/seo-programs.json#programs`, după verificarea documentului oficial.
2. Se rulează `npm run validate:program-registry` și `npm run sync:program-facts`.
3. Se rulează `npm run test:program-registry` și `npm run audit:program-facts`.
4. Un URL indisponibil generează un caz de verificare separat; nu schimbă automat statusul și nu rescrie pagina.
