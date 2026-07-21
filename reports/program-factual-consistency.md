# Audit de consistență factuală a programelor

Data auditului: 2026-07-21

## Rezultat

- Programe în registrul canonic: 20
- Erori: 0
- Avertismente: 0
- Statusuri: apel_deschis=1, apel_inchis=1, calendar_estimativ=9, consultare_publica=4, ghid_aprobat_nedeschis=5
- Mod strict pentru freshness: inactiv

Auditul este local și determinist. Nu interoghează URL-urile oficiale, nu deduce statusul din răspunsuri HTTP și nu rescrie date factuale. Registrul aprobat din `config/seo-programs.json#programs` rămâne singura sursă de adevăr.

## Freshness și status

| Program | Status | Verificat | Început | Sfârșit |
|---|---|---:|---:|---:|
| Programul Regional Nord-Est | ghid_aprobat_nedeschis | 2026-07-20 | — | — |
| Fonduri regionale | calendar_estimativ | 2026-07-20 | — | — |
| DR12 AFIR | consultare_publica | DE_VALIDAT_UMAN | — | — |
| DR14 AFIR | consultare_publica | DE_VALIDAT_UMAN | — | — |
| Start-Up Nation | calendar_estimativ | 2026-05-20 | — | — |
| Femeia Antreprenor | calendar_estimativ | 2026-05-20 | — | — |
| Digitalizare IMM | apel_inchis | DE_VALIDAT_UMAN | — | — |
| Modernizarea microîntreprinderilor – Apel 2 | consultare_publica | 2026-06-02 | — | — |
| Fondul pentru Modernizare – autoconsum | calendar_estimativ | 2026-05-20 | — | — |
| Fondul pentru Modernizare – energie regenerabilă | calendar_estimativ | 2026-05-20 | — | — |
| AFIR Autoconsum Agroalimentar | apel_deschis | 2026-07-20 | 2026-06-15 | 2026-08-14 |
| Autoconsum instituții publice | ghid_aprobat_nedeschis | 2026-05-20 | — | — |
| PRO INFRA | ghid_aprobat_nedeschis | DE_VALIDAT_UMAN | — | — |
| Apeluri GAL | calendar_estimativ | 2026-05-26 | — | — |
| GAL-AFIR / LEADER | ghid_aprobat_nedeschis | 2026-05-26 | — | — |
| e-MOVE RO | consultare_publica | 2026-05-27 | — | — |
| PoCIDIF 2.1 | ghid_aprobat_nedeschis | 2026-07-13 | — | — |
| PNRR | calendar_estimativ | DE_VALIDAT_UMAN | — | — |
| Programul Tranziție Justă | calendar_estimativ | DE_VALIDAT_UMAN | — | — |
| Fondul pentru Modernizare | calendar_estimativ | DE_VALIDAT_UMAN | — | — |

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
