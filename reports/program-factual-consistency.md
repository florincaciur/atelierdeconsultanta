# Audit de consistență factuală a programelor

Data auditului: 2026-07-20

## Rezultat

- Programe în registrul canonic: 17
- Erori: 0
- Avertismente: 0
- Statusuri: consultation=4, final=5, open=1, unknown=7
- Mod strict pentru freshness: inactiv

Auditul este local și determinist. Nu interoghează URL-urile oficiale, nu deduce statusul din răspunsuri HTTP și nu rescrie date factuale. Registrul aprobat din `config/seo-programs.json` rămâne singura sursă de adevăr.

## Freshness și status

| Program | Status | Verificat | Început | Sfârșit |
|---|---|---:|---:|---:|
| Programul Regional Nord-Est | final | 2026-07-20 | — | — |
| Fonduri regionale | unknown | 2026-07-20 | — | — |
| DR12 AFIR | consultation | 2026-07-20 | — | — |
| DR14 AFIR | consultation | 2026-07-20 | — | — |
| Start-Up Nation | unknown | 2026-05-20 | — | — |
| Femeia Antreprenor | unknown | 2026-05-20 | — | — |
| Digitalizare IMM | unknown | 2026-05-20 | — | — |
| Modernizarea microîntreprinderilor – Apel 2 | consultation | 2026-06-02 | — | — |
| Fondul pentru Modernizare – autoconsum | unknown | 2026-05-20 | — | — |
| Fondul pentru Modernizare – energie regenerabilă | unknown | 2026-05-20 | — | — |
| AFIR Autoconsum Agroalimentar | open | 2026-07-20 | 2026-06-15 | 2026-08-14 |
| Autoconsum instituții publice | final | 2026-05-20 | — | — |
| PRO INFRA | final | 2026-07-13 | — | — |
| Apeluri GAL | unknown | 2026-05-26 | — | — |
| GAL-AFIR / LEADER | final | 2026-05-26 | — | — |
| e-MOVE RO | consultation | 2026-05-27 | — | — |
| PoCIDIF 2.1 | final | 2026-07-13 | — | — |

## Verificări efectuate

- identitate, sursă, status, reviewedAt, sume și procente între config, official-guides, bannere, navbar, pagină și JSON-LD;
- title/meta și descriere banner raportate la registru;
- paritatea desktop/mobil și interdicția valorilor consultative în navbar;
- existența perioadei pentru `sourceStatus=open`;
- freshness de maximum 30 de zile pentru `announced` și `open`;
- afirmații de tip „apel deschis” și valori financiare nesusținute în conținutul paginii;
- prezența fiecărei rute în `llms.txt`.

## Constatări

| Severitate | Rută | Categorie | Suprafață | Detaliu |
|---|---|---|---|---|
| — | — | — | — | Nu au fost identificate inconsistențe. |

## Workflow recomandat

1. Datele factuale se actualizează manual numai în `config/seo-programs.json#programs`, după verificarea documentului oficial.
2. Se rulează `npm run sync:program-facts` pentru consumatori.
3. Se rulează `npm run audit:program-facts`; în CI se poate folosi `node tools/audit-program-factual-consistency.js --strict-freshness`.
4. Un URL indisponibil generează un caz de verificare separat; nu schimbă automat statusul și nu rescrie pagina.
