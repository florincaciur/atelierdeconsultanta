# P1.06 — Hero homepage compact și orientat spre decizie

Data QA: 21 iulie 2026
Mediu: server local static, sursele curente din workspace

## Rezultat

**PASS** pentru layout, copy, sursa datelor, CTA-uri, responsive și instrumentare. Hero-ul păstrează identitatea bleumarin–portocaliu, are două acțiuni și exact trei informații în panoul secundar.

## Copy final

- H1: „Consultanță și proiectare pentru investiții finanțate”
- Text: „Verificăm solicitantul, programul, punctajul, bugetul și documentele înainte de a începe dosarul. Concluzia poate fi: continuăm, ajustăm sau nu depunem acum.”
- CTA principal: „Începe verificarea proiectului” → `/contact`
- CTA secundar: „Vezi cum lucrăm” → `/metodologie-verificare-eligibilitate`
- Microcopy: „Prima etapă este o verificare orientativă. Nu promitem aprobarea.”

Copy-ul din brief a fost păstrat fără ajustări editoriale.

## Panoul secundar

1. Poziționarea aprobată „Verificare prudentă, documentată și interdisciplinară — consultanță și proiectare — înainte de dosar” și metoda în cinci pași: solicitant → program → punctaj → buget și documente → decizie.
2. Program verificat recent: calculat automat dintre programele publice cu sursă oficială completă. La QA: AFIR Autoconsum Agroalimentar, verificat la 20 iulie 2026.
3. Indicator de actualizare: data maximă `verifiedAt` din registrul public și link către hub-ul programelor.

Statusul, data, instituția și URL-ul oficial nu sunt valori editoriale locale; sunt generate din `config/seo-programs.json`.

## Comparație geometrică

| Viewport | Indicator | Înainte | După | Rezultat |
|---|---|---:|---:|---|
| 1366×768 | Înălțime hero | 1.048 px | 506 px | −542 px (−51,7%) |
| 1366×768 | CTA principal integral în fold | Nu; bottom 905 px | Da; bottom 496 px | PASS |
| 1366×768 | CTA secundar integral în fold | Nu; bottom 905 px | Da; bottom 496 px | PASS |
| 1366×768 | H1 | — | 54,656 px / line-height 57,935 px | PASS 52–56 px |
| 390×844 | Înălțime hero | 1.739 px | 980 px | −759 px (−43,6%) |
| 390×844 | CTA principal integral în fold | Da; bottom 678 px | Da; bottom 492 px | +186 px spațiu |
| 390×844 | CTA secundar integral în fold | Da; bottom 740 px | Da; bottom 552 px | +188 px spațiu |
| 390×844 | H1 | 27,52 px | 37,088 px / line-height 40,055 px | PASS 36–42 px |
| ambele | Overflow orizontal | — | Nu | PASS |

## Core Web Vitals și proxy-uri sintetice

| Măsurare Lighthouse locală | Scor | LCP | CLS | TBT |
|---|---:|---:|---:|---:|
| Baseline desktop istoric, 11 iunie 2026, Lighthouse 13.4.0 | 100 | 483 ms | 0,0429 | 0 ms |
| După, desktop, 21 iulie 2026, Lighthouse 13.4.1 | 100 | 569 ms | 0 | 0 ms |
| După, mobil simulat, 21 iulie 2026, Lighthouse 13.4.1 | 90 | 2.784 ms | 0 | 133 ms |

Desktop-ul păstrează scorul 100 și TBT 0; variația LCP de +86 ms nu este o regresie majoră, iar CLS scade la 0. Pentru mobil nu există un baseline identic anterior modificării, deci raportul nu pretinde o comparație falsă. INP este metrică de teren și trebuie urmărită în RUM/CrUX după publicare; TBT este raportat doar ca proxy sintetic, nu ca înlocuitor INP.

Stilul critic al hero-ului este inclus inline din fișierul-sursă pentru a evita o cerere CSS suplimentară care blochează LCP.

## Analytics și accesibilitate

- Ambele CTA-uri au `cta_click`, `data-analytics-cta-view="true"` și varianta `p1_06`.
- Implementarea globală emite `cta_view` o singură dată la minimum 50% vizibilitate; contractul analytics existent rămâne PASS.
- Focus vizibil, target de minimum 48 px și contrastul bleumarin–portocaliu sunt păstrate.
- `prefers-reduced-motion` elimină transformările CTA.
- Elementele decorative și controalele caruselului din hero au fost eliminate; fundalul nu introduce elemente care par interactive.

## Capturi

- `reports/p1-06-homepage-hero-before-desktop.png`
- `reports/p1-06-homepage-hero-after-desktop.png`
- `reports/p1-06-homepage-hero-before-mobile.png`
- `reports/p1-06-homepage-hero-after-mobile.png`

Rapoarte Lighthouse: `reports/p1-06-lighthouse-after-desktop.json` și `reports/p1-06-lighthouse-after-mobile.json`.
