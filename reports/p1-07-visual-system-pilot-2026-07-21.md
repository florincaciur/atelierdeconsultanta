# P1.07 — QA sistem vizual pilot

Data: 21 iulie 2026

Scope: homepage, Contact, AFIR Autoconsum Agroalimentar
Rezultat: **PASS**

## Înainte / după

| Rută | Body înainte | Body după | H1 desktop înainte | H1 desktop după | Overflow 1366 / 390 / 320 |
|---|---:|---:|---:|---:|---|
| `/` | 16px / 1.60 | 17px / 1.65 | 54.66px | 54.66px | nu / nu / nu |
| `/contact` | 16px / 1.70 | 17px / 1.65 | 49.60px | 56px | nu / nu / nu |
| `/afir-autoconsum-agroalimentar` | 16px / 1.70 | 17px / 1.65 | 49.60px | 56px | nu / nu / nu |

H1 la 390px: homepage 37.09px, Contact și pagina de program 39.04px. Toate valorile sunt în intervalele responsive definite de contract.

## Verificări

- 13/13 perechi de contrast trec pragul configurat; cel mai mic raport pentru text normal este accent/off-white la 4.80:1.
- Textul normal folosește 17px și line-height 1.65; măsura documentată este maximum 68ch.
- Focusul folosește outline de 3px fără modificare de layout: albastru pe light, galben pe dark.
- Statusurile au simbol, text și culoare: `●`, `◐`, `○`; eticheta continuă să vină din registrul programelor.
- La 390px, niciun control relevant nu este sub 24×24px; checkbox-ul este 24×24px, iar controalele primare sunt minimum 44px înălțime.
- Nu există overflow orizontal la 1366, 390 sau 320px pe cele trei rute.
- Regula `prefers-reduced-motion: reduce` este încărcată și detectabilă în browser.
- Sticky CTA este acoperit de contract și documentație, dar nu a fost injectat deoarece componenta nu exista în pilot.

## Capturi

### Înainte

- `reports/p1-07-before-home-desktop.png`
- `reports/p1-07-before-contact-desktop.png`
- `reports/p1-07-before-program-desktop.png`

### După

- `reports/p1-07-after-home-desktop.png`
- `reports/p1-07-after-home-mobile.png`
- `reports/p1-07-after-contact-desktop.png`
- `reports/p1-07-after-contact-mobile.png`
- `reports/p1-07-after-program-desktop.png`
- `reports/p1-07-after-program-mobile.png`

Capturile „după” folosesc viewport-ul (1366×768 și 390×844), nu captură full-page, pentru a evita repetarea headerului sticky în compozitorul browserului.
