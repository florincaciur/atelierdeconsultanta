# P1.09 — Raport QA pentru layout-ul paginilor lungi

Data: 21 iulie 2026
Pilot: `/afir-autoconsum-agroalimentar`

## Acoperire

- 27 pagini eligibile: homepage, 9 programe și 17 ghiduri.
- 419 ancore stabile generate și verificate.
- 67 de tabele în regiuni responsive/focusabile.
- 9 acțiuni de program mutate imediat după rezumatul decizional.
- Conținutul editorial a fost păstrat integral conform contractului automat.

## Măsurători înainte / după — pilot desktop 1366×768

| Măsură | Înainte | După | Diferență |
| --- | ---: | ---: | ---: |
| Înălțime pagină | 12.588 px | 12.457 px | −1,0% |
| Înălțime `main` | 11.543 px | 11.412 px | −1,1% |
| Poziția primei acțiuni decizionale | 11.151 px | 2.351 px | −78,9% |
| Lățime maximă paragraf | 983 px | 699 px | −28,9%; maximum 68ch |
| Copii direcți în `main` | 4 | 5 | +1 cuprins semantic |
| Detalii secundare compactate | 0 | 12 | conținutul rămâne în HTML |

Reducerea de înălțime este obținută în ciuda coloanei de lectură mai înguste, prin compactarea exclusivă a informațiilor secundare.

## Verificări browser

| Criteriu | Rezultat | Dovadă |
| --- | --- | --- |
| Cuprins desktop sticky | PASS | top 108 px după 4.850 px scroll |
| Ancoră neacoperită | PASS | titlul țintă la 128 px sub viewport/header |
| Stare secțiune | PASS | exact un link cu `aria-current="location"` |
| Homepage sticky | PASS | top 72 px; titlul țintă la 136 px; hash păstrat |
| Disclosure mobil | PASS | închis inițial; 54 px înălțime control |
| Enter / Spațiu | PASS | `false → true → false`, focus rămas pe `SUMMARY` |
| 320 px | PASS | fără overflow al documentului; `main` trece la block |
| Tabel la 320 px | PASS | overflow numai în regiunea tabelului |
| CTA mobil | PASS | 50 px înălțime |
| Reduced motion / fără JS | PASS structural | ancore native, `<details open>` în HTML, fără text injectat prin JS |

## Teste automate

- `npm run sync:long-form-layout` — PASS: 27 pagini, 419 ancore.
- `npm run test:long-form-layout` — PASS: idempotență, păstrarea conținutului și contracte responsive/accessibility.
- `npm run build` — PASS: întregul pipeline P0/P1, 91 URL-uri canonice și 184 fișiere Cloudflare generate.
- Contractul verifică pragul, idempotența, ancorele, ID-urile unice, 68ch, tabelele, disclosure-ul, analytics și păstrarea numărului de cuvinte.

## Capturi

- `reports/p1-09-before-program-desktop.png`
- `reports/p1-09-after-program-desktop.png`
- `reports/p1-09-after-program-toc-desktop.png`
- `reports/p1-09-after-program-mobile.png`
- `reports/p1-09-after-homepage-toc-desktop.png`
