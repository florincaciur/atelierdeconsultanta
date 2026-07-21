# P1.08 — QA carusel și grid programe

Data verificării: 21 iulie 2026
Mediu: build local servit la `http://127.0.0.1:4173/`

## Rezultat

PASS pentru implementarea și testele automate ale noului explorer de programe de pe homepage.

- Un singur carusel, cu 6 programe selectate explicit în configurația editorială.
- Fără auto-rotire; poziția a rămas neschimbată după așteptare.
- Controale cu nume accesibile „Programul anterior” și „Programul următor”.
- Contor accesibil `1 din 6`, actualizat la navigare.
- Slide-urile ascunse au `inert`, `aria-hidden="true"` și zero elemente focusabile.
- Navigarea cu săgeți, Home/End, butoane și swipe touch funcționează fără mutarea necerută a focusului.
- Al doilea carusel a fost înlocuit cu un grid de 12 programe publicabile și listabile.
- Filtrele familie/status/beneficiar sunt locale paginii, nu modifică URL-ul și anunță rezultatul în `aria-live="polite"`.
- Cardurile conțin un singur link, „Vezi condițiile”; CTA-ul comercial global nu este repetat.

## Verificări de interacțiune

| Criteriu | Rezultat | Dovadă |
| --- | --- | --- |
| Un singur carusel | PASS | 1 container, 6 slide-uri |
| Fără auto-rotire | PASS | contor neschimbat după 1,3 s |
| Tastatură | PASS | ArrowLeft/ArrowRight/Home/End și butoanele schimbă slide-ul |
| Focus | PASS | focusul rămâne pe controlul folosit; 0 linkuri focusabile în slide-urile ascunse |
| Touch | PASS | swipe la 390 px: `1 din 6` → `2 din 6` |
| Filtru familie | PASS | Energie: 4 rezultate, toate cu familia selectată |
| Filtru status | PASS | Apel deschis: 1 rezultat, cu statusul selectat |
| Reset filtre | PASS | revenire la 12 rezultate și toate valorile `all` |
| URL stabil | PASS | filtrele nu schimbă calea, query-ul sau hash-ul |
| Structură screen reader | PASS semantic | numele controalelor, caruselului, filtrelor, contorului și rezultatului sunt prezente în arborele semantic |

Verificarea screen reader este una semantică în browser; nu pretinde o sesiune separată NVDA/VoiceOver.

## Reflow și dimensiuni

| Context | Rezultat |
| --- | --- |
| 320 px | fără overflow orizontal; grid cu o coloană; 25/25 controale relevante au minimum 44×44 CSS px |
| 390×844 px | carusel și grid utilizabile cu touch; o coloană |
| Echivalent CSS pentru zoom 200% la 1366 px (viewport 683 px) | fără overflow; carusel 620 px; grid cu două coloane de 300 px |
| 1366×768 px | carusel controlabil și grid cu trei coloane |

## Analytics

- `carousel_interaction`: emis numai la interacțiuni explicite cu butoane, tastatură sau touch.
- `program_card_click`: emis declarativ numai la clickul pe linkul programului.
- Parametrii folosesc identificatori de componentă/program; nu se transmit valori introduse de utilizator sau alte date personale.

## Teste automate

- `npm run build` — PASS, inclusiv auditul tehnic SEO cu 0 probleme și release gate-ul P0.
- `npm run test:homepage-programs`
- `npm run verify:analytics`
- `npm run test:program-registry`
- `npm run test:program-statuses`
- `npm run audit:program-facts`
- `npm run test:design-system`

## Capturi

- `reports/p1-08-priority-carousel-desktop.png`
- `reports/p1-08-program-grid-desktop.png`
- `reports/p1-08-priority-carousel-mobile.png`
- `reports/p1-08-program-grid-mobile.png`
