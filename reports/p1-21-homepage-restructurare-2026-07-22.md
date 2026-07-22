# P1.21 — raport homepage decizional

Măsurare: 22 iulie 2026. Baseline-ul a fost măsurat pe producție înaintea intervenției; rezultatul a fost măsurat pe build-ul local cu Chromium headless. Valorile de laborator nu înlocuiesc datele de teren din CrUX/GSC.

| Indicator | Înainte desktop 1366×768 | După desktop 1366×768 | Înainte mobil 390×844 | După mobil 390×844 |
|---|---:|---:|---:|---:|
| Înălțime document | 11.458 px | 8.736 px | 11.772 px | 9.285 px |
| Linkuri în `<main>` | 65 | 33 | 65 | 33 |
| Formulare în `<main>` | 2 | 0 | 2 | 0 |
| Secțiuni de prim nivel | 11 | 8 | 11 | 8 |
| Componente tip carusel | 3 | 1 | 3 | 1 |
| CTA principal în primul ecran | da, 686 px | da, 687 px | da, 703 px | da, 680 px |
| Overflow orizontal | — | 0 | 0 | 0 |

Reducerea de înălțime este de aproximativ 23,8% pe desktop și 21,1% pe mobil. Numărul de linkuri din conținut a scăzut cu 49,2%, fără ascunderea secțiunilor eliminate.

## Core Web Vitals

- Baseline producție din `config/p0-release-gate.json`: LCP 483,279 ms, CLS 0,04291, INP `DE_VALIDAT_UMAN`.
- Build local după restructurare: LCP 160 ms desktop / 132 ms mobil și CLS 0 în ambele viewporturi.
- INP nu este declarat dintr-un click sintetic. Interacțiunea caruselului a fost verificată funcțional; validarea INP reală rămâne în monitorizarea de teren după publicare.

## Inventar keep / move / remove

| Decizie | Conținut | Motiv |
|---|---|---|
| Keep | hero compact, copy aprobat, SVG cu cinci etape, două CTA-uri contextuale | decizia și acțiunea apar înainte de fold |
| Keep | cuprins `details/summary`, închis implicit | navigare accesibilă fără panou permanent supradimensionat |
| Keep | un carusel cu șase programe și cinci legături spre huburi | selecție editorială + acces la taxonomie |
| Rewrite | metoda, servicii, instrumente, dovezi, analiză, CTA final | fiecare secțiune are un singur scop și maximum o acțiune principală |
| Move | gridul complet și listele lungi de programe | aparțin huburilor de familie și paginii „Toate programele” |
| Remove | al doilea carusel, caruselul de blog și secțiunile repetitive | reduce deciziile concurente și controalele redundante |
| Remove | newsletter și formularul lung de contact din homepage | un singur tip de intrare în conversie: CTA spre formularul scurt Contact |
| Remove | testimonialele/dovezile neverificabile | nu publicăm dovezi fără document și aprobare |

Testele automate verifică 320, 390, 768 și 1366 px, lipsa overflow-ului, CTA-ul înainte de fold la 390/1366 px, cuprinsul închis, caruselul funcțional, zero formulare și zero erori în consolă.
