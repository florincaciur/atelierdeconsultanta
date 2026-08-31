# Design imersiv FABER — 31 august 2026

Implementare pe ramura `codex/immersive-faber`. Site-ul public nu a fost modificat prin acest task.

## Ce se schimbă

- Pagina principală: paletă crem / grafit / teracotă, tipografie amplă și o compoziție volumetrică originală, realizată în CSS.
- Obiectul reacționează la mișcarea cursorului și la scroll. Cele cinci straturi se reunesc pe parcursul metodei FABER.
- Pe desktop (minimum 1000 × 700 px), secțiunea metodei rămâne în ecran și trece prin cele cinci verificări în funcție de poziția scroll-ului, în ambele sensuri. Nu se interceptează rotița, touch-ul sau tastele de scroll.
- Selector pentru afaceri, agricultură, energie și digitalizare, cu legături către paginile existente. Alegerea este o navigare după domeniu, nu un verdict de eligibilitate.
- Indicator de progres, navigare între secțiuni și apariții discrete ale conținutului.
- Pe telefon și tabletă se păstrează scroll-ul obișnuit, butoanele, glisarea și navigarea cu tastatura.
- Buton pentru oprirea animațiilor, preferință păstrată local și respectarea `prefers-reduced-motion`. Fără JavaScript, conținutul și legăturile principale rămân disponibile.

Registrul programelor, cele 23 de bannere, sursele oficiale, datele de verificare, contactul, calculatoarele și URL-urile existente sunt păstrate. Detaliile ample din hero se deschid explicit. Nu s-au copiat imagini sau cod din proiectul Evora; acesta a fost reper pentru mișcare și compoziție.

## Previzualizare locală

Din rădăcina proiectului:

```powershell
node tools/preview-immersive.cjs
```

Deschide `http://127.0.0.1:4173/`. Pentru artefactul construit: `node tools/preview-immersive.cjs --dist` (oprește întâi celălalt server pe același port).

## Backup înainte de modificare

Directorul de backup este **în afara site-ului**, astfel încât arhivele nu sunt publicate accidental:

`C:\Users\flori\Documents\Claude\Projects\atelierdeconsultanta-backups\2026-08-31-before-immersive`

| Fișier | Conținut |
|---|---|
| `published-source-before-immersive.zip` | Toate fișierele versionate din versiunea actualizată, înainte de design |
| `published-repository-before-immersive.bundle` | Repository Git cu istoric complet și etichetă de restaurare; verificat cu `git bundle verify` |
| `live-index.html` | Copia HTML preluată direct de la site-ul public |
| `source-before-immersive.zip` | Copia proiectului local inițial, mai vechi decât site-ul live |
| `repository-before-immersive.bundle` | Istoricul proiectului local inițial |
| `SHA256SUMS.txt` | Sume de control pentru arhive și copia HTML |

Punctul de restaurare al versiunii actualizate este:

```text
tag:    backup/pre-immersive-2026-08-31
commit: baac7b9e16eaaeac99f580a47b73f5c2b91b3cc8
```

Titlurile, programele și linkurile din homepage-ul acestui punct au fost comparate cu copia live și corespund. Fișierul HTML descărcat nu reprezintă singur întregul site; arhiva sursă și bundle-ul sunt backup-urile pentru restaurare.

## Revenire, fără a șterge noul design

Pentru a pregăti vechiul site într-un director separat, din proiectul curent:

```powershell
git worktree add --detach ../atelierdeconsultanta-restore backup/pre-immersive-2026-08-31
Set-Location ../atelierdeconsultanta-restore
npm ci
npm run build
npm run validate:cloudflare
```

Alege un director nou dacă `atelierdeconsultanta-restore` există deja. Aceste comenzi nu modifică site-ul live și nu șterg noul design. Publicarea se face separat, prin fluxul obișnuit și verificările proiectului.

Dacă repository-ul original nu mai este disponibil, bundle-ul este autonom:

```powershell
git clone --branch backup/pre-immersive-2026-08-31 "C:\Users\flori\Documents\Claude\Projects\atelierdeconsultanta-backups\2026-08-31-before-immersive\published-repository-before-immersive.bundle" "C:\Users\flori\Documents\Claude\Projects\atelierdeconsultanta-restored"
```

Restaurarea completă readuce și conținutul la acest moment. Dacă programele sunt actualizate ulterior, separă revenirea de design de actualizările de conținut înainte de publicare.

## Întreținere

- `assets/immersive-home.css`: prezentarea, componentele volumetrice și breakpoint-urile.
- `assets/immersive-home.js`: scroll, selector, navigare și preferința de mișcare.
- `tools/immersive-home-template.js`: markup-ul prezentării.
- Generatorii existenți `sync-homepage-hero.js` și `sync-homepage-decision-flow.js` includ noua prezentare. Rebuild-ul nu o elimină.
- `tests/homepage-decision-flow-responsive.mjs`: verificări la 320, 390, 768 și 1366 px, scroll înainte/înapoi, controale manuale, mișcare redusă, preferință persistentă și fallback fără JavaScript.

Testele și observațiile finale sunt în `reports/immersive-design/verification.md`. Nu există dependințe frontend noi, modele 3D externe sau video obligatoriu pentru afișarea paginii.

## Starea publicării

Implementarea nu a fost trimisă în producție. Verificarea suplimentară a publicării a trecut 21 de controale, fără erori critice, dar a păstrat două rezultate FAIL pentru aceeași lipsă preexistentă: valoarea INP de referință aprobată. Nu au fost schimbate configurațiile de aprobare. Înainte de deploy sunt necesare acceptarea designului și rezolvarea cerinței de performanță conform regulii P0 existente; vezi [raportul complet](../reports/immersive-design/publication-preflight.md).
