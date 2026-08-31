# Design imersiv FABER — 31 august 2026

Implementare pe ramura `codex/immersive-faber`. Site-ul public nu a fost modificat prin acest task.

## Ce se schimbă

- Pagina principală folosește paleta comună a site-ului: bleumarin `#0d1f3c`, portocaliu `#b84716`, alb și nuanțele neutre din `assets/design-profiles.css`. Header-ul păstrează stilurile comune paginilor interioare.
- Prima secțiune afișează deschis tabelul celor zece măsuri din registru. Fiecare are o ilustrație animată reprezentativă, selectată la hover, focus, click sau atingere; linkul „Vezi condițiile” deschide pagina măsurii. Roadmap-ul SVG și sculptura inițială au fost înlocuite conform feedback-ului beneficiarului.
- Cele cinci straturi volumetrice rămân în secțiunea metodei FABER și se reunesc pe parcursul scroll-ului.
- Pe desktop (minimum 1000 × 700 px), secțiunea metodei rămâne în ecran și trece prin cele cinci verificări în funcție de poziția scroll-ului, în ambele sensuri. Nu se interceptează rotița, touch-ul sau tastele de scroll.
- Formularul de solicitări este integrat la finalul paginii, înaintea componentei Google. Reutilizează fluxul și endpoint-ul existent, fără colectare sau destinații noi. Încărcarea homepage-ului nu mută automat utilizatorul la formular.
- Indicator de progres, navigare între secțiuni și apariții discrete ale conținutului.
- Pe telefon și tabletă se păstrează scroll-ul obișnuit, butoanele, glisarea și navigarea cu tastatura.
- Buton pentru oprirea animațiilor, preferință păstrată local și respectarea `prefers-reduced-motion`. Fără JavaScript, conținutul și legăturile principale rămân disponibile.

Registrul programelor, cele 23 de bannere, sursele oficiale, datele de verificare, contactul, calculatoarele și URL-urile existente sunt păstrate. Detaliile ample din hero se deschid explicit. Nu s-au copiat imagini sau cod din proiectul Evora; acesta a fost reper pentru mișcare și compoziție.

Printscreen-ul menționat în feedback nu a fost disponibil în conversație; tabelul a fost recuperat din sursa homepage-ului păstrată în Git.

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
| `immersive-v1-before-feedback.zip` | Prima variantă imersivă, înaintea reviziei cerute; etichetă `backup/immersive-v1-before-feedback-2026-08-31`, commit `c948ec2` |

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
- `tools/hero-program-scenes.js` și `assets/homepage-hero.js`: cele zece ilustrații și selecția măsurii; faptele rămân în registru.
- `tools/contact-triage-form.js` și `assets/contact-triage.js`: formularul comun pentru homepage și Contact.
- `tools/immersive-home-template.js`: markup-ul prezentării.
- Generatorii existenți `sync-homepage-hero.js` și `sync-homepage-decision-flow.js` includ noua prezentare. Rebuild-ul nu o elimină.
- `tests/homepage-decision-flow-responsive.mjs`: verificări la 320, 390, 768 și 1366 px, scroll înainte/înapoi, controale manuale, mișcare redusă, preferință persistentă și fallback fără JavaScript.

Testele inițiale sunt în `reports/immersive-design/verification.md`; verificările reviziei sunt în `reports/immersive-design/revision-client-2026-08-31.md`. Nu există dependințe frontend noi, modele 3D externe sau video obligatoriu pentru afișarea paginii.

## Starea publicării

Versiunea de publicare din 31 august este `immersive-20260831-4`: tabel cu zece ilustrații, cinci plăci sincronizate cu etapa activă și formularul final. Designul și publicarea au fost cerute explicit de beneficiar. Sursa corectă a fost proiectul separat `atelierdeconsultanta-main`, nu copia mai veche din proiectul GitHub. Ramura de publicare integrează această sursă cu remediile deja existente pe origin.

`verify-live-release.js` verifică această revizie, conținutul complet din main, cele zece scene, formularul și nouă resurse CSS/JS, atât la URL-ul obișnuit, cât și fără cache. Un build reușit sau simpla schimbare a manifestului nu mai sunt suficiente pentru confirmare.

Raportul [preflight inițial](../reports/immersive-design/publication-preflight.md) rămâne istoric. Lipsa preexistentă a baseline-ului INP real nu este rezolvată sau transformată în PASS: responsabilul este Frontend performance owner; retestul necesar este obținerea unei măsurători de teren aprobate, cu sursa, perioada și dispozitivul documentate, apoi repetarea comparației. Testele sintetice nu o înlocuiesc. Configurația gate-ului (blocare pentru severity critical) și aprobările nu au fost modificate.
