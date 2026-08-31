# Verificare design imersiv — 31 august 2026

Acest raport descrie prima variantă. Tabelul, formularul și paleta au fost revizuite ulterior conform feedback-ului; vezi [verificările reviziei](revision-client-2026-08-31.md).

## Rezultat verificat

Implementarea este integrată în generatorii paginii principale, pe ramura `codex/immersive-faber`. Previzualizare: `http://127.0.0.1:4173/`. Nu s-a făcut push sau deploy în producție.

### Interacțiuni și afișare

- Browser Chrome: inspecție vizuală pentru hero, metoda fixată în ecran, catalog și contact.
- Test automat actualizat la 320 × 720, 390 × 844, 768 × 900 și 1366 × 768: fără overflow orizontal.
- CTA principal vizibil în primul ecran la 390 × 844 și 1366 × 768.
- Selectorul Agricultură schimbă destinația la `/fonduri-europene-agricultura`; alegerea este anunțată accesibil și nu pretinde verificarea eligibilității.
- Scroll nativ înainte / înapoi schimbă etapa metodei; conținutul rămâne la 80 px sub partea superioară pe desktop.
- Tab-uri, săgeți și navigare cu tastatura funcționale. Indicatorul textual urmărește etapa activă fără anunțuri repetate la scroll.
- Carusel: trecere la programul următor și contor corect, fără rotire automată.
- Meniu mobil: deschidere / închidere. Instrumente: calculator și ghiduri accesibile.
- Mișcare redusă: secțiunea nu se fixează, animațiile sunt oprite; opțiunea manuală persistă după reîncărcare.
- Fără JavaScript: CTA disponibil, toate cele 5 verificări și cele 4 panouri de servicii / instrumente vizibile; controalele care cer JavaScript sunt ascunse.
- Linkul de contact este rezolvat de serverul local către pagina canonică, nu către aliasul de redirecționare. Nu s-au trimis mesaje sau formulare reale.

### Conținut și construcție

Au trecut:

```text
node tools/sync-homepage-hero.js --check
node tools/sync-homepage-decision-flow.js --check
node tests/homepage-hero-contract.mjs
node tests/homepage-clarity-contract.mjs
node tests/homepage-decision-flow-contract.mjs
node tests/homepage-program-explorer-contract.mjs
node tests/homepage-decision-flow-responsive.mjs
node scripts/verify-answer-readiness.js
node tools/check-links.js --offline --check --no-report
node tools/build-cloudflare-assets.js
node tools/validate-cloudflare-deploy.js
node tests/brand-entity-consistency-contract.mjs --dist
node tests/contact-nap-contract.mjs --dist
git diff --check
```

CSS-ul nou a fost analizat cu CleanCSS: zero erori și zero avertismente. JavaScript-ul nou trece `node --check`. Nu există dependințe frontend noi. CSS + JS adăugate însumează aproximativ 10 KB după gzip, fără un video sau un model 3D de descărcat.

Registrul, sursele și datele programelor nu au fost modificate. Se păstrează cele 23 de bannere, cele 4 servicii, cele 3 instrumente / ghiduri, URL-urile canonice, schema și datele de contact. Rezumatul esențial rămâne vizibil, în afara detaliilor pliante.

### Backup și limite

Bundle-ul backup a trecut `git bundle verify` și conține istoric complet. Titlurile, programele și linkurile din copia sursă de dinaintea schimbării corespund paginii live descărcate. Arhivele și SHA256SUMS.txt se află în directorul exterior documentat în `docs/immersive-design-and-rollback.md`.

**Pipeline complet PASS:** `npm run build:pipeline` s-a încheiat cu cod 0 în worktree-ul separat `atelierdeconsultanta-immersive-validation`, inclusiv 104 verificări vizuale ale paginilor de programe, controalele de navigare / contact / SEO, verificarea conținutului fără JavaScript și construirea pachetului Cloudflare. Logul complet este în directorul de backup, `validation-build-final.log`.

În proiectul utilizatorului există copii HTML salvate din browser, ignorate de Git, pe care unele verificatoare vechi le tratează ca pagini publice; acestea nu au fost modificate sau șterse. Pachetul public `dist` le exclude. Pentru o nouă rulare integrală sau publicare, folosește checkout-ul curat, nu exporturile locale de browser.

Această verificare locală nu măsoară impactul real asupra conversiilor, INP sau performanței utilizatorilor din producție. Controlul suplimentar de publicare a confirmat că lipsește valoarea INP de referință aprobată cerută de configurația existentă. Detaliile, limitele măsurătorilor sintetice și pașii rămași sunt în [raportul de publicare](publication-preflight.md). Preferințele de design se pot evalua în previzualizare înainte de înlocuirea site-ului public.
