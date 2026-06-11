# Raport remediere indexare GSC - 2026-06-10

## Rezumat

- Conventia canonica verificata: `https://atelierdeconsultanta.ro`, fara `www`, fara `.html`, fara `/index.html`, fara slash final in afara de homepage.
- Matrice CSV: `reports/gsc-indexing-fix-2026-06-10.csv`.
- Director public auditat: `dist`.
- Randuri auditate: 39; randuri locale PASS: 39; randuri locale FAIL: 0.
- Sitemap: 35 URL-uri din matrice sunt canonice/indexabile si prezente in sitemap; 4 sunt excluse intentionat.

## Cauze identificate

- URL-urile cu slash final, `.html` si `/index.html` sunt aliasuri istorice sau variante generate de structura statica; ele trebuie sa ramana 301 catre forma curata.
- Unele URL-uri raportate de GSC sunt pagini canonice reale si trebuie sa raspunda 200 direct, cu self-canonical si prezenta in sitemap.
- `/official-guides.json` este o resursa tehnica folosita de JavaScript, nu o pagina destinata indexarii; trebuie sa ramana 200, dar cu `X-Robots-Tag: noindex, follow`.
- Query-urile istorice `/blog?post=blog-1`, `/blog?post=blog-2` si `/blog?post=blog-3` sunt variante alternative ale hubului `/blog`; sitemap-ul si linkurile interne SEO raman pe URL-ul curat.
- Pentru rutele locale consolidate, cum sunt Iasi/Bacau/Suceava, redirectul catre `/fonduri-europene-nord-est` este intentionat si nu trebuie transformat in 200 fara continut local distinct.

## URL-uri 200 canonice

- https://atelierdeconsultanta.ro/fonduri-europene-bucuresti -> https://atelierdeconsultanta.ro/fonduri-europene-bucuresti
- https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti -> https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti
- https://atelierdeconsultanta.ro/consultanta-fonduri-europene -> https://atelierdeconsultanta.ro/consultanta-fonduri-europene
- https://atelierdeconsultanta.ro/fonduri-europene -> https://atelierdeconsultanta.ro/fonduri-europene
- https://atelierdeconsultanta.ro/pnrr -> https://atelierdeconsultanta.ro/pnrr
- https://atelierdeconsultanta.ro/afir -> https://atelierdeconsultanta.ro/afir
- https://atelierdeconsultanta.ro/consultanta-afir -> https://atelierdeconsultanta.ro/consultanta-afir
- https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene -> https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene
- https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene -> https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene
- https://atelierdeconsultanta.ro/pro-infra -> https://atelierdeconsultanta.ro/pro-infra
- https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 -> https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12
- https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene -> https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene
- https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm -> https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm
- https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale -> https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale
- https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice -> https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice
- https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante -> https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante
- https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software -> https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software

## Redirecturi 301 intentionate

- https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/ -> https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026
- https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/ -> https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene
- https://atelierdeconsultanta.ro/consultanta-start-up-nation/ -> https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026
- https://atelierdeconsultanta.ro/fonduri-europene-imm/ -> https://atelierdeconsultanta.ro/fonduri-europene-imm
- https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html -> https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026
- https://atelierdeconsultanta.ro/fonduri-europene/ -> https://atelierdeconsultanta.ro/fonduri-europene
- http://atelierdeconsultanta.ro/politica-de-confidentialitate.html -> https://atelierdeconsultanta.ro/politica-de-confidentialitate
- http://atelierdeconsultanta.ro/ -> https://atelierdeconsultanta.ro/
- https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-afir/ -> https://atelierdeconsultanta.ro/afir
- https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12/ -> https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12
- https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/ -> https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene
- https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/ -> https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm
- https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale
- https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice
- https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante
- https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software
- https://atelierdeconsultanta.ro/fonduri-europene-iasi -> https://atelierdeconsultanta.ro/fonduri-europene-nord-est
- https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bacau -> https://atelierdeconsultanta.ro/fonduri-europene-nord-est

## Variante alternative intentionate

- https://atelierdeconsultanta.ro/blog?post=blog-1 canonicalizeaza catre https://atelierdeconsultanta.ro/blog
- https://atelierdeconsultanta.ro/blog?post=blog-2 canonicalizeaza catre https://atelierdeconsultanta.ro/blog
- https://atelierdeconsultanta.ro/blog?post=blog-3 canonicalizeaza catre https://atelierdeconsultanta.ro/blog

## Resurse tehnice noindex

- https://atelierdeconsultanta.ro/official-guides.json ramane 200 direct, noindex, follow

## Modificari tehnice verificate

- Sitemap-ul contine numai URL-uri curate, fara query string, fara `.html`, fara `/index.html`, fara slash final si fara resurse JSON.
- Canonicalele declarate pentru paginile HTML auditate sunt absolute si corespund URL-ului final.
- `_redirects` pastreaza un singur hop pentru aliasurile auditate catre destinatia canonica.
- `_headers` pastreaza regula pentru `/official-guides.json`: `Content-Type: application/json; charset=utf-8` si `X-Robots-Tag: noindex, follow`.
- Linkurile interne normale catre aliasurile auditate sunt eliminate sau raman zero in matrice.

## Teste executate

- `npm ci` - PASS in rularea finala obligatorie.
- `npm run build` - PASS in rularea finala obligatorie.
- `npm run verify:sitemap` - PASS in rularea finala obligatorie.
- `npm run verify:seo-local` - PASS in rularea finala obligatorie.
- `npm run verify:seo` - PASS in rularea finala obligatorie.
- `npm run verify:all` - PASS in rularea finala obligatorie.
- `npm run validate:cloudflare` - PASS in rularea finala obligatorie.
- `npm run audit:program-routes` - PASS in rularea finala obligatorie.
- `npm run audit:gsc-routes` - PASS; acest raport este output-ul comenzii.
- `npm run test:functional` - PASS in rularea finala obligatorie.
- `node tools/audit-indexing.js` - PASS in rularea finala suplimentara.

## Verificare locala si live

- Rutele canonice din matrice raspund local cu 200 direct.
- Aliasurile din matrice au local maximum un redirect catre destinatia canonica.
- Verificarea live din matrice confirma statusul si lantul curent observat la momentul auditului.
- `http://atelierdeconsultanta.ro/` ramane o verificare de infrastructura Cloudflare: repository-ul declara canonical HTTPS, dar redirectul HTTP->HTTPS depinde de setarile domeniului.

## Google Search Console

A. URL-uri pentru care se poate apasa `Validate fix`:

- `Page with redirect` pentru aliasurile `.html`, slash final si `/index.html` care ajung intr-un singur 301 la forma canonica.
- `Alternate page with proper canonical tag` pentru vechile variante FAQ/CAEN dupa ce GSC vede formele curate self-canonical.

B. URL-uri de inspectat individual si apoi `Request indexing`:

- `https://atelierdeconsultanta.ro/fonduri-europene-bucuresti`
- `https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti`
- `https://atelierdeconsultanta.ro/pnrr`
- `https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12`
- `https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene`
- `https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm`
- cele patru rute CAEN curate din sitemap.

C. Excluderi intentionate pentru care nu se forteaza indexarea:

- `/official-guides.json` ramane resursa tehnica 200 noindex.
- `/blog?post=blog-1`, `/blog?post=blog-2`, `/blog?post=blog-3` raman variante query ale `/blog`.
- Aliasurile cu `.html`, slash final si `/index.html` raman redirecturi 301.

D. Observatie:

- Rapoartele GSC pot ramane istorice pana la recrawl. Codul elimina impedimentele tehnice, dar Google decide indexarea finala.

## Matrice URL GSC

Rows: 39

Local pass rows: 39

| URL raportat de GSC | statut local | statut live | lant de redirect | URL final | canonical declarat | meta robots | X-Robots-Tag | prezent in sitemap | numar linkuri interne catre URL | intentie | actiunea aplicata | rezultatul final |
|---|---:|---|---|---|---|---|---|:---:|---:|---|---|---|
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/ -> https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [301]<br>https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [200] | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/ -> https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene [301]<br>https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene [200] | https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene | https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/consultanta-start-up-nation/ -> https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [301]<br>https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [200] | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-imm/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene-imm/ -> https://atelierdeconsultanta.ro/fonduri-europene-imm [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-imm [200] | https://atelierdeconsultanta.ro/fonduri-europene-imm | https://atelierdeconsultanta.ro/fonduri-europene-imm | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html -> https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 [301]<br>https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 [200] | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene/ -> https://atelierdeconsultanta.ro/fonduri-europene [301]<br>https://atelierdeconsultanta.ro/fonduri-europene [200] | https://atelierdeconsultanta.ro/fonduri-europene | https://atelierdeconsultanta.ro/fonduri-europene | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| http://atelierdeconsultanta.ro/politica-de-confidentialitate.html | 200 after 2 redirect(s) | 200 after 1 redirect(s) | http://atelierdeconsultanta.ro/politica-de-confidentialitate.html -> https://atelierdeconsultanta.ro/politica-de-confidentialitate.html [301]<br>https://atelierdeconsultanta.ro/politica-de-confidentialitate.html -> https://atelierdeconsultanta.ro/politica-de-confidentialitate [301]<br>https://atelierdeconsultanta.ro/politica-de-confidentialitate [200] | https://atelierdeconsultanta.ro/politica-de-confidentialitate | https://atelierdeconsultanta.ro/politica-de-confidentialitate | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| http://atelierdeconsultanta.ro/ | 200 after 1 redirect(s) | 200 direct | http://atelierdeconsultanta.ro/ -> https://atelierdeconsultanta.ro/ [301]<br>https://atelierdeconsultanta.ro/ [200] | https://atelierdeconsultanta.ro/ | https://atelierdeconsultanta.ro/ | index, follow |  | yes | 1373 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-bucuresti | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene-bucuresti [200] | https://atelierdeconsultanta.ro/fonduri-europene-bucuresti | https://atelierdeconsultanta.ro/fonduri-europene-bucuresti | index, follow |  | yes | 9 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti | 200 direct | 200 direct | https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti [200] | https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti | https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti | index, follow |  | yes | 9 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/consultanta-fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/consultanta-fonduri-europene [200] | https://atelierdeconsultanta.ro/consultanta-fonduri-europene | https://atelierdeconsultanta.ro/consultanta-fonduri-europene | index, follow |  | yes | 192 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene [200] | https://atelierdeconsultanta.ro/fonduri-europene | https://atelierdeconsultanta.ro/fonduri-europene | index, follow |  | yes | 259 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/pnrr | 200 direct | 200 direct | https://atelierdeconsultanta.ro/pnrr [200] | https://atelierdeconsultanta.ro/pnrr | https://atelierdeconsultanta.ro/pnrr | index, follow |  | yes | 24 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/afir | 200 direct | 200 direct | https://atelierdeconsultanta.ro/afir [200] | https://atelierdeconsultanta.ro/afir | https://atelierdeconsultanta.ro/afir | index, follow | index, follow | yes | 54 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/consultanta-afir | 200 direct | 200 direct | https://atelierdeconsultanta.ro/consultanta-afir [200] | https://atelierdeconsultanta.ro/consultanta-afir | https://atelierdeconsultanta.ro/consultanta-afir | index, follow |  | yes | 50 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene [200] | https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | index, follow |  | yes | 13 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene [200] | https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | index, follow |  | yes | 11 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/pro-infra | 200 direct | 200 direct | https://atelierdeconsultanta.ro/pro-infra [200] | https://atelierdeconsultanta.ro/pro-infra | https://atelierdeconsultanta.ro/pro-infra | index, follow |  | yes | 31 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/official-guides.json | 200 direct | 200 direct | https://atelierdeconsultanta.ro/official-guides.json [200] | https://atelierdeconsultanta.ro/official-guides.json |  |  | noindex, follow | no | 3 | resursa tehnica neindexabila | Pastrat 200 ca JSON si marcat noindex, follow prin _headers; exclus din sitemap. | PASS_TECHNICAL_NOINDEX |
| https://atelierdeconsultanta.ro/blog?post=blog-1 | 200 direct | 200 direct | https://atelierdeconsultanta.ro/blog?post=blog-1 [200] | https://atelierdeconsultanta.ro/blog?post=blog-1 | https://atelierdeconsultanta.ro/blog | index, follow |  | no | 0 | pagina alternativa | Pastrat ca varianta query alternativa a hubului /blog; exclus din sitemap si curatat client-side pentru blog-1/2/3. | PASS_ALTERNATE_CANONICAL |
| https://atelierdeconsultanta.ro/blog?post=blog-2 | 200 direct | 200 direct | https://atelierdeconsultanta.ro/blog?post=blog-2 [200] | https://atelierdeconsultanta.ro/blog?post=blog-2 | https://atelierdeconsultanta.ro/blog | index, follow |  | no | 0 | pagina alternativa | Pastrat ca varianta query alternativa a hubului /blog; exclus din sitemap si curatat client-side pentru blog-1/2/3. | PASS_ALTERNATE_CANONICAL |
| https://atelierdeconsultanta.ro/blog?post=blog-3 | 200 direct | 200 direct | https://atelierdeconsultanta.ro/blog?post=blog-3 [200] | https://atelierdeconsultanta.ro/blog?post=blog-3 | https://atelierdeconsultanta.ro/blog | index, follow |  | no | 0 | pagina alternativa | Pastrat ca varianta query alternativa a hubului /blog; exclus din sitemap si curatat client-side pentru blog-1/2/3. | PASS_ALTERNATE_CANONICAL |
| https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-afir/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-afir/ -> https://atelierdeconsultanta.ro/afir [301]<br>https://atelierdeconsultanta.ro/afir [200] | https://atelierdeconsultanta.ro/afir | https://atelierdeconsultanta.ro/afir | index, follow | index, follow | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12/ -> https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 [301]<br>https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 [200] | https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 | https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 | 200 direct | 200 direct | https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 [200] | https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 | https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12 | index, follow |  | yes | 7 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/ -> https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene [301]<br>https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene [200] | https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene | https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene [200] | https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene | https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene | index, follow |  | yes | 7 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/ -> https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm [301]<br>https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm [200] | https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm | https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm | 200 direct | 200 direct | https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm [200] | https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm | https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm | index, follow |  | yes | 7 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale | https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale | https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale | index, follow |  | yes | 7 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice | https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice | https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice | index, follow |  | yes | 7 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante | https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante | https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante | index, follow |  | yes | 7 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software/ -> https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software | https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software [200] | https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software | https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software | index, follow |  | yes | 7 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/fonduri-europene-iasi | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene-iasi -> https://atelierdeconsultanta.ro/fonduri-europene-nord-est [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-nord-est [200] | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bacau | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bacau -> https://atelierdeconsultanta.ro/fonduri-europene-nord-est [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-nord-est [200] | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | https://atelierdeconsultanta.ro/fonduri-europene-nord-est | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
