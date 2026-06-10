# Raport remediere indexare GSC - 2026-06-10

## Rezumat

- Conventia canonica ramane: `https://atelierdeconsultanta.ro`, fara `www`, fara `.html`, fara `/index.html`, fara slash final in afara de homepage.
- Matricea CSV este in `reports/gsc-indexing-fix-2026-06-10.csv`; matricea detaliata ramane mai jos in acest raport.
- Auditul local pe `dist` a verificat 39 URL-uri din lista GSC si din rutele canonice cerute: 39 rezultate locale PASS.
- Sitemap-ul ramane curat: 95 URL-uri HTML canonice, fara query string, fara `.html`, fara `/index.html`, fara slash final si fara `official-guides.json`.
- `/official-guides.json` ramane accesibil cu 200 ca resursa JSON, dar este marcat `X-Robots-Tag: noindex, follow` prin `_headers`.

## Cauze identificate

- `official-guides.json` era tratat ca resursa publica 200, dar nu avea regula de deploy pentru `X-Robots-Tag: noindex, follow`; GSC il putea raporta la "Crawled - currently not indexed".
- Testul `verify:seo-local` pastra asteptari vechi in care cele trei pagini FAQ curate trebuiau sa redirectioneze catre pagini parinte; cerinta actuala le pastreaza indexabile, self-canonical si in sitemap.
- Testul functional avea un numar fix vechi de 94 URL-uri in sitemap; sitemap-ul actual are 95 URL-uri canonice.
- Generatorul sitemap folosea `mtime` local si putea schimba artificial `lastmod` dupa checkout/build. Generatorul pastreaza acum `lastmod` din sitemap-ul comis pentru paginile nemodificate si actualizeaza data doar pentru surse HTML modificate.
- Auditul GSC existent nu acoperea `official-guides.json`, `blog?post=blog-2`, `blog?post=blog-3` si toate rutele canonice/alternative cerute in prompt.
- Scriptul client-side pentru query-urile istorice de blog curata doar `blog-1`; acum curata client-side `blog-1`, `blog-2` si `blog-3` catre `/blog`, fara sa introduca linkuri interne SEO cu query.

## URL-uri reparate sau confirmate

- Pagini canonice 200 verificate in matrice: 17.
- Aliasuri pastrate ca redirect 301 catre canonice: 18.
- Variante alternative intentionate: 3 (`/blog?post=blog-1`, `/blog?post=blog-2`, `/blog?post=blog-3`).
- Resurse tehnice noindex: 1 (`/official-guides.json`).
- URL-uri adaugate in sitemap in acest commit: 0; sitemap-ul avea deja cele 95 de URL-uri canonice dupa sincronizarea cu `origin/main`.
- URL-uri eliminate din sitemap in acest commit: 0; `official-guides.json` nu este in sitemap.
- URL-uri marcate noindex in acest commit: 1, prin `_headers`.

## Redirecturi intentionate

- Slash final, `.html` si `/index.html` raman aliasuri 301 pentru paginile canonice curate.
- Localele consolidate, de exemplu `/fonduri-europene-iasi` si `/consultanta-fonduri-europene-bacau`, raman 301 catre `/fonduri-europene-nord-est`.
- `/intrebari/ce-documente-sunt-necesare-pentru-afir/` ramane 301 catre `/afir`.
- Aliasurile nu sunt in sitemap si matricea raporteaza 0 linkuri interne normale catre aliasurile GSC auditate.

## Pagini indexabile confirmate

- Bucuresti: `/fonduri-europene-bucuresti` si `/consultanta-fonduri-europene-bucuresti` sunt 200 direct, `index, follow`, self-canonical si in sitemap.
- FAQ: `/intrebari/ce-documente-sunt-necesare-pentru-dr12`, `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene`, `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm` sunt 200 direct, self-canonical si in sitemap.
- CAEN: `/fonduri-europene-caen/0111-culturi-cereale`, `/4321-instalatii-electrice`, `/5610-restaurante`, `/6201-dezvoltare-software` sunt 200 direct, self-canonical si in sitemap.
- `/pnrr`, `/afir`, `/consultanta-afir`, `/cat-costa-consultanta-fonduri-europene`, `/cum-alegi-consultant-fonduri-europene` si `/pro-infra` sunt 200 direct, self-canonical si in sitemap.

## Modificari aplicate

- `_headers`: adaugata regula exacta pentru `/official-guides.json` cu `Content-Type: application/json; charset=utf-8`, `X-Robots-Tag: noindex, follow` si cache scurt.
- `blog/index.html`: query-urile istorice `?post=blog-1`, `?post=blog-2`, `?post=blog-3` sunt curatate client-side catre `/blog`.
- `tools/generate-sitemap.js`: stabilizare `lastmod`, fara actualizari artificiale pentru pagini nemodificate.
- `tools/validate-seo-local.js`: asteptarile vechi pentru FAQ redirect au fost inlocuite cu verificari pentru rute canonice indexabile si pentru `official-guides.json`.
- `tools/audit-indexing.js`: verificari noi pentru JSON-LD parsabil si pentru resursa tehnica `official-guides.json`.
- `tools/validate-cloudflare-deploy.js`: verifica prezenta `dist/official-guides.json` si regula `dist/_headers`.
- `tools/audit-gsc-routes.js`: matrice GSC extinsa, cu statut local, statut live, redirect chain, canonical, robots, sitemap, link count, intentie si actiune.
- `tests/faber-functional-checks.mjs`: sitemap count actualizat la 95 si verificare HTTP pentru `official-guides.json` in `dist`.
- `sitemap.xml`: doar `lastmod` pentru `/blog` s-a actualizat, deoarece `blog/index.html` a fost modificat.

## Teste executate

- `npm ci` - PASS.
- `npm run build` - PASS, 95 URL-uri in sitemap si `dist` generat.
- `npm run verify:sitemap` - PASS.
- `npm run verify:seo-local` - PASS, 95 URL-uri si 3442 linkuri interne.
- `npm run verify:seo` - PASS, 168 fisiere, 0 fail.
- `npm run verify:all` - PASS.
- `npm run validate:cloudflare` - PASS, 356 redirecturi, 0 dinamice, regula `official-guides.json` validata in `dist/_headers`.
- `npm run audit:program-routes` - PASS.
- `npm run audit:gsc-routes` - PASS, 39/39 randuri locale PASS.
- `npm run test:functional` - PASS.
- `node tools/audit-indexing.js` - PASS, 95 URL-uri si linkuri interne.

## Verificare locala dist

- `/fonduri-europene-bucuresti`: 200, canonical self, `index, follow`.
- `/consultanta-fonduri-europene-bucuresti`: 200, canonical self, `index, follow`.
- `/fonduri-europene-bucuresti/`: 301 catre `/fonduri-europene-bucuresti`.
- `/consultanta-fonduri-europene-bucuresti.html`: 301 catre `/consultanta-fonduri-europene-bucuresti`.
- `/pnrr`: 200, canonical self, `index, follow`.
- `/intrebari/ce-documente-sunt-necesare-pentru-dr12`: 200, canonical self, `index, follow`.
- `/fonduri-europene-caen/6201-dezvoltare-software/`: 301 catre forma curata.
- `/blog?post=blog-2`: 200 cu canonical `/blog`.
- `/official-guides.json`: 200, `application/json; charset=utf-8`, `X-Robots-Tag: noindex, follow`.

## Verificare live

- Verificarea live pre-deploy a confirmat ca URL-urile canonice Bucuresti si aliasurile cu slash raspund corect pe site-ul curent.
- Inainte de acest deploy, `https://atelierdeconsultanta.ro/official-guides.json` raspundea 200 `application/json`, dar fara `X-Robots-Tag`; remedierea este in `_headers` si in `dist/_headers`.
- Inainte de acest deploy, `http://atelierdeconsultanta.ro/` raspundea 200 direct. Daca ramane asa dupa deploy, este necesara activarea setarii Cloudflare "Always Use HTTPS" sau o regula Cloudflare echivalenta la nivel de domeniu; aceasta nu este controlata de fisierele statice ale repo-ului.

## Pasi Google Search Console

A. Validate fix:
- `Page with redirect`: dupa deploy, pentru aliasurile care redirectioneaza intr-un singur hop catre forma canonica.
- `Alternate page with proper canonical tag`: pentru FAQ/CAEN dupa ce GSC recrawleaza formele curate si vede self-canonical.

B. Inspectare individuala si Request indexing:
- `/fonduri-europene-bucuresti`
- `/consultanta-fonduri-europene-bucuresti`
- `/pnrr`
- cele trei FAQ curate din sitemap
- cele patru pagini CAEN curate din sitemap

C. Excluderi intentionate:
- `/official-guides.json` trebuie sa ramana 200 noindex; nu forta indexarea.
- `/blog?post=blog-1`, `/blog?post=blog-2`, `/blog?post=blog-3` sunt variante query alternative ale `/blog`; nu se trimit in sitemap si nu se forteaza indexarea.
- Aliasurile `.html`, slash final si `/index.html` trebuie sa ramana redirecturi 301, nu pagini indexabile.

D. Observatie:
- Rapoartele GSC pot ramane istorice pana la recrawl. Nu exista garantie ca Google va indexa o pagina; modificarile elimina impedimentele tehnice si clarifica semnalele canonice.

## Matrice URL GSC

| URL raportat de GSC | statut local | statut live | lant de redirect | URL final | canonical declarat | meta robots | X-Robots-Tag | prezent in sitemap | numar linkuri interne catre URL | intentie | actiunea aplicata | rezultatul final |
|---|---:|---|---|---|---|---|---|:---:|---:|---|---|---|
| https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026/ -> https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [301]<br>https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [200] | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene/ -> https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene [301]<br>https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene [200] | https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene | https://atelierdeconsultanta.ro/firma-consultanta-fonduri-europene | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/consultanta-start-up-nation/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/consultanta-start-up-nation/ -> https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [301]<br>https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 [200] | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | https://atelierdeconsultanta.ro/consultanta-start-up-nation-2026 | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-imm/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene-imm/ -> https://atelierdeconsultanta.ro/fonduri-europene-imm [301]<br>https://atelierdeconsultanta.ro/fonduri-europene-imm [200] | https://atelierdeconsultanta.ro/fonduri-europene-imm | https://atelierdeconsultanta.ro/fonduri-europene-imm | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026.html -> https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 [301]<br>https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 [200] | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | https://atelierdeconsultanta.ro/blog-afir-fotovoltaice-ferme-2026 | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene/ | 200 after 1 redirect(s) | 200 after 1 redirect(s) | https://atelierdeconsultanta.ro/fonduri-europene/ -> https://atelierdeconsultanta.ro/fonduri-europene [301]<br>https://atelierdeconsultanta.ro/fonduri-europene [200] | https://atelierdeconsultanta.ro/fonduri-europene | https://atelierdeconsultanta.ro/fonduri-europene | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| http://atelierdeconsultanta.ro/politica-de-confidentialitate.html | 200 after 2 redirect(s) | 200 after 1 redirect(s) | http://atelierdeconsultanta.ro/politica-de-confidentialitate.html -> https://atelierdeconsultanta.ro/politica-de-confidentialitate.html [301]<br>https://atelierdeconsultanta.ro/politica-de-confidentialitate.html -> https://atelierdeconsultanta.ro/politica-de-confidentialitate [301]<br>https://atelierdeconsultanta.ro/politica-de-confidentialitate [200] | https://atelierdeconsultanta.ro/politica-de-confidentialitate | https://atelierdeconsultanta.ro/politica-de-confidentialitate | index, follow |  | yes | 0 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| http://atelierdeconsultanta.ro/ | 200 after 1 redirect(s) | 200 direct | http://atelierdeconsultanta.ro/ -> https://atelierdeconsultanta.ro/ [301]<br>https://atelierdeconsultanta.ro/ [200] | https://atelierdeconsultanta.ro/ | https://atelierdeconsultanta.ro/ | index, follow |  | yes | 1347 | alias cu redirect | Pastrat 301 direct catre URL-ul canonic; alias exclus din sitemap si din linkurile interne normale. | PASS_REDIRECT_TO_CANONICAL |
| https://atelierdeconsultanta.ro/fonduri-europene-bucuresti | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene-bucuresti [200] | https://atelierdeconsultanta.ro/fonduri-europene-bucuresti | https://atelierdeconsultanta.ro/fonduri-europene-bucuresti | index, follow |  | yes | 11 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti | 200 direct | 200 direct | https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti [200] | https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti | https://atelierdeconsultanta.ro/consultanta-fonduri-europene-bucuresti | index, follow |  | yes | 11 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/consultanta-fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/consultanta-fonduri-europene [200] | https://atelierdeconsultanta.ro/consultanta-fonduri-europene | https://atelierdeconsultanta.ro/consultanta-fonduri-europene | index, follow |  | yes | 190 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/fonduri-europene [200] | https://atelierdeconsultanta.ro/fonduri-europene | https://atelierdeconsultanta.ro/fonduri-europene | index, follow |  | yes | 211 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/pnrr | 200 direct | 200 direct | https://atelierdeconsultanta.ro/pnrr [200] | https://atelierdeconsultanta.ro/pnrr | https://atelierdeconsultanta.ro/pnrr | index, follow |  | yes | 21 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/afir | 200 direct | 200 direct | https://atelierdeconsultanta.ro/afir [200] | https://atelierdeconsultanta.ro/afir | https://atelierdeconsultanta.ro/afir | index, follow | index, follow | yes | 23 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/consultanta-afir | 200 direct | 200 direct | https://atelierdeconsultanta.ro/consultanta-afir [200] | https://atelierdeconsultanta.ro/consultanta-afir | https://atelierdeconsultanta.ro/consultanta-afir | index, follow |  | yes | 57 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene [200] | https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | https://atelierdeconsultanta.ro/cat-costa-consultanta-fonduri-europene | index, follow |  | yes | 13 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | 200 direct | 200 direct | https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene [200] | https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | https://atelierdeconsultanta.ro/cum-alegi-consultant-fonduri-europene | index, follow |  | yes | 11 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
| https://atelierdeconsultanta.ro/pro-infra | 200 direct | 200 direct | https://atelierdeconsultanta.ro/pro-infra [200] | https://atelierdeconsultanta.ro/pro-infra | https://atelierdeconsultanta.ro/pro-infra | index, follow |  | yes | 27 | pagina canonica indexabila | Confirmat 200 direct, self-canonical, indexabil si prezent in sitemap cand este pagina HTML. | PASS_CANONICAL_200 |
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
