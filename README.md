# FABER — Atelier de Consultanță

Site static pentru [atelierdeconsultanta.ro](https://atelierdeconsultanta.ro), generat și verificat cu Node.js/npm și publicat prin Cloudflare din branch-ul de producție.

## IndexNow

Site-ul folosește IndexNow pentru notificarea motoarelor compatibile după publicarea conținutului.

### Generarea sau rotirea cheii

1. Generează o cheie IndexNow din pagina Bing/IndexNow sau cu un generator UUID. Cheia trebuie să aibă 8–128 caractere și poate conține litere, cifre și cratime.
2. Pune cheia în fișierul `indexnow-key.txt` din rădăcina repo-ului. Fișierul trebuie să conțină doar cheia, în UTF-8.
3. După deploy, verifică public `https://atelierdeconsultanta.ro/indexnow-key.txt`.
4. Scriptul `tools/submit-indexnow.js` citește cheia și trimite `keyLocation: https://atelierdeconsultanta.ro/indexnow-key.txt`.

Comenzi:

- `npm run submit:indexnow` trimite URL-urile schimbate față de `HEAD~1`;
- `npm run submit:indexnow:all` trimite toate URL-urile canonice;
- `node tools/submit-indexnow.js --changed --dry-run` verifică selecția fără submit.

Documentație: [IndexNow](https://www.indexnow.org/documentation) și [Bing IndexNow](https://www.bing.com/indexnow/getstarted).

## Registrul programelor și caruselul

Sursa unică pentru identitatea, statusul, sursele și includerea programelor pe suprafețele publice este `config/seo-programs.json#programs`.

- `presentation.carousel=true` și `presentation.carouselOrder` controlează includerea și ordinea în carusel;
- `presentation.hero=true` și `presentation.heroOrder` controlează selectorul din hero;
- `presentation.navigationOrder` controlează măsurile din navigarea globală;
- `discovery.listed=true` este echivalentul repo pentru `catalogEnabled=true` și controlează includerea în catalog și family hubs; selecția este centralizată în `catalogPrograms()`;
- `banners.json`, `partials/global-header.html`, `index.html` și paginile programelor sunt artefacte materializate și nu se editează ca surse factuale independente.

Fluxul sigur de modificare este:

1. actualizează înregistrarea programului numai pe baza sursei oficiale aprobate;
2. rulează `npm run validate:program-registry` și `npm run test:status-governance`;
3. rulează sincronizările necesare (`npm run sync:program-facts`, `npm run sync:global-header`, `npm run sync:homepage-hero`, `npm run sync:homepage-programs`, `npm run sync:program-family-hubs`);
4. verifică outputs-urile cu `npm run check:program-facts-sync` și testele relevante.

`config/homepage-programs.json` păstrează doar comportamentul componentei (limită, autorotire, linkul către catalog și reguli de grid). `config/program-status-taxonomy.json` definește vocabularul de status, iar atribuirea canonică este în fiecare program. `config/program-source-registry.json` păstrează numai catalogul surselor oficiale suplimentare; rolurile surselor fiecărui program sunt în înregistrarea sa.

Panoul `/admin/` nu este autoritatea pentru faptele programelor și nu trebuie folosit pentru publicarea directă a unui `banners.json` independent.

## Politica URL și canonical

Hostul canonical este `https://atelierdeconsultanta.ro`. Rutele indexabile folosesc forma curată lowercase, fără `www`, query string, `.html`, `/index.html` sau slash final, cu excepția homepage-ului `/`. Path-urile sunt case-sensitive: o variantă cu majuscule nu este un URL alternativ și poate răspunde 404. Autoritatea pentru setul public este inventarul generat de `tools/generate-route-inventory.js`; `_redirects` și workerul de domeniu păstrează aliasurile istorice prin 301 direct.

Definițiile din `config/seo-programs.json#pages` care indică rute retrase trebuie să declare `redirectTo`. Artefactele HTML păstrate ca fallback folosesc canonicalul destinației și nu devin surse publice concurente. Rulează `npm run test:canonical-policy` după orice schimbare de rutare, canonical, robots, sitemap sau host.

Toate mutările legacy sunt 301 directe către o destinație semantică indexabilă; nu există fallback global 404 către homepage. Rutele necunoscute și `/404` trebuie să emită HTTP 404, iar documentul `404.html` rămâne `noindex, follow`, fără canonical. Rulează `npm run test:redirect-policy` după orice schimbare a grafului de redirect sau a fallback-ului 404.

## Sitemap, crawling și suprafețe pentru asistenți

`sitemap.xml` publică numai URL-uri canonice, indexabile și servite 200. Politica de includere este în `config/sitemap-policy.json`; `lastmod` provine exclusiv din `lastMeaningfulUpdate` editorial verificat, nu din data build-ului. `robots.txt` permite suprafețele publice și activele de randare, protejează endpointurile `/api` și declară un singur sitemap canonical.

Pentru paginile HTML, meta robots și `X-Robots-Tag` nu trebuie să se contrazică. Răspunsurile 404 sunt `noindex, follow`, iar `/admin` rămâne crawlable `noindex` pentru ca directiva să poată fi observată. Preferințele crawlerelor AI sunt aprobate în `config/crawler-access-policy.json` și nu se schimbă implicit.

`llms.txt` este o hartă editorială opțională și selectivă, nu o copie a site-ului. Linkurile sale trebuie să fie canonice, indexabile și prezente în sitemap; data de actualizare urmărește ultima verificare a programelor publice din registry. După orice schimbare a acestor suprafețe rulează `npm run test:sitemap`, `npm run test:crawler-policy` și `npm run verify:llms-urls`.
