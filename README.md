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
- `discovery.listed=true` controlează includerea în catalog și family hubs;
- `banners.json`, `partials/global-header.html`, `index.html` și paginile programelor sunt artefacte materializate și nu se editează ca surse factuale independente.

Fluxul sigur de modificare este:

1. actualizează înregistrarea programului numai pe baza sursei oficiale aprobate;
2. rulează `npm run validate:program-registry` și `npm run test:status-governance`;
3. rulează sincronizările necesare (`npm run sync:program-facts`, `npm run sync:global-header`, `npm run sync:homepage-hero`, `npm run sync:homepage-programs`, `npm run sync:program-family-hubs`);
4. verifică outputs-urile cu `npm run check:program-facts-sync` și testele relevante.

`config/homepage-programs.json` păstrează doar comportamentul componentei (limită, autorotire, linkul către catalog și reguli de grid). `config/program-status-taxonomy.json` definește vocabularul de status, iar atribuirea canonică este în fiecare program. `config/program-source-registry.json` păstrează numai catalogul surselor oficiale suplimentare; rolurile surselor fiecărui program sunt în înregistrarea sa.

Panoul `/admin/` nu este autoritatea pentru faptele programelor și nu trebuie folosit pentru publicarea directă a unui `banners.json` independent.
