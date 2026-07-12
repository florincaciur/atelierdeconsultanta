# Audit determinist de paritate: repository, deploy și live

Data capturii: 2026-07-12 21:56 EEST (18:56 UTC)

## Concluzie executivă

Versiunea publică folosește lanțul **`origin/main` → GitHub Pages, directorul rădăcină `/` → Cloudflare proxy/cache → `atelierdeconsultanta.ro`**.

- Branch publicat: `main`.
- Commit publicat la momentul capturii: `93c7c74147a28d1a069a6432681bdf6c41d52606`.
- Director publicat: rădăcina repository-ului, nu `dist/`.
- `master` nu este sursa deploy-ului, chiar dacă `origin/master` indica același commit.
- Configurația `wrangler.jsonc` definește separat un output Cloudflare în `./dist`, dar corpul live este identic cu origin-ul GitHub Pages, nu cu un deploy independent demonstrabil din `dist`.
- Cloudflare termină TLS, aplică reguli de cache/header și injectează Managed Content în `robots.txt`; pentru restul probelor corpul primit prin Cloudflare este identic byte-for-byte cu GitHub Pages accesat direct.

Diferențele de titlu și conținut observate au două cauze independente:

1. `main` local este la `3bda76ecc0156c661a094f65f877d0c2ed784daf`, cu un commit înaintea `origin/main`; acele schimbări nu erau încă publicate la captură.
2. Pentru șase rute există simultan `<slug>.html` și `<slug>/index.html`. Ruta fără extensie publică fișierul plat. `tools/build-cloudflare-assets.js` codifică aceeași precedență și exclude varianta `index.html` când există fișierul plat. Divergența este vizibilă în special pentru `/dr14` și `/pro-infra`.

## Surse și metodă

Au fost comparate:

- checkout-ul curent, identic cu `main` local înaintea acestui raport;
- `origin/main` și `origin/master` după ultimul `fetch` disponibil;
- răspunsurile HTTPS publice descărcate cu redirecturile urmate;
- origin-ul GitHub Pages accesat direct la `185.199.108.153` prin `curl --resolve`;
- deployment-urile și workflow-urile din API-ul public GitHub;
- fișierele de configurare și generatoarele din repository.

SHA-256 este calculat pe octeții exacți. Pentru stabilirea parității de conținut s-a calculat suplimentar o variantă normalizată CRLF → LF, deoarece GitHub Pages servește LF. SHA-urile brute locale și live rămân raportate mai jos.

### Proveniența inputurilor

| Input | SHA-256 |
|---|---|
| `atelierdeconsultanta.ro-Performance-on-Search-2026-07-12.zip` | `1c6cfe778bc968c1e06edf3fe246aa73e882c6f8cebe9e7484c235a95aedf6fe` |
| `atelierdeconsultanta.ro-Performance-on-Search-2026-07-12 (1).zip` | `8df3614342320736cee42077cf3192540952b020ba9863cf1a8c4e8ac475d787` |
| `atelierdeconsultanta.ro-Coverage-2026-07-12.zip` | `9bf5e662dd24c9fe716fc01d3b5aeeed0ff20da317810c1be36d0b59df6cb707` |
| `sitemap.xml` local, 100 URL-uri | `3933cba49f4aed2103b4039d41427d1b7b08d9de78e62dd5dad35a1a908bffe3` |

## Dovezi pentru branch și directorul publicat

| Verificare | Rezultat |
|---|---|
| Repository GitHub | `florincaciur/atelierdeconsultanta`, default branch `main`, GitHub Pages activ |
| Workflow-uri | `pages-build-deployment` dinamic și `SEO Freshness & Sitemap Ping` |
| Ultimul deployment GitHub Pages | deployment `5383039850`, `ref=main`, SHA `93c7c74...`, creat 2026-07-09 21:23:39 UTC |
| Deployment environment | `github-pages`, executat de aplicația GitHub Pages |
| Custom domain | `CNAME` conține `atelierdeconsultanta.ro` |
| Origin direct | `Server: GitHub.com`, `Last-Modified: Thu, 09 Jul 2026 21:23:49 GMT`, `Cache-Control: max-age=600` |
| Domeniu public | IP-uri Cloudflare, `Server: cloudflare`, `CF-Cache-Status: HIT` |
| Test de corp | Cloudflare și origin GitHub Pages au corpuri identice pentru toate probele, exceptând injectarea Cloudflare din `robots.txt` |
| Director | Conținutul normalizat se potrivește cu fișierele din rădăcina `origin/main`; nu există dovadă că domeniul public servește `dist/` |

API-ul GitHub Pages `/pages` a răspuns 404 fără autentificare, dar API-ul de deployments, workflow-ul dinamic, commitul deployment-ului și testul direct de corp stabilesc branch-ul și origin-ul. Inventarul Cloudflare din cont nu a putut fi citit: tokenul Wrangler este expirat. Această limitare nu schimbă concluzia de rutare, deoarece origin-ul a fost verificat direct.

Origin-ul GitHub Pages prezintă un certificat expirat la acces direct și a necesitat `curl -k` pentru testul de corp. Certificatul public Cloudflare este valid; observația privește doar origin-ul bypassat.

## Paritate pe fișiere

| Fișier solicitat | SHA-256 local brut | SHA-256 live brut | Determinare |
|---|---|---|---|
| `index.html` | `dea81fff594c124d4457d56a5847ecf333b4646c5bf58614bbed415977e1840a` | `7561c36194ce9ce2a38165266d6e59a7cd02da83c4b6d698d2b2763b1e8a18b0` | Live = `origin/main:index.html` după CRLF→LF; `main` local conține versiunea încă nepublicată. |
| `dr12-afir/index.html` | `b1da882d2d9cd59419fe8dc07aa7c5ba17797ef9913d5ed2ecb7ad69f3815fe2` | `93abfda06ff231bcf563385841eba0714dcd6cbeabe0b1253d9d50a7f07f2fae` | Live = `origin/main:dr12-afir.html`; la commitul publicat, fișierul plat și varianta din director au același conținut normalizat. Schimbarea locală din director nu este publicată și rămâne umbrită de fișierul plat. |
| `dr14/index.html` | `063e8892562e208b635ea3c7c187e619acc9dd57007a4b67a3d5d162536719e4` | `0fdfc1148d72bdfb93e304ce3df4d00f25f8b88eb606428d5f14627f5635b26a` | Live = `origin/main:dr14.html`, nu `dr14/index.html`. Fișierul plat produce titlul `DR14 AFIR | investiții pentru ferme mici`; varianta din director are `DR 14 AFIR | ghid AFIR`. |
| `por-adr-nord-est/index.html` | `21d828fba2484113e3e2bfa6d6f5005a50f0d3b3da7ed6c91a8956d752e3aed4` | `955f54cb03c765dee17f8ecc9ec3aedc45e364da084d4e000dfc036bcb14fd6f` | Conținut egal după CRLF→LF; ruta este servită din fișierul plat, cu același conținut ca varianta din director. |
| `afir-autoconsum-agroalimentar/index.html` | `542565cfa88766951edd6b80a4ff9f7b7aef014358e8777d3275b1f12db027cd` | `f9b7f676d83626ee10ccb8f307fb1b09888c2c81474718b4e5433c707dbbd19b` | Conținut egal după CRLF→LF; ruta este servită din fișierul plat, cu același conținut. |
| `pro-infra/index.html` | `bdb6204d87edd9f502ac1ad8c1cc30a3cc833cdc38c566124d79d3b19ef15dd7` | `7cfddb01356637e1795cca35c7d7d61a372d4e7d59774304ac170683610f5b8d` | Live = `origin/main:pro-infra.html`, nu `pro-infra/index.html`. Fișierul plat produce titlul `PRO INFRA | producție pentru infrastructura de transport`; varianta din director are `PRO INFRA 2026 | ghid FABER`. |
| `pocidif-21/index.html` | `75664dd9c9a729b994eb0608b624b8dd21f10de1e7b9c48d7018ba71238bc110` | `ad1a14812485322f6d8ffd4bf28d42d253831a28c77e145ae2746440d5c42ec4` | Conținut egal după CRLF→LF; ruta este servită din fișierul plat, cu același conținut. |
| `sitemap.xml` | `3933cba49f4aed2103b4039d41427d1b7b08d9de78e62dd5dad35a1a908bffe3` | `186b1b5e13b52d314cb890e1d60e0cd82c7dfc9b0e16ea7fb9b67130399c4704` | Live = `origin/main:sitemap.xml`; versiunea locală cu 100 URL-uri este încă nepublicată. |
| `robots.txt` | `ac7455c4005c57e51bd4b21454290842abf1fd39607307a1d9fb5bb9c71dbb6b` | `7d435b370cd9c6724abb7d7dbae4e17a072418ad4d6be8e98e300433eb5473ab` | Origin GitHub Pages servește regulile repo-ului; Cloudflare preprinde un bloc Managed Content și reguli pentru crawlere AI. |
| `llms.txt` | `099c6fa031594650be40874d026e1a3fab7f16bfb6ec13245516214f22a67469` | `e4f7ded09d82a19607811984c306fc4265181ed348fd6321c9c6902cc58caa73` | Live = `origin/main:llms.txt`; versiunea locală este încă nepublicată. |
| `banners.json` | `0331ad3798e36493edf96bcec85aa1030736dfd0ebb8b4f06cee0198158020cc` | `0e441ba2d0e157df9dae4c70daddfd09f72cfa5d95e1a7f8cc6ce5f76689efba` | Conținut egal după CRLF→LF. |

Niciun SHA brut local nu coincide cu SHA-ul live deoarece checkout-ul folosește preponderent CRLF, în timp ce GitHub Pages servește LF; pentru fișierele marcate egale, hash-ul normalizat coincide.

## Fișiere plate care câștigă rezoluția rutei

Pentru toate rutele de mai jos, corpul live normalizat coincide cu fișierul plat din `origin/main`:

| Rută | Sursă efectivă | Observație |
|---|---|---|
| `/dr12-afir` | `dr12-afir.html` | Varianta din director este umbrită. |
| `/dr14` | `dr14.html` | Titlu și corp diferite față de `dr14/index.html`. |
| `/por-adr-nord-est` | `por-adr-nord-est.html` | Cele două variante au același corp la captură. |
| `/afir-autoconsum-agroalimentar` | `afir-autoconsum-agroalimentar.html` | Cele două variante au același corp la captură. |
| `/pro-infra` | `pro-infra.html` | Titlu și corp diferite față de `pro-infra/index.html`. |
| `/pocidif-21` | `pocidif-21.html` | Cele două variante au același corp la captură. |

Această precedență nu este accidentală în outputul Cloudflare: `tools/build-cloudflare-assets.js` refuză explicit copierea `<route>/index.html` dacă există `<route>.html`, apoi copiază outputul în `dist/`.

## Configurație de deploy și generatoare

### GitHub Pages și Actions

- GitHub Pages este activ și creează deployments cu `ref=main` în environment `github-pages`.
- Workflow-ul dinamic `pages-build-deployment` nu este stocat în `.github/workflows`; este gestionat de GitHub Pages.
- Singurul workflow stocat, `.github/workflows/seo-freshness.yml`, rulează săptămânal, modifică toate valorile `<lastmod>` din `sitemap.xml`, face commit și împinge explicit în `main`, apoi trimite sitemap-ul către Bing și IndexNow.
- Nu există workflow stocat care să ruleze `npm run build`, `wrangler deploy` sau `wrangler pages deploy` la push.

### Cloudflare

- `wrangler.jsonc` este o configurație Worker cu static assets din `./dist`, `html_handling=drop-trailing-slash` și comandă de build/validare.
- `package.json` oferă atât `deploy` (`wrangler deploy`) cât și `deploy:pages` (`wrangler pages deploy dist`), dar niciuna nu este apelată de GitHub Actions.
- Domeniul public este proxy Cloudflare peste GitHub Pages. Testul bypass demonstrează că HTML/XML/TXT/JSON provin de la GitHub Pages; Cloudflare nu servește un corp diferit, cu excepția `robots.txt`.
- Nu s-a putut enumera contul Cloudflare deoarece tokenul local Wrangler este expirat. Nu se afirmă că nu există proiecte sau Workers în cont; se afirmă doar că nu sunt origin-ul corpului public observat.

### Fișiere generate care pot schimba sursa

- `npm run build` rulează `apply:design-profiles`, `generate:sitemap`, `generate:feed` și abia apoi construiește `dist`.
- `tools/apply-design-profiles.js` poate rescrie fișiere HTML sursă.
- `tools/generate-sitemap.js` rescrie `sitemap.xml`.
- `tools/generate-feed.js` rescrie `feed.xml`.
- `tools/generate-project-design-pages.js` scrie pagini `<slug>/index.html`, dar nu face parte din `npm run build` și nu este apelat de workflow-ul GitHub.
- `tools/build-cloudflare-assets.js` curăță și reconstruiește `dist`; nu este sursa deployment-ului GitHub Pages actual.

## Cache și headers

| Resursă | Origin GitHub Pages | Domeniu public Cloudflare |
|---|---|---|
| HTML | `Cache-Control: max-age=600` | `public, max-age=0, must-revalidate`, `CF-Cache-Status: HIT` |
| `sitemap.xml` | `max-age=600` | `public, max-age=3600`, `X-Robots-Tag: noindex, nofollow` |
| `llms.txt` | `max-age=600` | `public, max-age=3600`, `X-Robots-Tag: noindex, nofollow` |
| `banners.json` | `max-age=600` | `public, max-age=0, must-revalidate` |
| `robots.txt` | corp repo, 94 bytes LF | corp Cloudflare Managed Content + corp repo, 1.930 bytes |

Regulile observate corespund `_headers` pentru HTML implicit, sitemap și llms; resursele de asset sunt configurate `max-age=31536000, immutable`. Cache-ul nu explică titlurile divergente: corpurile publice coincid cu commitul GitHub Pages publicat.

## GSC: inventar scurt

- Export 3 luni: 2026-04-11–2026-07-10, 260 query-uri, 134 pagini; 108 query-uri și 61 pagini în banda pozițiilor 6–12.
- Export 28 zile: 2026-06-13–2026-07-10, 161 query-uri, 90 pagini; 75 query-uri și 47 pagini în banda pozițiilor 6–12.
- CSV-ul de query-uri conține 183 rânduri, păstrate separat pe fereastră.
- CSV-ul de pagini conține toate cele 224 rânduri din cele două exporturi, cu marcaje `position_6_12` și `legacy_html`.
- Exportul Coverage este agregat și nu conține exemple URL.

Detaliile sunt în `gsc-query-opportunities.csv`, `gsc-page-opportunities.csv` și `gsc-indexing-remediation.md`.

## Limite și stare

- Auditul este o captură înainte de push; după publicarea unui commit nou în `main`, GitHub Pages poate schimba live-ul.
- Nu au fost modificate pagini, design, redirecturi, headere sau conținut public în timpul auditului.
- Nu se declară rezolvate problemele Page Indexing; exportul Coverage nu conține URL-urile exacte.
