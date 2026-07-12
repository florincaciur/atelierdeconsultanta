# GSC: oportunități și plan de remediere a indexării

Data auditului: 2026-07-12

## Inputuri și ferestre

| Export | Fereastră | Conținut relevant |
|---|---|---|
| `Performance-on-Search-2026-07-12.zip` | 2026-04-11–2026-07-10, Last 3 months | 260 query-uri, 134 pagini |
| `Performance-on-Search-2026-07-12 (1).zip` | 2026-06-13–2026-07-10, Last 28 days | 161 query-uri, 90 pagini |
| `Coverage-2026-07-12.zip` | seria se încheie la 2026-06-30 | motive și volume agregate, fără exemple URL |

Fișierele de oportunități păstrează separat cele două ferestre. Nu se însumează și nu se deduplichează metrici din perioade suprapuse.

## Oportunități query 6–12

`gsc-query-opportunities.csv` conține toate cele 183 de rânduri cu poziția inclusiv între 6 și 12:

- 108 din fereastra de 3 luni;
- 75 din fereastra de 28 zile.

Primele oportunități din ultimele 28 zile, sortate după impresii:

| Query | Clicks | Impressions | CTR | Position |
|---|---:|---:|---:|---:|
| femeia antreprenor 2026 | 4 | 103 | 3,88% | 9,69 |
| dr 12 afir lansare | 1 | 79 | 1,27% | 7,67 |
| femeia antreprenor 2026 inscriere | 0 | 41 | 0% | 9,07 |
| programul femeia antreprenor 2026 | 0 | 37 | 0% | 9,92 |
| gal afir | 0 | 34 | 0% | 7,74 |
| cand incepe programul femeia antreprenor 2026 | 0 | 24 | 0% | 9,67 |
| femeia antreprenor 2026 conditii | 1 | 23 | 4,35% | 8,87 |
| fonduri femeia antreprenor 2026 | 0 | 18 | 0% | 9,83 |
| adr nord est microintreprinderi | 0 | 17 | 0% | 8,65 |
| pro infra | 2 | 16 | 12,5% | 9,56 |

## Oportunități pagină

`gsc-page-opportunities.csv` conține toate cele 224 de rânduri din exporturile Pages, inclusiv impresii, CTR, poziție și marcaje pentru banda 6–12 și URL-uri legacy `.html`.

Primele pagini în banda 6–12 din ultimele 28 zile:

| Page | Clicks | Impressions | CTR | Position |
|---|---:|---:|---:|---:|
| `https://atelierdeconsultanta.ro/calculator-soc` | 6 | 2.276 | 0,26% | 8,21 |
| `https://atelierdeconsultanta.ro/femeia-antreprenor-2026` | 15 | 927 | 1,62% | 8,17 |
| `https://atelierdeconsultanta.ro/dr12-afir` | 7 | 471 | 1,49% | 8,37 |
| `https://atelierdeconsultanta.ro/gal-afir` | 0 | 343 | 0% | 6,05 |
| `https://atelierdeconsultanta.ro/investitii-modernizarea-microintreprinderilor-apel-2` | 9 | 341 | 2,64% | 6,9 |
| `https://atelierdeconsultanta.ro/dr14` | 3 | 213 | 1,41% | 8,49 |
| `https://atelierdeconsultanta.ro/e-move` | 7 | 158 | 4,43% | 7,71 |
| `https://atelierdeconsultanta.ro/acte-necesare-fonduri-europene-nerambursabile` | 2 | 141 | 1,42% | 7,22 |
| `https://atelierdeconsultanta.ro/fondul-modernizare-energie-regenerabila-2026` | 0 | 125 | 0% | 7,18 |
| `https://atelierdeconsultanta.ro/cod-caen-start-up-nation-2026` | 0 | 105 | 0% | 6,02 |

Acestea sunt oportunități de analiză, nu instrucțiuni de modificare automată a conținutului.

## Page Indexing: ce conține efectiv exportul

Ultimul punct din `Chart.csv`, 2026-06-30:

- 96 URL-uri not indexed;
- 93 URL-uri indexed;
- 358 impressions în ziua respectivă.

`Critical issues.csv` conține numai agregate:

| Reason | Source | Validation | Pages |
|---|---|---|---:|
| Page with redirect | Website | Started | 72 |
| Alternate page with proper canonical tag | Website | Started | 11 |
| Redirect error | Website | Started | 3 |
| Excluded by ‘noindex’ tag | Website | Started | 3 |
| Duplicate without user-selected canonical | Website | Started | 1 |
| Discovered - currently not indexed | Google systems | Started | 3 |
| Crawled - currently not indexed | Google systems | Started | 1 |
| Not found (404) | Website | N/A | 0 |
| Duplicate, Google chose different canonical than user | Google systems | Passed | 2 |

Exportul nu include niciun fișier cu exemple URL și metadata spune `Sitemap: All known pages`. Prin urmare:

- nu se poate lega niciun URL concret de cele 3 `Redirect error`;
- nu se poate identifica ce URL-uri sunt cele 3 noindex, cele 3 discovered sau acel URL crawled;
- nu se poate confirma din acest export că o problemă Coverage a fost reparată;
- starea `Started` descrie validarea GSC, nu o remediere confirmată.

## URL-uri legacy `.html` cu impresii

Exportul de 3 luni conține exact 23 URL-uri legacy cu impresii. La 2026-07-12, fiecare a fost verificat live și răspunde cu un singur 301 către URL-ul fără `.html`, urmat de 200. Acest rezultat este valabil numai pentru URL-urile exacte de mai jos și nu demonstrează că cele 3 `Redirect error` din Coverage sunt rezolvate.

| URL GSC | Impressions | CTR | Position | Verificare live |
|---|---:|---:|---:|---|
| `https://atelierdeconsultanta.ro/calculator-soc.html` | 1.017 | 2,85% | 7 | 301 → `/calculator-soc` → 200 |
| `https://atelierdeconsultanta.ro/dr14.html` | 406 | 1,72% | 9,1 | 301 → `/dr14` → 200 |
| `https://atelierdeconsultanta.ro/start-up-nation-2026.html` | 166 | 2,41% | 10,73 | 301 → `/start-up-nation-2026` → 200 |
| `https://atelierdeconsultanta.ro/por-adr-nord-est.html` | 149 | 0% | 6,69 | 301 → `/por-adr-nord-est` → 200 |
| `https://atelierdeconsultanta.ro/dr12-afir.html` | 102 | 1,96% | 6,36 | 301 → `/dr12-afir` → 200 |
| `https://atelierdeconsultanta.ro/acte-necesare-fonduri-europene-nerambursabile.html` | 98 | 2,04% | 7,5 | 301 → `/acte-necesare-fonduri-europene-nerambursabile` → 200 |
| `https://atelierdeconsultanta.ro/femeia-antreprenor-2026.html` | 86 | 2,33% | 10,23 | 301 → `/femeia-antreprenor-2026` → 200 |
| `https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri-plan.html` | 58 | 5,17% | 14,6 | 301 → `/start-up-nation-2026-idei-afaceri` → 200 |
| `https://atelierdeconsultanta.ro/cum-alegi-programul-potrivit-fonduri-europene-2026.html` | 46 | 4,35% | 5,85 | 301 → URL fără `.html` → 200 |
| `https://atelierdeconsultanta.ro/digitalizare-imm.html` | 44 | 0% | 47,32 | 301 → `/digitalizare-imm` → 200 |
| `https://atelierdeconsultanta.ro/femeia-antreprenor-2026-conditii-idei-afaceri.html` | 42 | 2,38% | 16,05 | 301 → URL fără `.html` → 200 |
| `https://atelierdeconsultanta.ro/termeni-si-conditii.html` | 40 | 2,5% | 3,33 | 301 → `/termeni-si-conditii` → 200 |
| `https://atelierdeconsultanta.ro/blog.html?post=blog-1` | 28 | 0% | 4,5 | 301 → `/blog?post=blog-1` → 200 |
| `https://atelierdeconsultanta.ro/pro-infra.html` | 27 | 0% | 9,11 | 301 → `/pro-infra` → 200 |
| `https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` | 24 | 8,33% | 8,83 | 301 → URL fără `.html` → 200 |
| `https://atelierdeconsultanta.ro/autoconsum-publici.html` | 20 | 0% | 3,95 | 301 → `/autoconsum-public-fotovoltaice-institutii-publice` → 200 |
| `https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar.html` | 19 | 0% | 19,53 | 301 → `/afir-autoconsum-agroalimentar` → 200 |
| `https://atelierdeconsultanta.ro/pnrr-digitalizare-imm-cheltuieli-eligibile.html` | 13 | 0% | 35,77 | 301 → URL fără `.html` → 200 |
| `https://atelierdeconsultanta.ro/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html` | 5 | 0% | 33,6 | 301 → URL fără `.html` → 200 |
| `https://atelierdeconsultanta.ro/politica-de-confidentialitate.html` | 3 | 0% | 5,67 | 301 → `/politica-de-confidentialitate` → 200 |
| `https://atelierdeconsultanta.ro/blog.html` | 3 | 0% | 4 | 301 → `/blog` → 200 |
| `https://atelierdeconsultanta.ro/gdpr.html` | 3 | 0% | 3,33 | 301 → `/gdpr` → 200 |
| `https://atelierdeconsultanta.ro/dr-12-afir-instalarea-tinerilor-fermieri.html` | 2 | 0% | 5,5 | 301 → URL fără `.html` → 200 |

În exportul de 28 zile nu apare niciun URL `.html`. „Nu apare” nu înseamnă automat zero impresii; exportul trebuie tratat ca lista returnată de interfața GSC, nu ca dovadă exhaustivă despre toate URL-urile proprietății.

## Plan de remediere determinist

1. Exportă din GSC lista de exemple pentru fiecare motiv cu `Pages > 0`, în special cele 3 `Redirect error`, cele 3 noindex, cele 3 discovered, acel URL crawled și duplicatele.
2. Pentru fiecare URL exportat, capturează statusul inițial, lanțul complet, URL-ul final, canonicalul, meta robots, `X-Robots-Tag`, prezența în sitemap și numărul de linkuri interne.
3. Separă redirecturile intenționate de erori. Cele 23 URL-uri legacy din Performance sunt verificate ca 301 direct; nu le atribui automat bucketului Coverage.
4. Pentru `Alternate page with proper canonical tag`, validează că alternativa este intenționată și că nu apare în sitemap sau linkuri interne canonice.
5. Pentru `Excluded by noindex`, validează intenția la nivel de URL și ambele surse de directivă: HTML și header HTTP.
6. Pentru `Discovered` și `Crawled - currently not indexed`, verifică unicitatea conținutului, self-canonical, linkurile interne, statusul 200 și includerea în sitemap înainte de orice cerere de indexare.
7. Pentru duplicate, compară canonicalul declarat cu canonicalul ales de Google și elimină doar semnalele contradictorii demonstrate.
8. Repornește validarea GSC numai după ce lista exactă a URL-urilor este verificată; păstrează data și rezultatul pentru fiecare URL.

## Ce nu s-a făcut

- Nu au fost modificate pagini, conținut, design, redirecturi sau canonicale.
- Nu s-a declarat rezolvat niciun bucket Page Indexing fără URL-uri exacte.
- Nu s-au combinat metricile celor două ferestre GSC.
