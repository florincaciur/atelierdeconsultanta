# Audit GSC și crawlabilitate — 2026-07-28

Surse analizate:

- exporturile `atelierdeconsultanta.ro-Coverage-2026-07-28.xlsx` și `.zip`;
- capturile GSC cu exemplele eșuate;
- verificarea rutelor locale, a Worker-ului de domeniu și a răspunsurilor live existente înainte de remediere.

## Inventarul exportului

| Motiv GSC | URL-uri | Stare observată |
|---|---:|---|
| Page with redirect | 73 | Validation failed |
| Redirect error | 4 | Validation failed |
| Excluded by `noindex` tag | 4 | Validation failed |
| Crawled — currently not indexed | 3 | Validation failed |
| Blocked by robots.txt | 1 | Validation started |
| Alternate page with proper canonical tag | 5 | Validation started |
| Duplicate without user-selected canonical | 1 | Validation started |
| Discovered — currently not indexed | 7 | Passed |

Exportul mai indică 101 pagini indexate și 98 neindexate. Excluderile intenționate și aliasurile redirectate nu trebuie transformate în pagini canonice duplicate doar pentru reducerea numărului „Not indexed”.

## Decizii și remedieri

### Redirecturi și variante canonice

- Cele 73 de aliasuri istorice rămân redirecturi permanente. Contractul tehnic verifică 124 de reguli: zero bucle, zero lanțuri, zero URL-uri redirectate în sitemap și zero linkuri interne către redirecturi.
- Exemplele `Redirect error` verificate sunt:
  - `/blog-afir-fotovoltaice-ferme-2026.html`;
  - `/eligibilitate-fonduri-europene/`;
  - `/cod-caen-start-up-nation-2026/`;
  - `/fonduri-nerambursabile/`.
- Fiecare trebuie să ajungă într-un singur redirect permanent la un URL canonic ce răspunde `200`.
- Varianta HTTP a `/pnrr-digitalizare-imm-cheltuieli-eligibile` se consolidează prin HTTPS, iar destinația declară canonical propriu.
- Variantele cu `?post=`, HTTP și slash final rămân alternative corect consolidate; nu sunt pagini canonice noi.

### `noindex`

- `/dr-14-afir-conditii-eligibilitate-greseli-frecvente` a fost restaurată din suspendarea editorială rămasă accidental: `index, follow`, conținutul articolului, H1, canonical și JSON-LD.
- Aceeași cauză a fost eliminată preventiv pe `/dr-12-afir-instalarea-tinerilor-fermieri`.
- `/testimoniale` și `/portofoliu` păstrează intenționat `noindex, follow`, conform deciziei proprietarului.
- `/studii-de-caz` rămâne alias redirectat către `/studii-de-caz-fonduri-europene`, care este indexabil și self-canonical.
- `/official-guides.json` rămâne o resursă tehnică `200` cu `X-Robots-Tag: noindex, nofollow`; nu este pagină editorială.
- `/granturi-digitalizare-imm` rămâne neindexabil cât timp decizia separată de consolidare cu `/digitalizare-imm` nu este aprobată.

### Crawled — currently not indexed

- URL-ul `/contact?program_slug=...&source_page=...` primește acum un singur `301` către `/contact#...`. Parametrii nu mai creează un document crawlabil distinct, dar browserul îi păstrează pentru precompletarea formularului și atribuirea sursei.
- `/start-up-nation-2026-plan-de-afaceri/` rămâne alias permanent către forma canonică fără slash.
- `/official-guides.json` rămâne exclus intenționat ca resursă tehnică.

### Robots și agenți AI

- `/admin` și `/api` rămân private pentru orice crawler.
- Paginile și asset-urile publice sunt permise prin grupul `User-agent: *`.
- `robots.txt` declară explicit familiile cunoscute OpenAI, Anthropic, Perplexity, Google, Apple, Common Crawl, Meta, Amazon, ByteDance, Mistral și DeepSeek, inclusiv crawlere de căutare, acces la cererea utilizatorului și antrenare.
- `llms.txt` conține numai URL-uri canonice, indexabile și fără redirect; sitemap-ul conține 96 de URL-uri canonice.

## Criterii de acceptare

- pagină canonică publică: răspuns direct `200`, canonical propriu, fără `noindex`, prezentă în sitemap;
- alias: un singur `301` către destinație `200` self-canonical;
- pagină privată/tehnică: exclusă intenționat din index și sitemap;
- zero bucle sau lanțuri de redirect;
- zero linkuri interne către aliasuri;
- politicile crawlerelor permit conținutul public și păstrează `/admin` și `/api` blocate.

Validările GSC vor fi relansate manual de proprietar. Trecerea unei validări în GSC depinde de recrawl-ul Google și nu poate fi confirmată instantaneu de deploy.
