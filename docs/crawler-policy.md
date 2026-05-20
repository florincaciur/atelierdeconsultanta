# Crawler policy

Ultima actualizare: 2026-05-21

## Rezumat

Site-ul permite crawling-ul paginilor publice canonice pentru motoare de cautare si sisteme AI care respecta `robots.txt`. Nu exista reguli separate prin care anumite crawlere importante sunt blocate. Restrictiile se aplica tuturor user-agentilor si vizeaza doar zone private, interne sau variante duplicate.

## Crawlere permise

- Crawlerele de search indexing pot accesa paginile publice, sitemap-ul si `llms.txt`.
- Crawlerele AI/search care respecta `robots.txt` pot accesa aceleasi pagini publice.
- Asset-urile necesare randarii paginilor publice raman accesibile; sunt blocate doar fisierele de tip source map si zonele interne.

## Zone blocate

- `/admin/` - zona administrativa, nu este sursa publica.
- `/dist/`, `/tools/`, `/scripts/`, `/reports/`, `/config/`, `/node_modules/`, `/.github/`, `/.wrangler/` - fisiere interne, build, scripturi sau rapoarte.
- `/*.map$` - source maps, utile pentru debugging, nu pentru indexare.
- Parametri de tracking precum `utm_`, `fbclid`, `gclid`, `msclkid`, `ref` - evita variante duplicate ale aceleiasi pagini.

## Search indexing vs training

`robots.txt` controleaza accesul crawlerelor care il respecta. Indexarea in motoare de cautare si folosirea continutului pentru antrenare sau imbunatatirea modelelor sunt activitati diferite si pot fi tratate diferit de fiecare operator.

Politica actuala nu blocheaza explicit crawlere AI prin user-agent. Daca se doreste o politica separata pentru training, trebuie analizate user-agenturile reale din loguri si documentatia fiecarui operator, apoi adaugate reguli explicite in `robots.txt` si revizuite periodic.

## Ce trebuie verificat periodic in logs

- User-agenturi noi care acceseaza intens site-ul.
- Cereri catre `/admin/`, fisiere interne sau URL-uri cu parametri de tracking.
- 404-uri frecvente generate de crawlere.
- Accesari ale paginilor redirectate sau noindex care ar trebui eliminate din linkuri interne.
- Crawl frecvent pe URL-uri inexistente in `sitemap.xml`.
- Cereri pentru `llms.txt`, `robots.txt` si `sitemap.xml`, ca semnal ca fisierele sunt descoperite corect.
