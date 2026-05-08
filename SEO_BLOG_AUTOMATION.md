# Automatizare articole SEO pentru blog

Script principal:

```bash
node tools/generate-seo-blog-article.js --config config/seo-blog-article.example.json
```

Dry run, fără modificarea `blog.json` sau `sitemap.xml`:

```bash
node tools/generate-seo-blog-article.js --config config/seo-blog-article.example.json --dry-run
```

## Ce face automatizarea

- verifică accesul web înainte de generare;
- rulează etapa `WEB_RESEARCH_AND_AI_SEARCH_ALIGNMENT`;
- caută identitatea FABER / atelierdeconsultanta.ro;
- caută surse oficiale pentru program;
- verifică Google și Bing, continuând doar dacă cel puțin un SERP este disponibil;
- marchează motoarele AI indisponibile dacă nu există acces API/configurat;
- extrage text din document local `.txt`, `.md`, `.html`, `.docx` și, unde mediul permite, `.pdf`;
- generează articol HTML semantic, publicabil static;
- generează rapoarte în `reports/`;
- actualizează `blog.json`, dacă există;
- actualizează `sitemap.xml`, dacă există;
- validează HTML, canonical, robots, JSON-LD, H1, meta, word count, linkuri interne și limbaj interzis;
- rulează `node tools/audit-site-links.js` după generare.

## Input JSON

Vezi `config/seo-blog-article.example.json`.

Câmp minim:

- `linkGhidSolicitant`
- `numeDocumentOficial`

Poți completa doar unul dintre ele. Automatizarea deduce prudent:

- programul / măsura de finanțare;
- keywordul principal;
- keywordurile secundare;
- titlul SEO;
- meta description;
- slugul și URL-ul final;
- publicul țintă;
- categoria blog;
- întrebările relevante din web/SERP;
- linkurile interne.

Dacă vrei control editorial, poți suprascrie orice câmp:

- `titluPropus`
- `program`
- `beneficiarPrincipal`
- `keywordPrincipal`
- `keyworduriSecundare`
- `urlFinalDorit`
- `paginiInterneObligatorii`
- `dataPublicarii`
- `dataActualizarii`
- `categorieBlog`
- `icon`

Dacă lipsește `numeDocumentOficial`, scriptul folosește sursele oficiale de pe web. Dacă lipsește și web research-ul nu găsește surse oficiale, generarea se oprește.

## Exemplu minim

```json
{
  "linkGhidSolicitant": "https://site-oficial.ro/ghid-solicitant-program.pdf",
  "numeDocumentOficial": ""
}
```

Sau, dacă ai descărcat ghidul în repository:

```json
{
  "linkGhidSolicitant": "",
  "numeDocumentOficial": "ghid-solicitant-program.pdf"
}
```

În al doilea caz scriptul va încerca să deducă programul din document și va căuta singur sursele oficiale pe web.

## Reguli stricte

Scriptul nu generează articol publicabil dacă lipsește accesul web. Eroarea afișată este:

```text
Nu pot genera articol publicabil: lipsește accesul web necesar pentru verificarea surselor oficiale, a SERP-urilor și a semnalelor AI Search.
```

Scriptul nu inventează răspunsuri din ChatGPT, Claude, Gemini, DeepSeek, Manus sau Perplexity. Dacă nu există acces API configurat, raportul marchează motorul ca indisponibil.

## Output generat

Pentru slugul final, scriptul creează:

- articol HTML: `/<slug>.html` sau ruta din `urlFinalDorit`;
- `reports/seo-brief-<slug>.md`;
- `reports/seo-research-<slug>.md`;
- `reports/publish-checklist-<slug>.md`;
- update în `blog.json`, dacă nu rulezi cu `--dry-run` sau `--no-blog-json`;
- update în `sitemap.xml`, dacă nu rulezi cu `--dry-run` sau `--no-sitemap`.

## Publicare

După generare, verifică fișierele modificate:

```bash
git status --short
node tools/audit-site-links.js
```

Publică prin commit și push doar după ce raportul și checklistul nu au erori.

## IndexNow

Cheia IndexNow este publicată în root:

```text
https://atelierdeconsultanta.ro/a54d3e71f7854ddd9b9fc4cb91c7d681.txt
```

După deploy, poți trimite un URL nou către IndexNow:

```bash
node tools/submit-indexnow.js --url https://atelierdeconsultanta.ro/pagina-noua.html
```

Sau poți trimite toate URL-urile din `sitemap.xml`:

```bash
node tools/submit-indexnow.js --sitemap
```

Generatorul de articole acceptă și:

```bash
node tools/generate-seo-blog-article.js --config config/articol-nou.json --submit-indexnow
```

Folosește `--submit-indexnow` doar după ce pagina finală este deja publică/live.
