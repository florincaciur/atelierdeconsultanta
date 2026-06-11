# Release SEO-tech 2026-06-12

## Scop

Sincronizare finala dupa sprintul SEO-tech: sitemap regenerat, `llms.txt` aliniat cu paginile canonice indexabile si checklist GSC pentru post-deploy.

## URL-uri afectate

- `https://atelierdeconsultanta.ro/programul-tranzitie-justa`
- `https://atelierdeconsultanta.ro/programul-tranzitie-justa-intrebari-documente`
- `https://atelierdeconsultanta.ro/sitemap.xml`
- `https://atelierdeconsultanta.ro/llms.txt`

## Redirecturi noi

Nu au fost adaugate redirecturi noi in acest release. Redirecturile existente pentru variantele PTJ cu slash final, `.html` si `/index.html` raman gestionate in `_redirects`.

## Pagini scoase din index

Nu au fost marcate pagini noi cu `noindex` in acest release. Sitemap-ul regenerat exclude in continuare paginile `noindex`, fallback-urile de redirect si resursele tehnice.

## Pagini noi adaugate/promovate

- PTJ hub: `https://atelierdeconsultanta.ro/programul-tranzitie-justa`
- PTJ support: `https://atelierdeconsultanta.ro/programul-tranzitie-justa-intrebari-documente`

Ambele sunt prezente in `sitemap.xml` si au fost adaugate in `llms.txt` ca URL-uri canonice publice.

## Checklist GSC post-deploy

1. Trimite din nou `https://atelierdeconsultanta.ro/sitemap.xml` in Google Search Console.
2. Ruleaza URL Inspection pentru:
   - `https://atelierdeconsultanta.ro/programul-tranzitie-justa`
   - `https://atelierdeconsultanta.ro/programul-tranzitie-justa-intrebari-documente`
3. Apasa Request indexing pentru cele doua pagini PTJ daca inspectia confirma `URL is available to Google`.
4. Pentru paginile consolidate prin redirect, foloseste Validate fix doar daca GSC le raporteaza ca probleme tehnice; aliasurile intentionate pot ramane excluse ca redirecturi.
5. Pentru resurse tehnice sau pagini `noindex`, nu cere indexare manuala.
6. Verifica peste recrawl ca rapoartele istorice GSC se reduc; nu considera o mentiune istorica drept regresie pana cand Google recrawleaza URL-ul.
