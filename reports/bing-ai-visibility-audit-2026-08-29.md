# Audit Bing și vizibilitate în răspunsuri AI — 29 august 2026

## Concluzie executivă

Problema dominantă din exporturile primite este **volumul încă foarte mic de apariții**, nu un CTR care se degradează. În intervalul complet există 424 de impresii și 14 clicuri (CTR 3,30%), iar ultimele 28 de zile concentrează 252 de impresii și 9 clicuri (CTR 3,57%). Vizibilitatea crește, însă Bing dispune încă de puține observații și de un istoric scurt pentru domeniu.

Cele trei fișiere sunt ferestre temporale suprapuse ale aceluiași raport zilnic. Valorile nu trebuie adunate. Ele nu conțin dimensiunile `query` sau `page`; prin urmare nu permit atribuirea unei cauze certe unei interogări, unei pagini sau unei poziții medii.

## Datele analizate

| Export | Interval | Clicuri | Impresii | CTR recalculat | Zile cu impresii |
|---|---:|---:|---:|---:|---:|
| Overview complet | 11.05–26.08.2026 | 14 | 424 | 3,30% | 69/108 |
| Fereastră de 90 zile | 29.05–26.08.2026 | 14 | 423 | 3,31% | 68/90 |
| Ultimele 28 zile | 30.07–26.08.2026 | 9 | 252 | 3,57% | 27/28 |

Prima impresie din exportul complet apare la 27.05.2026, primul clic la 23.06.2026, iar maximul zilnic este de numai 22 de impresii, la 12.08.2026.

### Evoluția pe ferestre consecutive de 28 zile

| Interval | Clicuri | Impresii | CTR | Zile cu impresii |
|---|---:|---:|---:|---:|
| 04.06–01.07 | 1 | 29 | 3,45% | 16/28 |
| 02.07–29.07 | 4 | 142 | 2,82% | 25/28 |
| 30.07–26.08 | 9 | 252 | 3,57% | 27/28 |

Ultima perioadă crește cu 77,5% la impresii și cu 125% la clicuri față de perioada precedentă. Semnalul este pozitiv, dar 9 impresii/zi în medie rămân insuficiente pentru o prezență stabilă pe un portofoliu larg de interogări.

## Diagnosticul de bază

1. **Acoperire și istoric limitate în Bing.** Datele arată o fază de descoperire și extindere, nu o pierdere bruscă de ranking. Corpusul observat este încă mic.
2. **Autoritatea externă nu poate fi creată numai prin cod.** Sursele oficiale, schema semantică și claritatea editorială ajută motorul să înțeleagă și să citeze pagina, dar recomandarea depinde și de reputație, mențiuni și legături editoriale autentice din afara domeniului.
3. **Nu există o blocare tehnică evidentă în versiunea auditată.** Bingbot este permis de politica wildcard, sitemap-ul conține 104 URL-uri canonice, paginile nu sunt orfane, linkurile interne nu sunt rupte, iar IndexNow rulează după publicarea pe `main`.
4. **Nu există suficiente date pentru un diagnostic query-level.** Pentru a separa problemele de relevanță, CTR și poziție sunt necesare exporturile Bing Webmaster Tools pentru `Keywords` și `Pages`. Pentru citări AI sunt necesare `Grounding queries` și `Page citations` din AI Performance.

Bing recomandă sitemap-uri cu `lastmod` corect și IndexNow pentru descoperirea rapidă a schimbărilor; aceste mecanisme informează motorul, fără a garanta indexarea sau rankingul. Pentru citarea în răspunsuri AI, Bing indică structură clară, răspunsuri directe, dovezi/surse și actualizări editoriale trasabile. Surse: [Bing — Sitemaps and IndexNow in AI-powered search](https://blogs.bing.com/webmaster/July-2025/Keeping-Content-Discoverable-with-Sitemaps-in-AI-Powered-Search), [Bing — AI Performance](https://blogs.bing.com/webmaster/February-2026/Introducing-AI-Performance-in-Bing-Webmaster-Tools-Public-Preview).

## Remedieri aplicate în această versiune

- Linkurile interne și externe au fost reinventariate automat: 16.566 legături locale, 79 URL-uri externe și 1.041 fragmente.
- Referința ANPC SAL care răspundea 404 a fost înlocuită cu pagina oficială actuală `https://anpc.ro/sal/`; formularea veche despre SOL a fost eliminată.
- Sursele oficiale rămân vizibile, descriptive și corelate cu `citation`/`subjectOf`, autoritatea publică și data ultimei verificări în datele structurate.
- Paginile păstrează răspunsul direct, titluri ierarhice, tabele/FAQ unde sunt utile, canonicale curate, legături contextuale și dată editorială verificată.
- A fost adăugat controlul oficial Google Preferred Sources pe toate cele 104 rute canonice indexabile. Acesta este o funcție Google și nu influențează direct Bing.
- Fluxul IndexNow va transmite URL-urile schimbate după ce deploy-ul din `main` devine accesibil public.

## Măsurare recomandată în Bing Webmaster Tools

La următoarea evaluare trebuie exportate separat:

- Search Performance → Keywords: query, impressions, clicks, CTR, average position;
- Search Performance → Pages: URL, impressions, clicks, CTR, average position;
- AI Performance → Grounding queries și Page citations;
- Index Explorer → pagini cunoscute, indexate, excluse și ultima accesare.

Aceste exporturi permit o matrice `query → pagină → poziție → citări` și evită atribuirea greșită a unei variații zilnice unei probleme tehnice.

## Limită de interpretare

SEO, AEO și GEO pot crește claritatea, crawlabilitatea și probabilitatea ca o pagină să fie selectată drept sursă. Nicio implementare din site și nici butonul Preferred Sources nu pot garanta prima pagină, o citare AI sau o recomandare.
