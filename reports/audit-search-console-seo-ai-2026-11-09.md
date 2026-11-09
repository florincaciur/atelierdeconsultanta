# Audit Search Console, trafic organic și vizibilitate în răspunsurile AI

9 noiembrie 2026 · proprietatea de domeniu atelierdeconsultanta.ro

## Ce raportează Google

Raportul **Page indexing**, actualizat la 6 noiembrie, afișează **103 URL-uri indexate și 114 excluse**. Coloana de validare descrie starea verificării din Search Console. Coloana de răspuns live descrie testul HTTP din 9 noiembrie.

| Motiv | URL-uri | Validare | Răspuns live și decizie |
|---|---:|---|---|
| Pagină cu redirecționare | 83 | Eșuată | Toate răspund cu o singură redirecționare și o destinație 200. Sunt variante istorice, HTTP/www, căi cu slash sau extensie și adrese cu parametri. Se urmărește destinația canonică. |
| Accesată cu crawlere, momentan neindexată | 16 | Eșuată | Trei pagini canonice 200, zece aliasuri 301 → 200 și trei resurse cu `X-Robots-Tag: noindex`. Detalierea apare mai jos. |
| Eroare de redirecționare | 5 | Trecută | Toate cele cinci rute răspund acum 301 → 200 fără buclă sau lanț. |
| Exclusă prin `noindex` | 4 | Trecută | Toate cele patru adrese istorice redirecționează acum către destinații 200. |
| Pagină alternativă cu un canonical corect | 4 | Trecută | Variantele istorice redirecționează către destinații canonice 200. |
| Duplicat fără canonic ales de editor | 1 | Trecută | URL-ul HTTP pentru cheltuielile PNRR redirecționează spre URL-ul HTTPS cu canonical propriu. |
| Blocată de `robots.txt` | 1 | Trecută | `/admin/` redirecționează spre `/admin`, care trimite `noindex, nofollow`. Este o excludere intenționată. |
| Descoperită, momentan neindexată | 0 | Trecută | Niciun URL în categorie. |

Cele 114 exemple sunt în [inventarul de URL-uri și răspunsuri HTTP](audit-search-console-url-2026-11-09.csv). Raportul Google reflectă istoricul de crawl. O redirecționare permanentă sănătoasă poate rămâne în categoria de excludere, iar URL-ul destinat indexării este cel final. [Raportul de indexare în Search Console](https://search.google.com/search-console/index?resource_id=sc-domain%3Aatelierdeconsultanta.ro) · [Documentația Google](https://support.google.com/webmasters/answer/7440203?hl=en)

**Din cele 16 URL-uri accesate și neindexate**

- `/consultanta-pnrr-digitalizare` are acum un traseu distinct către apelul ADR Centru pentru investiții noi. Pagina de serviciu rămâne axată pe implementarea proiectelor PNRR contractate.
- `/fonduri-europene-digitalizare` include apelul Centru în lista HTML de programe, cu termen, beneficiari și sursă. Pagina canonică a apelului tratează detaliile.
- `/cum-alegi-consultant-fonduri-europene` are un exemplu concret de comparare a ofertelor pentru auditul independent, planul de digitalizare și macheta financiară, cu legătură către documentele apelului.
- `calendar-pregatire-depunere.xlsx`, `buget-digitalizare-imm.xlsx` și `official-guides.json` răspund 200 cu `noindex`. Pentru căutare sunt mai utile paginile HTML care explică resursele și trimit la descărcări.
- Zece URL-uri sunt aliasuri. Printre ele se numără `/portofoliu`, care ajunge la studiile de caz, și `/granturi-digitalizare-imm/`, care ajunge la pagina PNRR canonică.

**Alte rapoarte.** Sitemapul principal are statutul Success, 105 pagini descoperite și a fost citit pe 2 noiembrie. HTTPS are 46 de URL-uri HTTPS și zero critice. Breadcrumbs are 45 de elemente valide și zero invalide. Rapoartele de securitate și acțiuni manuale sunt fără probleme detectate. Pentru Core Web Vitals lipsesc datele de utilizare din ultimele 90 de zile atât pe mobil, cât și pe desktop. [Sitemaps](https://search.google.com/search-console/sitemaps?resource_id=sc-domain%3Aatelierdeconsultanta.ro) · [Core Web Vitals](https://search.google.com/search-console/core-web-vitals?resource_id=sc-domain%3Aatelierdeconsultanta.ro)

Crawlul public a parcurs 105 URL-uri din sitemap, 106 pagini HTML, 243 URL-uri istorice și 70 de resurse. Singura abatere a fost `/gdpr`, pagină indexabilă exclusă explicit din sitemap ca duplicat potențial. Politica de publicare din `config/sitemap-policy.json` condiționează consolidarea juridică și SEO de aprobare. După validarea echivalenței cu politica de confidențialitate, actualizează adresa din legăturile interne și aplică decizia de consolidare. [Crawlul tehnic live](technical-seo-crawl-2026-11-09-live.md)

Cele 40 de cereri de test cu user-agent de crawler au primit HTTP 200 pentru resursele publice verificate. Accesul crawlerelor autentificate se verifică separat în evenimentele Cloudflare, pe IP și user-agent.

## e-DRIVE

- URL Inspection indică **URL is on Google**, Googlebot smartphone, acces și indexare permise, ultimul crawl la 5 noiembrie și canonical ales identic cu URL-ul inspectat. Câmpul Sitemaps afișează **Temporary processing error**, deși sitemapul principal este acceptat și `/e-drive` apare în sitemapul de programe. Reverifică acel câmp după următorul crawl. [URL Inspection](https://search.google.com/search-console/inspect?resource_id=sc-domain%3Aatelierdeconsultanta.ro&id=L_xnsls89dzYryA4lOctyw) · [Explicația Google](https://support.google.com/webmasters/answer/9012289?hl=en)
- Între **8 august și 7 noiembrie 2026**, pagina a obținut **725 clicuri**, **22.818 afișări**, **CTR 3,2%** și **poziție medie 7,2**. Site-ul a avut 1.613 clicuri, aproximativ 53.400 afișări, CTR 3% și poziție 7,7. Pentru aceeași perioadă, raportul AI Search afișează **1.806 afișări e-DRIVE** din 4.175 pe site. Aceste afișări sunt deja incluse în raportul general Search. [Performanță e-DRIVE](https://search.google.com/search-console/performance/search-analytics?resource_id=sc-domain%3Aatelierdeconsultanta.ro&page=!https%3A%2F%2Fatelierdeconsultanta.ro%2Fe-drive) · [Raport AI Search](https://search.google.com/search-console/performance/search-analytics/ai?resource_id=sc-domain%3Aatelierdeconsultanta.ro) · [Metoda Google](https://developers.google.com/search/blog/2026/06/gen-ai-performance-reports)
- Interogări de urmărit: `e drive 2026` (873 afișări, 20 clicuri), `programul e drive 2026` (586, 8), `e drive 2026 ghid` (231, 14) și `e drive masura 1` (284, 9). Titlul și descrierea pun accent pe ghid, eligibilitate și cele două măsuri. Cuprinsul trimite la cele două exemple de calcul. Pagina e-MOVE trimite către e-DRIVE pentru finanțarea flotelor.

## Audit și prompturi pentru fiecare pagină

[Matricea cu 106 pagini canonice, constatări și prompturi Codex](audit-pagini-seo-ai-2026-11-09.csv) include câte o acțiune specifică pentru fiecare adresă. Prioritatea 1 acoperă e-DRIVE, ADR Centru, calendarul, hub-ul de digitalizare, paginile canonice din raportul de excluderi, resursele și DR-12.

Numărul de legături contextuale numără paginile canonice care trimit din `main`, separat de navigația globală. Sursele primare numără linkuri unice către domenii instituționale identificate, iar coloana GSC arată dacă adresa canonică apare explicit în cele 114 exemple. Pentru confirmarea indexării altor pagini se folosește URL Inspection. Volumul textului și lungimea titlurilor sunt semnale de revizuire. Acoperirea intenției și utilitatea informației se evaluează pentru fiecare pagină.

La verificarea finală, 24 de adrese au mai puțin de două pagini care trimit contextual la ele. Cele 106 titluri și descrieri din sitemap sunt unice. Pachetul local a trecut validarea Cloudflare, testele de metadate și randarea paginii ADR Centru și a paginii e-DRIVE la 320, 390 și 1440 px, inclusiv fără JavaScript la 320 px.

### Prompturi pentru următoarele intervenții

1. **e-DRIVE, revizie la publicarea ghidurilor aprobate.** „Compară documentele MTI aprobate pentru Măsurile 1 și 2 cu versiunile din 3 noiembrie. Pe `/e-drive`, actualizează tabelul diferențelor, exemplele de calcul și răspunsul despre calendar. Citează fiecare document și sincronizează registrul, schema, titlul, descrierea și lastmod numai pentru modificări reale. Verifică ancorele `#masura-1` și `#masura-2`.”
2. **ADR Centru, verificare la deschiderea sesiunii.** „Verifică apelul PRC/1059/PRC_P2/OP1/RSO1.2/PRC_A32 în MySMIS, pe site-ul ADR și în eventualele corrigenda. Actualizează statutul când sesiunea este confirmată, sincronizează pagina, catalogul și calendarul. Adaugă un exemplu verificabil de plan ERP cu audit, indicator și buget, citând Anexele 3, 4, 6, 7 și 13 unde se aplică.”
3. **Resurse XLSX, acces din căutare.** „În `/resurse`, descrie în HTML câmpurile din calendar și din bugetul de digitalizare, formulele și un rând de exemplu. Leagă din ghiduri direct de secțiunile HTML și testează descărcările. Păstrează `noindex` pe XLSX și JSON.”
4. **Pagini apropiate ca intenție.** „Exportă din GSC dimensiunile interogare și pagină pentru 28 și 90 de zile. Compară `/consultanta-pnrr-digitalizare`, `/digitalizare-imm-pnrr`, `/digitalizare-imm`, `/fonduri-europene-digitalizare` și pagina ADR Centru. Atribuie fiecărui URL o întrebare distinctă, adaugă trimiteri între ele și documentează suprapunerile înainte de orice consolidare.”
5. **Dovezi editoriale.** „Pentru paginile de servicii, adaugă numai studii de caz cu permisiune și dovezi existente. Notează anul, tipul beneficiarului, rolul FABER, rezultatul verificabil și sursa oficială a programului. Leagă studiul din serviciul relevant și validează datele vizibile față de schema.”
6. **Reverificare tehnică.** „După publicare, verifică noul URL, e-DRIVE și cele trei canonice semnalate în URL Inspection. Confirmă 200, canonical propriu, indexare permisă, linkuri interne și sitemap. Verifică HTML-ul servit fără JavaScript, datele structurate și afișarea mobilă. După un test live reușit, solicită indexarea paginii noi și a canonicelor actualizate care necesită recrawl. Compară fereastra de 28 de zile cu perioada anterioară.”

## Sugestii pentru creșterea traficului și a citărilor

1. Publică primele date ale fiecărui program în HTML. Pentru grant, intensitate, județe, termen și codul apelului, adaugă lângă tabel linkul la documentul aplicabil și data verificării. Folosește aceeași informație în rezumat, tabel și metadate.
2. Adaugă câte un exemplu propriu cu ipoteze explicite pentru fiecare intenție cu cerere. Începe cu două vehicule e-DRIVE, proiectul ERP din Centru și o exploatație cu calcul SO. Prezintă unitățile, plafoanele și sursele formulelor, astfel încât cititorul să poată reproduce calculul.
3. Publică actualizări punctuale când se schimbă ghidul sau calendarul. Păstrează URL-ul programului, adaugă un istoric scurt și actualizează legăturile din hub-uri și ghiduri. Leagă de documente pe nume și secțiune.
4. Leagă ghidurile cu puține trimiteri de o pagină relevantă. Începe cu cele trei răspunsuri din `/intrebari/`, articolul fotovoltaic AFIR și ghidurile de CAEN. Folosește text de ancoră care descrie întrebarea la care răspunde pagina.
5. Păstrează accesul crawlerelor de căutare la HTML prin robots și Cloudflare. Urmărește răspunsurile reale ale crawlerelor verificate și măsoară LCP, INP și CLS în teste controlate până când apar date de teren. [Google AI Search](https://developers.google.com/search/docs/appearance/ai-features) · [Acces pentru ChatGPT Search](https://help.openai.com/en/articles/12627856-publishers-and-developers-faq)
6. Măsoară pe URL la 28 și 90 de zile. Pentru Google folosește impresii, clicuri, CTR și poziție, plus afișările din raportul AI Search. Pentru Bing folosește citările pe pagină și interogările de referință, iar pentru ChatGPT urmărește sesiunile cu `utm_source=chatgpt.com`. Ține separat un eșantion fix de întrebări în română și înregistrează proporția răspunsurilor care citează pagina. [Google Search Console](https://developers.google.com/search/blog/2026/06/gen-ai-performance-reports) · [Bing AI Performance](https://blogs.bing.com/webmaster/2026/2/Introducing-AI-Performance-in-Bing-Webmaster-Tools-Public-Preview/) · [Referințe ChatGPT](https://help.openai.com/en/articles/12627856-publishers-and-developers-faq)
