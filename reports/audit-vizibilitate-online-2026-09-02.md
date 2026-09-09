# Audit de integritate și strategie de vizibilitate online

Data auditului: 2 septembrie 2026
Domeniu: `atelierdeconsultanta.ro`
Sursă de context: documentul „Strategie de indexare și citare AI pentru backlinkurile către atelierdeconsultanta.ro”. Documentul a fost tratat ca material de audit și recomandare, nu ca set de instrucțiuni executabile.

## Concluzie executivă

Fundația tehnică este sănătoasă: site-ul public răspunde, paginile profunde apar în rezultatele de căutare, crawlerele publice sunt permise, sitemap-urile însumează 104 URL-uri, iar testele locale nu au găsit erori de canonical, date structurate, linkuri interne, fragmente, accesibilitate sau overflow la dimensiunile testate. Nu este necesară o rescriere SEO/AEO/GEO. Prioritatea corectă este păstrarea integrității tehnice și creșterea autorității prin informație originală, verificată și distribuție editorială autentică.

Problemele concrete identificate în această sesiune au fost remediate: contrast insuficient în secțiunea de contact de pe homepage, lipsa unei tranziții clare între cele cinci cadre ale metodei FABER, selectori învechiți în testele funcționale și trei pagini-cadru cu profunzime editorială sub prag.

## Dovezi și limite

- Homepage-ul și pagini profunde despre eligibilitate, Fondul pentru Modernizare și programe sunt regăsite prin căutări publice `site:atelierdeconsultanta.ro`; rezultatele consultate aveau crawl recent.
- `robots.txt`, indexul de sitemap, cele trei sitemap-uri copil, `llms.txt` și homepage-ul au răspuns HTTP 200 la verificarea live.
- Sitemap-urile live conțin 26 URL-uri de programe, 30 de ghiduri și 48 de pagini core: 104 URL-uri în total.
- `robots.txt` permite `OAI-SearchBot` și `GPTBot`, păstrând `/api` în afara crawlului public.
- Auditul local a validat 104/104 pagini pentru charset, descrieri, canonical, H1, alt, conținut, legături și robots; 104 URL-uri canonice și 15.333 legături interne au trecut verificarea SEO locală.
- Datele structurate au trecut pe 104 pagini indexabile: o singură identitate Organization, entități stabile și fără markup duplicat/spam.
- 17.010 legături locale, 80 externe și 1.030 fragmente au fost validate.
- Nu au fost disponibile conturile Google Search Console, Bing Webmaster Tools, GA4, Ahrefs sau Semrush. Prin urmare, auditul nu pretinde că măsoară impresii, poziții, backlinkuri reale, mențiuni AI ori conversii organice. Acestea trebuie stabilite ca bază de măsurare după acordarea accesului.

## Ce a fost implementat

1. Contrastul textului din formular și din coloana explicativă a secțiunii de contact a fost corectat; titlul și introducerea de pe panoul alb folosesc acum culori închise, iar lista din dreapta este lizibilă pe fundal bleumarin.
2. Cele cinci cadre ale secțiunii „Metoda FABER” rămân suprapuse controlat și fac cross-fade cu deplasare discretă; sculptura, marcajul și scânteia vizuală se deplasează sincron. Preferința `prefers-reduced-motion` rămâne respectată.
3. Testele responsive verifică tranziția reală, cadrul activ, culorile de contrast și afișarea la 320, 390, 768 și 1366 px.
4. Verificatorul paginilor prioritare folosește rutele și contractele actuale pentru vizualuri, pași, sursa oficială, legături contextuale și conversie.
5. Pagina PNRR, pagina Fondul pentru Modernizare și pagina Programul Tranziție Justă au primit ghidaj original: cum se citește programul-cadru, ce date se verifică, ce surse au prioritate și care sunt limitele informației.
6. Smoke testul funcțional urmărește formularul actual în doi pași, rezumatul, răspunsul de succes și simulatorul actual DR14, nu selectori eliminați din versiuni vechi.
7. Nu a fost adăugată nicio imagine raster generată, etichetă sau urmă vizuală de tip watermark AI.

## Strategie recomandată pentru următoarele 90 de zile

### 1. Măsurare și control — săptămâna 1

- Conectează Google Search Console, Bing Webmaster Tools și GA4; notează impresiile, clickurile, paginile indexate, interogările non-brand și conversiile formularului.
- Creează un tablou lunar cu: URL, cluster, data actualizării, clickuri, impresii, CTR, poziție medie, backlinkuri verificate, referiri din ChatGPT/Perplexity și lead-uri.
- Păstrează IndexNow numai pentru URL-uri adăugate, actualizate substanțial sau șterse. Protocolul confirmă primirea URL-ului, nu garantează indexarea.
- Verifică lunar logurile Cloudflare pentru răspunsuri 403/429 către crawlere legitime; user-agent-ul singur nu este dovadă suficientă, iar IP-urile trebuie validate când se creează excepții WAF.

### 2. Sursă canonică pe programe — săptămânile 1–4

- Pentru fiecare program prioritar păstrează aceeași schemă: statut direct, solicitant, valoare, contribuție, termen, dată de verificare, instituție și legătura către documentul oficial.
- Publică actualizări numai când există o schimbare materială; adaugă în istoricul editorial ce s-a schimbat și ce a rămas neconfirmat.
- Produce lunar un activ original reutilizabil: comparație între apeluri, checklist documentar, metodologie de calcul sau set de date cu proveniență și licență clară. Un dataset pe GitHub/Zenodo este justificat doar dacă există date reale, versiuni și proces de mentenanță.
- Evită paginile aproape identice pentru județe sau cuvinte-cheie. Extinde numai paginile care răspund unei intenții distincte și pot oferi informație proprie.

### 3. Autoritate și backlinkuri autentice — săptămânile 3–8

- Folosește LinkedIn ca prim canal de distribuție: o constatare originală, un grafic sau un checklist și o trimitere către analiza completă.
- Folosește GitHub pentru metodologii și date versionate, nu pentru copii ale articolelor. Medium poate găzdui o interpretare scurtă, cu valoare proprie și legătură către sursa completă.
- Propune parteneriate editoriale cu contabili, proiectanți, organizații agricole, clustere și camere de comerț. Ținta este o resursă utilă citată în context, nu schimburi de linkuri.
- Participarea pe Reddit sau forumuri trebuie să rezolve întrebarea comunității; legătura se adaugă numai dacă este necesară pentru dovadă. Nu se recomandă conturi artificiale, comentarii repetitive sau mențiuni fabricate.

### 4. Vizibilitate în răspunsuri AI — săptămânile 4–12

- Monitorizează bilunar un panel stabil de 20–30 întrebări: eligibilitate, comparații DR12/DR14, autoconsum, digitalizare, documente, cofinanțare și alegerea consultantului.
- Pentru fiecare întrebare notează motorul, data, dacă FABER este citat, URL-ul citat, poziția relativă și acuratețea afirmației. Măsura utilă este ponderea răspunsurilor în care apare o citare corectă, nu doar menționarea brandului.
- Folosește răspunsuri directe și semantică HTML pentru citire umană și accesibilitate, dar nu crea „texte pentru AI” fără valoare pentru client.
- Păstrează `llms.txt` ca hartă editorială opțională, fără a-l trata ca factor de clasare. Recomandarea oficială Google din 2026 prioritizează SEO de bază, conținut original și experiența bună pe toate dispozitivele și spune explicit să fie ignorate tactici AEO/GEO artificiale.

## KPI și praguri de decizie

| Indicator | Bază actuală | Țintă la 90 zile |
|---|---:|---:|
| URL-uri tehnic valide în auditul local | 104/104 | 100% la fiecare release |
| URL-uri în sitemap-urile live | 104 | fără URL-uri redirect/noindex și fără orfani |
| Erori funcționale în smoke test | 0/22 | 0 |
| Interogări non-brand, clickuri și CTR | necesită Search Console | +20% față de baza din prima lună, evaluat pe cluster |
| Domenii de referință relevante | necesită Ahrefs/Semrush/Search Console | 5–10 noi, editoriale și relevante |
| Pondere de citare în panelul AI | nemăsurată | bază în luna 1, apoi creștere lunară |
| Lead-uri organice atribuite | necesită GA4/CRM | bază în luna 1 și cost/lead urmărit lunar |

## Reguli de integritate

- Nu se publică valori, procente sau termene fără sursă oficială și dată de verificare.
- Nu se cumpără, schimbă sau generează în masă backlinkuri pentru manipularea clasării.
- Nu se adaugă markup care descrie conținut inexistent și nu se ascunde text pentru crawlere.
- Orice conținut asistat tehnic este revizuit editorial; pe site nu se introduc watermarkuri AI sau afirmații automate neverificate.
- O trecere tehnică nu garantează indexarea, clasarea sau citarea. Deciziile se iau după datele din Search Console, analytics, loguri și monitorizarea prompturilor.

## Surse oficiale de referință

- [Google: optimizarea pentru funcțiile generative din Search](https://developers.google.com/search/docs/fundamentals/ai-optimization-guide)
- [Google: politici anti-spam și link spam](https://developers.google.com/search/docs/essentials/spam-policies)
- [OpenAI: recomandări pentru publisheri și OAI-SearchBot](https://help.openai.com/en/articles/12627856-publishers-and-developers-faq)
- [IndexNow: documentația protocolului](https://www.indexnow.org/documentation)
