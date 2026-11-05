# Audit și remedieri FABER — 5 noiembrie 2026

Raportul principal este [audit-after.html](audit-after.html), cu căutare și filtre. Există și [versiunea Markdown](audit-after.md), [tabelul CSV](audit-after.csv) și [inventarul verificabil JSON](pages-after.json).

## Acoperire

- 106 pagini publice: toate cele 105 URL-uri din sitemap, plus `/gdpr`.
- 183 de surse/variante HTML excluse, enumerate separat cu motiv și acțiune recomandată; între acestea există duplicate, redirecturi, șabloane și documente tehnice.
- Toate cele 15 URL-uri din captura GSC, verificate individual în [gsc-before.json](gsc-before.json).
- Crawl tehnic inițial: 106 pagini HTML, 69 resurse interne, 105 URL-uri sitemap.
- Evaluarea fiecărei pagini include titlu, descriere, celelalte metadate, SEO, AEO, GEO, Bing/citare, afișare, limbaj și aspect. Recomandările sunt distincte de modificările efectiv publicate.

## Modificări aplicate

1. **Hero desktop și mobil:** înălțime determinată de conținut, spațiu sub header, panou aliniat sus, texte fără limitare artificială la două rânduri, controale de minimum 44/48 px și fonturi mai lizibile. Lista integrală a celor 15 programe rămâne în HTML. CSS-ul are o versiune nouă pentru actualizarea cache-ului.
2. **Fișiere auxiliare GSC:** `X-Robots-Tag: noindex, follow` pentru fișierele Excel din `/resurse/descarcari/`. Acestea rămân accesibile pentru descărcare și pentru crawl. JSON-ul avea deja `noindex`; nu a fost blocat suplimentar prin robots.txt.
3. **Metadate:** nouă pagini prioritare au titluri și descrieri revizuite în sursa configurată. Open Graph și Twitter se sincronizează pentru toate paginile din configurația snippet-urilor, nu doar pentru trei rute. Validatorul recunoaște acronimele tehnice SF, DALI, DTAC și PT.
4. **Proiectare:** comparație între SF, DALI, DTAC și PT/DE; datele necesare unei oferte; livrabile verificabile pentru SF; CTA de ofertare și legături contextuale din consultanța AFIR. Nu au fost inventate proiecte, persoane, acreditări sau rezultate.
5. **Conținut util pe paginile GSC:** separarea proiectelor PNRR contractate de finanțările noi; exemplu de buget ERP; datele inițiale pentru AFIR; diferența dintre utilaje și lucrări; comparația ofertelor de consultanță după livrabile.
6. **Limbaj și repetiții:** normalizatorul elimină metatextul despre construirea paginii și paragrafele identice repetate în același articol. Repetările exacte excedentare de peste 100 de caractere au scăzut de la 83 la 14; cele rămase sunt în principal răspunsuri/rezumate reutilizate în componente independente și necesită judecată editorială, nu ștergere automată.
7. **Prevenirea regresiilor:** sincronizarea informațiilor noi intră în build; testul hero verifică geometria și selecția tuturor programelor; verificarea producției testează și directivele live ale Excel/JSON.

## Interpretarea celor 15 URL-uri GSC

| URL raportat | Constatare și tratament |
|---|---|
| `/resurse/descarcari/calendar-pregatire-depunere.xlsx` | HTTP 200; lipsea `noindex`. Adăugat prin header, cu descărcarea păstrată. |
| `/resurse/descarcari/buget-digitalizare-imm.xlsx` | HTTP 200; lipsea `noindex`. Același tratament. |
| `/consultanta-pnrr-digitalizare` | HTTP 200, self-canonical, indexabilă. Conținut și metadate clarificate pentru implementare vs. finanțare nouă. |
| `/consultanta-pnrr-digitalizare/` | Avea deja 301 direct la varianta fără slash. Această variantă nu trebuie indexată separat. |
| `/consultanta-afir/` | Avea deja 301 direct; ținta a primit conținut și metadate mai specifice. |
| `/cum-alegi-consultant-fonduri-europene/` | Avea deja 301 direct; ținta a primit un exemplu concret de comparare a ofertelor. |
| `/official-guides.json` | HTTP 200 și deja `X-Robots-Tag: noindex, nofollow`; resursă auxiliară, nu pagină comercială. |
| `/fonduri-europene-digitalizare` | HTTP 200, self-canonical, în sitemap; păstrată ca hub distinct de PNRR și de consultanță. |
| `/firma-consultanta-fonduri-europene/` | Avea deja 301 direct; metadatele țintei clarifică intenția de servicii/comparare. |
| `/start-up-nation-2026-plan-de-afaceri/` | Avea deja 301 direct; metadatele țintei descriu structura planului. |
| `/consultant-fonduri-europene-imm/` | Avea deja 301 direct; titlu și descriere revizuite pentru serviciul IMM. |
| `/granturi-digitalizare-imm/` | Avea deja 301 direct la `/digitalizare-imm`; nu a fost recreată o pagină concurentă. |
| `/cum-alegi-consultant-fonduri-europene` | HTTP 200, self-canonical; îmbunătățiri pe aceeași țintă ca varianta cu slash. |
| `/fonduri-europene-femei-antreprenor/` | Avea deja 301 direct; ținta rămâne hub distinct de pagina programului. |
| `/fonduri-europene-nerambursabile-2026/` | Avea deja 301 direct; titlu și descriere revizuite pentru compararea programelor. |

„Crawled — currently not indexed” nu identifică singur o cauză tehnică unică. La începutul auditului, paginile HTML finale de mai sus erau accesibile și indexabile. Repetitivitatea și suprapunerea intențiilor pot contribui la selecția Google, dar această legătură este o inferență editorială, nu o cauză confirmată prin URL Inspection. Pentru Excel/JSON, rezultatul urmărit este excluderea corectă din index, nu obținerea indexării.

## Validare și limite

- [responsive.json](responsive.json): toate cele 106 pagini la 390 și 1440 px, 212 verificări de geometrie. Fără depășiri laterale ale documentului sau H1 acoperit de header. Caruselul de etape are controale în afara ferestrei sale de derulare locală; acestea nu produc scroll lateral al paginii.
- [hero-local.json](hero-local.json): 11 configurații între 320 și 1920 px, inclusiv text mărit la 200%; panoul nu intră sub meniu și nu este tăiat de secțiunea următoare.
- `npm run build` rulează fluxul complet al proiectului, inclusiv date structurate, sitemap, canonical/redirecturi, linkuri, accesibilitate, metadate, conținut și build Cloudflare. Jurnalul rulării este `build.log` în acest director.
- Build-ul complet și validarea Cloudflare au trecut. Poarta P0 locală a decis PASS, fără blocaje critice; păstrează o constatare neblocantă de performanță: baseline-ul INP este încă `DE_VALIDAT_UMAN`. Testele de geometrie și accesibilitate nu sunt prezentate ca dovadă că toate Core Web Vitals sunt bune în trafic real.
- Publicarea se verifică prin commit-ul exact din `/release.json`, prin verificatorul de release și prin repetarea testului hero/directive pe domeniul live. Dovezile ulterioare push-ului se salvează local în acest director.
- Singura constatare a crawl-ului tehnic inițial: `/gdpr` este indexabilă, dar exclusă intenționat din sitemap prin politica existentă. Auditul paginii explică opțiunile de consolidare; textul juridic nu a fost schimbat. Nu face parte din cele 15 URL-uri ale capturii GSC.
- Nu au fost accesate datele private de performanță sau URL Inspection din GSC și nici statisticile AI Performance din contul Bing. Nu sunt raportate valori inventate pentru trafic, poziții, CTR sau citări.
- Auditul conține verificări de structură și geometrie pentru fiecare pagină, nu o evaluare estetică manuală a fiecărui ecran.

## Pașii editoriali cu cel mai mare potențial

Prioritizează dovezi originale pentru serviciile de proiectare: specialiști identificați verificabil, exemple de documentații anonimizate cu acord, rolul exact al FABER, investiția și etapa. Pentru programe, folosește exemplele specifice din fișele individuale: condiții eliminatorii, cheltuieli, calcule de contribuție, documente și motive de respingere documentate.

În GSC urmărește URL-urile canonice, nu variantele 301 și fișierele auxiliare. Pentru paginile importante, verifică URL Inspection după publicare și solicită reindexarea conținutului actualizat, în limita disponibilă. Compară ulterior perioade egale de 28 de zile. În Bing urmărește citările pe URL și Citation Share unde este disponibil; IndexNow notifică schimbările, fără garanția indexării sau citării.

Metodologie: [Google — funcții AI și website-uri](https://developers.google.com/search/docs/appearance/ai-features), [Google — canonicalizare](https://developers.google.com/search/docs/crawling-indexing/canonicalization), [Bing Webmaster Guidelines](https://www.bing.com/webmasters/help/bing-webmaster-guidelines-30fba23a), [Bing — Citation Share și comparații](https://blogs.bing.com/search/2026/6/New-AI-Visibility-Insights-in-Bing-Webmaster-Tools-Intents-Topics-Citation-Share-Compare/).
