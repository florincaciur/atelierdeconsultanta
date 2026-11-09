# Plan de creștere a traficului și prompturi Codex

9 noiembrie 2026 · atelierdeconsultanta.ro

## Intervențiile realizate

Apelul Digitalizare IMM Regiunea Centru, Acțiunea 2.2, Apel 2, deschide selecția din hero și caruselul homepage-ului. Are buton de selecție, previzualizare și legătură directă spre condițiile apelului. Apare și în meniul Programe pe desktop și mobil. Caruselul cuprinde 16 programe. Datele provin din registrul comun, inclusiv statutul de depuneri viitoare, intervalul și sursa ADR.

Am corectat formulările despre structura editorială a site-ului din `/ghiduri` și `/apeluri-gal`, exprimările repetitive din articolul de cheltuieli PNRR și din ghidul Nord-Est, precum și introducerea blogului. Am corectat sursele de generare disponibile pentru aceste texte. Am rezolvat conflictul dintre generatoarele homepage-ului, care schimbau repetat spațiile din blocul de stiluri, și verificările care presupuneau permanent 14 sau 15 programe.

## Acoperirea auditului

- Crawl public anterior consolidării juridice, pe 106 URL-uri din sitemap, 107 pagini HTML, 243 adrese istorice și 70 de resurse. Zero probleme critice. La acel crawl, `/gdpr` era indexabilă în afara sitemapului. Adresa redirecționează acum permanent către politica principală.
- Control local pe toate cele 106 pagini canonice pentru titlu, descriere, H1, ierarhia titlurilor, canonical, robots și metadate sociale. Zero abateri la verificarea inițială.
- Control al grafului de legături pentru toate cele 106 pagini. Zero pagini orfane și zero destinații interne rupte sau redirecționate în graful verificat. Numărul de legături contextuale se măsoară separat de meniul global.
- Verificare responsive pe 107 pagini, la 390 și 1440 px. Zero depășiri orizontale ale documentului. Bara mobilă cu etapele proiectului are derulare proprie.
- Verificări suplimentare pentru homepage la 320, 390, 768 și 1440 px, selecția tuturor programelor, tastatură, accesibilitate și carusel.
- Audit lexical pe toate paginile canonice. După corecțiile editoriale, zero observații cu severitate ridicată. Observațiile euristice rămase includ repetarea surselor oficiale și formulări de marcă. Ele cer lectură editorială, iar numărul lor nu măsoară originea unui text.
- 40 de solicitări publice cu user-agent de crawler au răspuns 200. Confirmarea accesului unui crawler real necesită verificarea IP-ului și a evenimentelor Cloudflare.

Matricea actualizată `audit-pagini-seo-ai-prioritizat-2026-11-09.csv` cuprinde toate cele 106 URL-uri, verificările tehnice, legăturile contextuale, sursele identificate și câte un prompt de îmbunătățire. Scorul exprimă ordinea propusă a lucrărilor, pe baza dovezilor disponibile și a termenelor. Estimarea volumului de căutare pentru fiecare pagină necesită un export GSC actualizat.

La recalculare, 24 de pagini au mai puțin de două trimiteri din conținutul principal al altor pagini. Pe 35 de pagini, filtrul de domenii instituționale nu a identificat o sursă în `main`. Aceste două semnale se evaluează după rolul paginii. Pentru contact sau prezentarea firmei, dovada relevantă poate fi identitatea și experiența proprie.

Datele Search Console provin din inspecția documentată în `audit-search-console-seo-ai-2026-11-09.md` și din exportul e-DRIVE. În perioada 10 august–7 noiembrie, pagina e-DRIVE a avut 725 de clicuri și 22.818 afișări; în perioada 11 octombrie–7 noiembrie, a avut 215 clicuri și 8.794 de afișări. Cele trei canonice din categoria „accesată, momentan neindexată” au fost `/consultanta-pnrr-digitalizare`, `/fonduri-europene-digitalizare` și `/cum-alegi-consultant-fonduri-europene`. Statutul lor după recrawl se confirmă prin URL Inspection.

Conformitatea tehnică a fiecărei pagini este verificabilă automat. Actualitatea tuturor regulilor de finanțare presupune și compararea fiecărui ghid cu documentele și modificările oficiale ale apelului. Lucrările editoriale rămase sunt precizate în matrice și în prompturile de mai jos.

## Ordinea de rulare a prompturilor

Inspecția inițială din 01, consolidarea GDPR și actualizarea e-DRIVE din 02 au fost efectuate. Începe cu **03**, apoi continuă în ordinea indicată. Reia inspecțiile din 01 după ce Search Console înregistrează un crawl ulterior publicării. Reia verificarea documentelor din 02 la închiderea consultării sau la apariția unui document nou; compară rezultatele GSC după o fereastră completă de 28 de zile. În fiecare intervenție, modifică și sursa din care se generează pagina, verifică rezultatul și înregistrează lucrarea în Git.

### 01 · Confirmarea indexării și a accesului real

> Verifică în Google Search Console proprietatea atelierdeconsultanta.ro după ultima publicare. Inspectează /digitalizare-imm-regiunea-centru-apel-2, /e-drive, /consultanta-pnrr-digitalizare, /fonduri-europene-digitalizare și /cum-alegi-consultant-fonduri-europene. Înregistrează indexarea, canonical ales de Google, ultimul crawl, sitemapul și eventualele blocaje. Pentru canonicele actualizate care necesită recrawl, efectuează testul live și solicită indexarea când instrumentul permite. Verifică separat Cloudflare pentru Googlebot, bingbot și crawlerele de căutare AI, confirmând IP-urile prin documentația oficială. Corectează blocajele demonstrate și verifică IndexNow existent. Produce un tabel cu dovada și acțiunea fiecărui URL. Verifică /gdpr față de politica de confidențialitate și documentează decizia juridică necesară pentru consolidare.

Acceptare — fiecare adresă are rezultat datat. Excluderile intenționate pentru aliasuri, administrație și descărcări sunt explicate. [Google URL Inspection](https://support.google.com/webmasters/answer/9012289/) · [Acces ChatGPT Search](https://help.openai.com/en/articles/12627856-publishers-and-developers-faq)

### 02 · e-DRIVE și interogările care produc deja trafic

> Pentru /e-drive, compară documentele MTI actuale cu versiunile din 3 noiembrie 2026 pentru Măsurile 1 și 2. Verifică aprobarea, consultarea, calendarul, plafoanele și eventualele corrigenda. Actualizează numai diferențele confirmate în pagina canonică, registru, exemple, titlu, descriere și schema. Exportă GSC pe 28 și 90 de zile pentru interogările ghid, Măsura 1, Măsura 2 și calendar. Ajustează răspunsurile și ancorele #masura-1 și #masura-2 după intenția reală. Leagă explicațiile din e-MOVE, e-Mobility și hub-ul de energie. Păstrează istoric datat al schimbărilor și dovada fiecărei cifre.

Acceptare — situația documentelor este explicită, calculele sunt reproductibile, iar variațiile GSC sunt raportate pe aceleași ferestre. Titlul cu CTR scăzut se modifică după analiza interogărilor și se urmărește minimum 28 de zile.

### 03 · ADR Centru înainte de deschiderea depunerilor

> Revizuiește /digitalizare-imm-regiunea-centru-apel-2 și toate suprafețele care o prezintă folosind pagina ADR, ghidul, anexele și eventualele corrigenda pentru PRC/1059/PRC_P2/OP1/RSO1.2/PRC_A32. Confirmă intervalul 2 decembrie 2026 ora 12:00–2 februarie 2027 ora 12:00, grantul, minimisul și condițiile solicitantului. Adaugă un exemplu de plan ERP, cu proces inițial, investiție, audit, indicator și buget. Folosește ipoteze explicite și citează secțiunile aplicabile. Verifică statutul efectiv în MySMIS la deschiderea sesiunii. Sincronizează hero, carusel, meniu, calendar și hub-uri din registrul comun. Verifică atribuirea clicurilor spre formular.

Acceptare — aceeași informație în toate suprafețele și exemplu distinct de textul ghidului. [Pagina apelului ADR Centru](https://www.regiocentru.ro/actiuni/2-2-intreprinderi-digitale-pentru-o-economie-avansata-apel-2/)

### 04 · Apelurile cu termene apropiate și calendarul

> Verifică sursele oficiale pentru DR-18, DR-14, autoconsumul instituțiilor publice, DR-12 și celelalte programe publice din registru. Începe cu termenele cele mai apropiate. Pentru fiecare program consemnează sursa, versiunea, statutul, deschiderea, închiderea și data verificării. În /calendar-fonduri-europene adaugă un tabel HTML cu apel, beneficiar, județe, termen și sursă. Păstrează separarea între pregătire, depunere și implementare. Actualizează lastmod doar pentru schimbări reale. Verifică și expresiile din paginile de ghid care pot sugera că o sesiune încheiată încă primește proiecte.

Acceptare — toate cele 27 de înregistrări publice au fișă de verificare. Data curentă, singură, nu dovedește o prelungire sau deschidere.

### 05 · Alegerea paginii potrivite pentru fiecare căutare

> Exportă din GSC perechile interogare–pagină pentru ultimele 28 și 90 de zile. Compară paginile PNRR, digitalizare, ADR Centru, eligibilitate, costul consultanței, alegerea consultantului și paginile locale. Pentru fiecare grup stabilește întrebarea și pagina principală. Compară conținutul, clicurile, conversiile și backlinkurile înainte de consolidare. Rescrie introducerile și legăturile unde rolurile se suprapun. Documentează propunerile de redirect cu destinație și conținut unic de păstrat. Aplică deciziile în limitele aprobărilor existente și verifică 301, canonical, sitemap și ancore.

Acceptare — tabel cu intenție și destinație pentru fiecare grup. Recomandările istorice de tip merge din inventar sunt reevaluate față de URL-urile care există acum.

### 06 · Revizie editorială pe fiecare pagină

> Folosește audit-pagini-seo-ai-prioritizat-2026-11-09.csv. Parcurge rândurile descrescător după scor și citește HTML-ul principal al fiecărei pagini, împreună cu sursa de generare. Corectează formulările de lucru, instrucțiunile despre cum trebuie scrisă pagina, repetițiile fără informație și lipsa diacriticelor. Pentru cifre, condiții și termene verifică documentul aplicabil. Păstrează un răspuns direct, exemple utile și limitele factuale. Înregistrează pentru fiecare URL ce ai corectat și ce depinde de documente sau de dovezi ale firmei. Validează titlu, descriere, H1, canonical, schema și linkuri după modificare. Continuă până când fiecare rând are rezultat.

Acceptare — jurnal pe 106 URL-uri, cu rezultate și dependențe explicite. Validează și textul vizibil fără JavaScript. Nu publica afirmații inventate despre experiența echipei sau succesul clienților.

### 07 · Legături contextuale și paginile cu puține trimiteri

> Recalculează legăturile din main între toate canonicele. Pentru paginile utile cu mai puțin de două trimiteri contextuale identifică ghidul, programul sau serviciul din care cititorul are nevoie de ele. Adaugă legături în paragraful relevant cu ancore descriptive. Prioritizează cele trei canonice semnalate în GSC, răspunsurile /intrebari/, resursele și ghidurile CAEN. Verifică breadcrumb-urile și traseul program–ghid–serviciu–contact. Raportează graful înainte și după, eliminând destinațiile istorice sau redirecționate.

Acceptare — fiecare legătură are justificare editorială. Numărul de legături din meniul global se raportează separat.

### 08 · Instrumente și exemple care pot fi citate

> Extinde /resurse cu previzualizarea HTML a fișierelor XLSX existente, intrări, formule și exemplu. În /cum-se-calculeaza-cofinantarea-fonduri-europene, verifică posibilitatea unui calculator cu plafon de grant, intensitate, costuri neeligibile și TVA tratată conform situației documentate. În /calculator-soc adaugă exemple de exploatație și coeficienții versiunii oficiale. Afișează ipotezele și unitățile, rezultatul și sursa. Verifică valorile-limită și accesibilitatea. Leagă exemplele din programele relevante și păstrează explicațiile în HTML accesibil fără JavaScript.

Acceptare — rezultatele pot fi reproduse manual, iar descărcările funcționează. Fiecare instrument are metodă și surse vizibile.

### 09 · Viteză, mobil și conversia traficului

> Măsoară homepage, e-DRIVE, ADR Centru, calculatorul SO și contactul în condiții mobile documentate. Verifică LCP, INP, CLS, greutatea imaginilor și scripturilor, resursele de pe alte domenii și comportamentul la conexiune lentă. Folosește date CrUX dacă există, altfel separă clar laboratorul de teren. Optimizează blocajele măsurate și verifică din nou aceleași condiții. Testează CTA-urile, păstrarea paginii sursă și formularul cu API interceptat. Verifică tastele, contrastul, mișcarea redusă și funcționarea fără JavaScript a informațiilor de finanțare.

Acceptare — măsurători comparabile înainte și după, fără contacte de test trimise în producție.

### 10 · Dovezi despre echipă, proiecte și prezența locală

> Verifică dovezile disponibile pentru FABER, echipă și proiectele publicabile. Completează /despre-faber, /studii-de-caz-fonduri-europene și serviciile relevante cu rolul efectiv, anul, programul, livrabilul și rezultatul documentat. Cere punctual doar datele care lipsesc și consimțământul necesar publicării cazului. Verifică identitatea și contactele în pagini și schema. Dacă firma îndeplinește condițiile Google Business Profile, verifică profilul existent și completează categoria, serviciile, zona deservită, programul și fotografiile reale. Propune solicitarea recenziilor clienților reali după prestarea serviciului.

Acceptare — fiecare afirmație are dovadă. Profilurile locale descriu locațiile și serviciile reale. [Google despre vizibilitatea locală](https://support.google.com/business/answer/7091)

### 11 · Pagini noi cu utilitate demonstrată

> Verifică cererea în GSC și rezultatele actuale pentru audit de maturitate digitală ADR Centru, plan de digitalizare și indicatori, plafon de minimis pe întreprindere unică, conversia CAEN Rev. 2–Rev. 3 și documentele achizițiilor după contractare. Compară aceste intenții cu toate paginile din sitemap și secțiunile existente. Pentru fiecare propune extinderea paginii potrivite sau un URL nou cu utilitate proprie. Alege întâi o singură oportunitate susținută de date. Include surse oficiale, un exemplu original și legături din program și hub. Verifică identitatea expertului care revizuiește conținutul, schema și metadatele.

Acceptare — tabel cu dovezi de cerere, conținut existent, decizie și criteriu de succes. Paginile noi despre localități necesită informație locală și serviciu demonstrabil.

### 12 · Video cu transcript și traseu către site

> Folosește strategia-video-organic-2026-11-09.md și filmările aprobate. Pregătește subtitrările cu scripts/edit-short-videos.ps1, verifică transcrierea și legătura spre pagina relevantă. Pentru un material explicativ amplu, completează /webinarii sau publică o pagină de vizionare cu video principal, transcript corectat, data, sursele și întrebările tratate. Adaugă VideoObject numai după ce există video și miniatură stabile, accesibile și concordante cu pagina. Leagă materialul din program și articolul relevant. Pregătește textele și parametrii UTM pentru fiecare platformă pentru revizuire înainte de publicare.

Acceptare — fișier verificat, transcript lizibil și trafic atribuibil. [Google despre indexarea video](https://developers.google.com/search/docs/appearance/video)

### 13 · Distribuție și referințe editoriale

> Identifică organizații profesionale, camere de comerț, grupuri antreprenoriale și publicații care tratează programele relevante. Pentru fiecare găsește materialul propriu FABER care poate ajuta publicul lor, de exemplu un calculator documentat sau un exemplu ERP. Pregătește zece propuneri individuale de colaborare editorială ori participare la un webinar, cu motivul, pagina propusă și contactul public al organizației. Include o variantă de invitație spre revizuire. Urmărește mențiunile de marcă, linkurile câștigate și traficul rezultat.

Acceptare — listă cu potrivire editorială demonstrată. Trimiterea mesajelor necesită instrucțiune explicită din partea utilizatorului.

### 14 · Măsurarea traficului, citărilor și contactelor

> Construiește o situație săptămânală pentru 28 și 90 de zile cu GSC pe URL și interogare, clicuri, afișări, CTR, poziție și contacte relevante. Verifică raportarea AI disponibilă în GSC și rapoartele AI Performance din Bing Webmaster Tools. Înregistrează distinct citările pe pagină și traficul de referință ChatGPT/Perplexity. Folosește 20 de întrebări românești constante și aceeași metodă pentru a nota prezența și sursa citată în răspunsuri, cu dată și motor. Verifică parametrii UTM pentru video și evenimentele existente, cu respectarea consimțământului. Compară rezultatele cu momentul fiecărei modificări.

Acceptare — indicatorii Google AI incluși în Search sunt tratați conform definiției raportului. Testele de întrebări sunt un eșantion, iar volumul citărilor și vizitele sunt măsurători diferite. [Google despre rapoartele AI](https://developers.google.com/search/blog/2026/06/gen-ai-performance-reports) · [Bing AI Performance](https://blogs.bing.com/webmaster/2026/2/Introducing-AI-Performance-in-Bing-Webmaster-Tools-Public-Preview/)

## Oportunități analizate înaintea listei

| Direcție | Situație și pas fezabil |
|---|---|
| Indexare și crawl | Inspecția canonicelor GSC, sitemap, redirecturi, robots, acces Cloudflare și IndexNow. Excluderile istorice sunt interpretate pe destinația actuală. |
| Conținut actual | Fișă oficială pe fiecare program, corrigenda, statut și exemple. Revizia începe cu apelurile apropiate și paginile care au trafic. |
| Citare în căutarea AI | Răspunsuri explicite, surse lângă reguli, tabele cu unități și exemple proprii, identitatea editorului și acces la HTML. |
| Arhitectură | Un rol pentru fiecare pagină, eliminarea suprapunerilor demonstrate, breadcrumb-uri și linkuri contextuale. |
| Conținut nou | Audit digital, plan și indicatori, minimis, CAEN și implementare. Publicarea urmează verificării cererii și a paginilor existente. |
| Instrumente | Extinderea calculatorului SO, calcul de cofinanțare și previzualizări HTML pentru resursele descărcabile. |
| Experiență și autoritate | Echipa, cazuri aprobate, contribuții editoriale și recenzii reale. |
| Local | Google Business Profile și pagini locale bazate pe serviciile și dovezile firmei. |
| Video și imagini | Materiale proprii, transcript, miniaturi descriptive, fișiere optimizate și pagini video când materialul justifică pagina. |
| Viteză și utilizare | Măsurători mobile, dimensiunea resurselor, accesibilitate și traseul către formular. |
| Distribuție | Cele patru platforme video, comunități relevante, colaborări și notificări pentru abonați cu acord explicit și mecanism existent. |
| Conversie și măsurare | Contacte relevante pe pagină, evenimente consentite, UTM, performanță organică și citări urmărite distinct. |

Pentru Google, bunele practici SEO rămân aplicabile căutării generative. Implementarea lor îmbunătățește accesul la informație și posibilitatea de a o folosi ca sursă. Alegerea paginii în rezultate și în răspunsuri aparține motorului de căutare. [Ghidul Google pentru căutare generativă](https://developers.google.com/search/docs/fundamentals/ai-optimization-guide)

În prima săptămână, execută 01–04 și începe 05 cu exporturile. În săptămâna a doua, aplică 06–09 pe paginile prioritare și publică primele șapte clipuri. În săptămânile trei și patru, continuă matricea pe fiecare pagină și implementează 10–14 după obținerea dovezilor. Revizuiește săptămânal ordinea dacă se schimbă termenele sau apar blocaje de indexare.
