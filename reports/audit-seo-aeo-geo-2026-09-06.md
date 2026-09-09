# Audit SEO, AEO și vizibilitate AI — 6 septembrie 2026

## Concluzia auditului

Problemele demonstrabile sunt contradicțiile factuale, informația incompletă pentru anumite întrebări și prezentarea neclară a condițiilor unor programe. Acestea au fost corectate în sursele de generare și propagate în pagini. Nu am identificat un blocaj general de indexare pentru cele șapte URL-uri. Datele disponibile nu permit atribuirea unei poziții Google unei singure cauze și nu justifică promisiunea locului 1.

Am păstrat paginile de program existente și URL-urile lor. O pagină suplimentară despre același program, cu aceeași intenție, ar împărți semnalele între URL-uri fără un beneficiu demonstrat. Comparațiile și răspunsurile noi sunt incluse în paginile canonice.

## Date observate înainte de modificări

Google Search Console, raport Performanță / Web, 7 august–3 septembrie 2026, toate țările și dispozitivele. Valorile au fost citite din interfață în această sesiune; tabelul nu reprezintă un export brut. Total proprietate: 408 clicuri, aproximativ 13.000 afișări, CTR 3,1%, poziție medie 8,4.

| Pagină | Clicuri | Afișări | CTR | Poziție medie |
|---|---:|---:|---:|---:|
| /dr12-afir | 109 | 1.949 | 5,6% | 6,6 |
| /e-drive | 82 | 2.739 | 3,0% | 7,7 |
| /dr14 | 22 | 1.320 | 1,7% | 7,6 |
| /investitii-modernizarea-microintreprinderilor-apel-2 | 7 | 571 | 1,2% | 6,8 |
| /pro-infra | 5 | 67 | 7,5% | 14,1 |
| /diaspora-investeste-acasa | 4 | 254 | 1,6% | 6,6 |
| /e-mobility | 0 | 23 | 0% | 6,9 |

Poziția medie agregă interogări, dispozitive și localizări; nu înseamnă că pagina este în top 10 pentru fiecare căutare. De exemplu, pentru DR12, interogările observate includeau „dr12 ghid final” (82 afișări, poziție 4,0), „dr12 afir lansare” (276, poziție 6,0) și „dr12” (221, poziție 8,2). Răspunsul despre existența ghidului final trebuie să fie explicit și corect.

Cele șapte URL-uri live răspundeau HTTP 200, aveau canonical propriu și nu aveau directivă noindex. Sitemap-ul include 104 URL-uri canonice. Verificarea aceasta nu înlocuiește raportul individual de indexare Google.

## Probleme și remedieri

| Prioritate / pagină | Constatare | Modificarea implementată |
|---|---|---|
| P1 — DR14 | FAQ-ul mai răspundea că sesiunea nu este deschisă, deși AFIR afișează sesiune activă din 1 septembrie. Formulări despre achiziții simple puteau include greșit echipamente cu montaj. | Status deschis, calendar 1 septembrie–31 octombrie, sursă către contorul AFIR; corectate FAQ, rezumate, comparația cu DR12 și JSON-LD. Clarificată nota AFIR din 21 august: montajul/instalarea exclude încadrarea la achiziții simple chiar dacă nu este necesară autorizație de construire. |
| P1 — DR12 | Pagina refuza să ofere valori publicate în documentația consultativă și conținea formulări despre „query” sau aprobări editoriale interne. | Răspuns natural despre ghidul final și lipsa unei sesiuni confirmate; 200.000 EUR, intensități 80%/65% și minimum 12.000 SO prezentate explicit ca reguli consultative. Nicio dată de lansare inventată. |
| P1 — Microîntreprinderi, Apel 2 | CTR 1,2%; rezumatul automat privind beneficiarii folosea categorii generice de IMM, deși apelul este pentru microîntreprinderi. | Beneficiari formulați exact, titlu cu denumirea programului, regiune, apel și an, păstrate condițiile ghidului final și depunerile 28 septembrie–28 octombrie. Simulatorul de punctaj existent rămâne accesibil direct din meniu. |
| P1 — e-DRIVE | Întrebarea despre autoturism electric pe firmă nu era suficient de vizibilă față de plafonul măsurii 2. | Titlu și răspuns despre plafonul M1 de 30.000 EUR; tabel care separă măsurile, solicitanții, vehiculele, 300.000 EUR/întreprindere unică de minimis și 4 milioane EUR/beneficiar la măsura 2. Clarificate baza incrementală, casarea și diferența față de stațiile de reîncărcare. |
| P2 — PRO INFRA | Rezumatele omiteau valori oficiale; formularea generală despre EMS putea ascunde excepția prevăzută de schemă. | Buget 100 milioane EUR, plafon 15 milioane EUR, intensitate maximă posibilă prin competiție; clarificări EMS cu excepția documentabilă, sursă legislativă consolidată. |
| P2 — e-Mobility | Accent pe limita de 40% din buget fără aceeași vizibilitate a plafonului individual; condiții tehnice insuficient de ușor comparabile. | Tabel cu plafon 30 milioane EUR/beneficiar, limita suplimentară de 40%, distanță măsurată pe șosea, excluderea întreprinderilor nou-înființate, puteri pentru vehicule grele cu excepțiile schemei și regula de 75% pentru stocare. |
| P2 — Diaspora | Informație rămasă la anunțul inițial și sursă BID necorespunzătoare; condiții financiare incomplete. | Actualizată pagina după BID: operaționalizare, firmă cu mai puțin de 3 ani, condiția de rezidență, experiență/formare, grant de maximum 200.000 EUR, contribuții 5%/10%/15% în tabel și reducerea creditului după investiție. |
| Comun | Rezumatele AEO preferau etichete de descoperire generice față de eligibilitatea efectivă. | Generatorul folosește descrierea eligibilității din registrul verificat înaintea clasificărilor de navigare. |
| Comun | Logo-ul furnizat este alb pe fundal aproape alb. | Același fișier JPEG original în antetul comun, contrast CSS pe fundalul bleumarin, text alternativ, dimensiuni rezervate și adaptare pentru mobil. |

DR18 a fost actualizat punctual la sesiune deschisă deoarece apare în același meniu, iar aceeași sursă AFIR confirmă perioada; nu este prezentat drept audit complet suplimentar al DR18.

## SEO tehnic și răspunsuri citabile

Corecțiile se aplică atât paginilor, cât și registrelor și generatoarelor, pentru a nu fi pierdute la următorul build. Antetul este sincronizat pe 183 de fișiere HTML publice, inclusiv aliasuri. Metadatele, FAQ-ul vizibil, schema, breadcrumb-urile, legăturile contextuale, feed-ul și sitemap-urile sunt regenerate și verificate de pipeline.

Conținutul esențial rămâne în HTML, cu surse oficiale directe, stadiu și dată de verificare. Tabelele compară criterii concrete. Calendarele, cifrele consultative și regulile finale sunt diferențiate explicit. Calculatorul SO, punctajul DR14 și simulatorul pentru Apelul 2 oferă utilitate practică suplimentară rezumatelor.

Nu există o schemă specială care să garanteze citarea în AI. Google cere indexare și eligibilitate pentru snippet, alături de aceleași bune practici SEO; datele structurate trebuie să corespundă textului vizibil. FAQ-ul rămâne util utilizatorului fără a presupune acordarea de rezultate îmbogățite. [Google Search Central — funcții AI](https://developers.google.com/search/docs/appearance/ai-features), [regulile FAQ](https://developers.google.com/search/docs/appearance/structured-data/faqpage).

## Surse primare verificate

- [DR14 — sesiuni active AFIR](https://depunerepspac.afir.ro/Sesiune/Lista) și [ghid, cerere și note](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/).
- [DR12 — pagina intervenției](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/) și [comunicatul consultării](https://www.afir.ro/comunicate/consultare-publica-pentru-consolidarea-exploatatiilor-tinerilor-fermieri/).
- [Apelul 2 — Autoritatea de Management Nord-Est](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/).
- [e-DRIVE — Ordinul 742/2026](https://legislatie.just.ro/Public/DetaliiDocument/313289).
- [e-Mobility — Ordinul 746/2026](https://legislatie.just.ro/Public/DetaliiDocument/313291).
- [PRO INFRA — schema consolidată](https://legislatie.just.ro/Public/DetaliiDocument/306916).
- [Diaspora — produsul BID](https://www.bidromania.eu/produse/garantii/diaspora-investeste-acasa).

Unele pagini legislative au returnat 502 în instrumentul de căutare; textul a fost verificat și prin solicitare HTTP directă către aceeași sursă oficială.

## Ce nu este demonstrat de acest audit

Nu există suficiente date pentru a atribui pozițiile unei penalizări, unui deficit măsurat de backlink-uri sau Core Web Vitals. Search Console nu oferea date de teren CWV utilizabile în verificarea făcută. Testele de afișare și funcționare nu sunt măsurători Lighthouse și nu certifică viteza percepută în toate rețelele.

Rezultatele publice de căutare consultate includ pagini AFIR, presă de specialitate, consultanți și instrumente de autoevaluare; unele păstrează calendare estimate vechi. Aceste observații susțin utilitatea surselor actualizate și a calculatoarelor, dar nu reprezintă un clasament Google România controlat pe dispozitiv și locație. Nu am copiat conținutul concurenților.

Autoritatea externă, mențiunile independente și deciziile de indexare/citare nu pot fi obținute prin modificarea HTML-ului. Nu au fost fabricate recenzii, autori sau validări umane, nu au fost cumpărate linkuri și nu au fost trimise mesaje către terți.

## Măsurarea efectului

După recrawl, comparația relevantă este între intervale egale de 28 de zile, cu aceleași filtre, separat pentru fiecare pagină și interogare. Urmăriți în special CTR-ul DR14/Apel 2, interogările despre ghidul final DR12, mașini electrice pe firmă/e-DRIVE și creșterea afișărilor PRO INFRA/e-Mobility. Conversiile calificate contează alături de clicuri. O eventuală creștere nu poate fi atribuită exclusiv acestei intervenții fără a ține cont de lansările programelor și schimbările cererii.

Verificarea documentară și modificările din 6 septembrie au fost realizate de Codex la solicitarea utilizatorului; istoricul aprobărilor anterioare este păstrat separat.

## Validarea livrării

- Build-ul complet `npm run build` a trecut, inclusiv testele de SEO, FAQ/schema, canonical-uri, redirecționări, linkuri interne, accesibilitate, formulare și analytics.
- Verificarea vizuală automată a trecut pe 104 rute la două viewport-uri (208 verificări). Navbarul a fost testat separat la 320, 360, 390, 768, 1024 și 1366 px, cu imagine încărcată, fără suprapunere și cu navigare la tastatură.
- Regresia dedicată celor șapte pagini și siglei a trecut în surse (183 antete) și în pachetul `dist` (112 antete corespunzătoare fișierelor publice verificate). Fișierul publicat păstrează exact imaginea furnizată: SHA-256 `a9bd8ebbc9c0b787dc7e57abcfb121219b30ce0a4e6a58877199492b4da12a56`.
- Validarea Cloudflare a trecut. Poarta P0 permite publicarea: 11 criterii trecute, zero blocaje critice. Singurul criteriu rămas neîndeplinit este baseline-ul INP aprobat, absent deja din configurația proiectului; nu a fost înlocuit cu o valoare inventată. Responsabilul și retestarea sunt consemnate în raportul P0. Aceasta rămâne o limită a evaluării performanței, nu o dovadă a unei penalizări SEO.
- Verificarea live a livrării urmărește commitul din `/release.json`, cele 104 URL-uri din sitemap, imaginea logo și metadatele celor șapte pagini. Rezultatul efectiv al publicării este comunicat după deploy.
