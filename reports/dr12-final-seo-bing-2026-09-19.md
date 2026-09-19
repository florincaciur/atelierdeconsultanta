# Actualizare DR-12, homepage și vizibilitate Bing — 19 septembrie 2026

## Rezultatul editorial

Pagina `/dr12-afir` folosește ghidul final AFIR, Ediția I, Revizia 0, publicat la 18.09.2026 și aprobat prin OMADR 268/17.09.2026. Arhiva furnizată a fost tratată ca material documentar, nu ca instrucțiuni de executat. PDF-ul din arhivă coincide cu PDF-ul oficial descărcat: SHA-256 `cfe0a758b8276d7005ff0f1b1b2e58ae8c29cc0741cf6e8c471d236338fc09fc`.

Surse verificate:

- [Ghid și anexe DR-12](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/)
- [Ghidul final PDF](https://www.afir.ro/media/aqtlitop/ghidul-solicitantului-dr-12.pdf)
- [Anunțul publicării](https://www.afir.ro/info-la-zi/ghidul-final-pentru-dr-12/)
- [Sesiuni AFIR](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/)
- [Ordine și legislație](https://www.afir.ro/instrumente/normative/legislatie-nationala/)

La verificare nu este anunțată perioada de depunere DR-12. Datele de început și sfârșit rămân necompletate în registru; statutul este `FINAL_GUIDE`, fără a anunța un apel deschis. Se precizează data verificării și locul unde va fi publicată sesiunea.

Conținutul acoperă beneficiarii și excepția de vârstă pentru sM 6.1 finalizat, controlul exploatației, minimum 12.000 SO, competențe, drepturile asupra amplasamentului, investițiile, cheltuielile neeligibile, documentele și finanțarea. Grantul este de maximum 200.000 EUR, cu intensitate de 80% sau 65%; contribuția de 20%/35% poate crește ca efect al plafonului și al costurilor neeligibile. Vechimea de cinci ani în IACS este explicată la punctajul 6.2, fără a fi prezentată drept condiție generală de eligibilitate.

Grila și calculatorul de la finalul paginii au maximum 100 de puncte și pragurile finale 80/45. Sunt tratate necumularea variantelor, proporția terenului și asigurării, pragul de 10% pentru investițiile de precizie, criteriul distinct al proprietății/construcțiilor și istoricul FEADR. Calculul nu rotunjește un punctaj sub prag pentru a-l declara eligibil. Rezultatul este orientativ, nu o evaluare AFIR. Legătura este disponibilă în meniul Calculatoare pe desktop și mobil. Formula DR-12 veche a fost eliminată din scriptul comun.

## Datele furnizate și prioritățile rezultate

Exporturile Search Console indică pentru DR-12: 116 clicuri / 2.711 afișări / CTR 4,28% / poziție medie 6,5 în fereastra de 28 de zile; 41 / 958 / poziție 5,89 în șapte zile; 248 / 5.122 / poziție 6,68 în trei luni. Interogarea „dr 12 afir lansare” are 14 clicuri / 636 afișări în 28 de zile, justificând răspunsul explicit despre calendar în partea superioară a paginii. Homepage-ul are 14 clicuri / 145 afișări / poziție 20,05 în 28 de zile.

Exportul Bing Search, 19 iunie–17 septembrie, însumează 27 clicuri și 686 afișări, CTR aproximativ 3,94%. Exportul AI însumează 135 citări. Numărul zilnic al paginilor citate nu a fost însumat ca și cum ar reprezenta pagini unice. Aceste valori sunt repere înaintea modificării, nu rezultate atribuite actualizării.

Raportul de acoperire, ultima observație 14 septembrie: 102 pagini indexate și 114 neindexate. Motivele includ 88 redirecționări, șapte pagini accesate dar neindexate, cinci `noindex`, cinci alternative cu canonical, patru erori de redirecționare, o blocare robots, un duplicat fără canonical și trei pagini descoperite dar neindexate. Exportul agregat nu identifică URL-urile afectate; nu se poate afirma că cele patru erori de redirecționare au fost eliminate. Redirecționările valide și paginile intenționat `noindex` nu reprezintă automat defecte.

## Modificări SEO, AEO și GEO

- Titluri, descrieri, Open Graph și Twitter sincronizate pentru homepage și DR-12; titlul Contact scurtat pentru avertismentul Bing. Canonical, JSON-LD, sitemap și informațiile despre program sunt păstrate coerente prin generatoare.
- Răspunsuri directe în HTML, FAQ vizibil, surse primare cu trimiteri la paginile ghidului, data verificării și exemple explicite de cofinanțare. Grila se poate citi și fără JavaScript.
- Homepage-ul și comparația DR-12/DR-14 folosesc noul statut. Meniul global conduce direct la calculator. Vechea copie `dr12-afir.html` este eliminată; aliasurile sunt gestionate prin redirecționările existente spre ruta canonică.
- Navigarea la secțiunile homepage-ului lasă spațiu sub bara fixă. Resursele temporare de analiză sunt excluse din inventarul public și din pachetul de publicare.
- Politica existentă pentru crawlere și fluxul IndexNow sunt păstrate și verificate. Nu s-au adăugat blocaje pentru Bing ori pentru citarea AI.

[Bing Webmaster Guidelines](https://www.bing.com/webmasters/help/bing-webmaster-guidelines-30fba23a) și [documentația AI Performance](https://blogs.bing.com/webmaster/February-2026/Introducing-AI-Performance-in-Bing-Webmaster-Tools-Public-Preview) susțin monitorizarea separată a indexării și a citărilor. Nici datele structurate, nici IndexNow nu garantează clasarea în primele cinci rezultate sau citarea de către orice agent AI.

Avertismentul despre backlinkuri de calitate nu poate fi rezolvat exclusiv în cod. Sunt necesare mențiuni editoriale reale pe domenii relevante, de exemplu organizații profesionale, parteneri sau publicații care folosesc materialele documentate. Nu au fost cumpărate linkuri și nu au fost trimise mesaje către terți. Revalidarea avertismentelor în Bing depinde de recrawl și de datele disponibile în cont.

## Verificări

- Calculator: punctaj minim/maxim, ambele componente, necumulare, limitele 9,99%/10%, 45 și 80 de puncte, valori invalide și resetare.
- Afișare DR-12: 320, 390, 768 și 1440 px, fără depășire orizontală, fără erori JavaScript și fără încălcări axe în conținutul principal.
- Homepage: testele responsive, fallback fără JavaScript, mișcare redusă și 76 de combinații de stare/dimensiune au trecut; fără erori axe, elemente tăiate sau depășire orizontală în auditul efectuat.
- Audit factual: 26 de programe, zero erori și zero avertismente după actualizare.

Verificările automate de navigare și metadate au fost actualizate pentru noul calculator și ghidul final. Raportul nu echivalează verificarea locală cu confirmarea indexării sau a unei creșteri de trafic după publicare.

Comenzi reproductibile pentru noile verificări: `npm run test:dr12-final` și `npm run test:dr12-final-ui`. Auditul vizual extins al programelor a trecut 243 de verificări (27 de rute × nouă dimensiuni de ecran). Verificarea legăturilor a acoperit 18.512 legături locale și 1.055 fragmente; graful intern nu are pagini orfane sau legături rupte/redirecționate. Politicile de redirecționare/canonical și contractul Cloudflare au trecut.

Au trecut și cele 237 de verificări responsive ale stratului vizual comun al site-ului. Testele de conținut fără JavaScript confirmă că informațiile esențiale sunt disponibile direct în HTML, iar FAQ-ul vizibil este în concordanță cu datele structurate.

Fluxul de build a fost parcurs până la capăt, cu reluare de la etapele corectate. Pachetul Cloudflare a fost generat cu 229 de fișiere. Testele de metadate/logo pentru varianta `dist`, matricea celor cinci URL-uri prioritare, verificările IndexNow și AI citation readiness au trecut. Calculatorul și resursele lui sunt prezente în pachet, iar directoarele locale de analiză sunt excluse.
