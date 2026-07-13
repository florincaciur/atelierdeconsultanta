# Raport: eliminare secțiuni sumar și colapsare resurse FAQ

Data implementării: 13 iulie 2026

## Rezultat

Au fost executate exclusiv modificările solicitate:

- eliminarea blocului compact „Pe scurt” cu etichetele Solicitant, Investiție, Punctaj și Ghid din paginile de program în care mai exista;
- eliminarea celor trei blocuri indicate din homepage;
- păstrarea primelor șase carduri FAQ vizibile și mutarea statică a grilei „Resurse utile” într-un panou ascuns inițial, controlat de un buton accesibil.

## Fișiere modificate

- `index.html`;
- `dr12-afir/index.html`;
- `dr14/index.html`;
- `tools/apply-design-profiles.js`;
- `scripts/verify-section-cleanup.js`;
- `scripts/seo-release-check.js`;
- `docs/section-cleanup-home-desktop.png`;
- `docs/section-cleanup-home-mobile.png`;
- acest raport.

## Pagini de program curățate

Inventarul întregului repository a identificat combinația exactă a celor patru carduri numai în:

- `dr12-afir/index.html`;
- `dr14/index.html`.

Celelalte pagini enumerate în cerință nu mai conțineau blocul compact exact în starea curentă. Validatorul verifică 18 rute de program, compuse din lista explicită și rutele canonice din `banners.json`.

Funcțiile `renderSummary` și `addSummary` au fost eliminate din `tools/apply-design-profiles.js`, împreună cu apelul generatorului. Rularea generatorului după modificare a raportat 0 fișiere modificate, iar blocul nu a reapărut.

CSS-ul `.audit-design-summary*` nu a fost eliminat deoarece este încă utilizat de pagini editoriale care nu intră în această cerință. Nu au fost eliminate clase CSS comune.

## Secțiuni eliminate din homepage

- headingul și lista „Ce trebuie verificat” din rezumatul FABER;
- secțiunea „Servicii pentru pregătirea proiectului”;
- secțiunea „Programe și surse de finanțare”.

Linkurile similare din navbar, mega-menu, footer, carusele, programe, FAQ și „Resurse utile” au fost păstrate.

## Structura FAQ

Înainte:

- șase carduri FAQ vizibile;
- secțiunea „Resurse utile” vizibilă imediat după FAQ.

După:

- aceleași șase întrebări și răspunsuri rămân vizibile și nemodificate;
- butonul `#homepage-faq-toggle` este vizibil după grilă;
- `aria-expanded="false"` și `aria-controls="homepage-faq-extra"` sunt starea inițială;
- `#homepage-faq-extra` conține static headingul și toate cele 17 linkuri din „Resurse utile” și pornește cu atributul `hidden`;
- la expandare textul devine „Ascunde resursele utile”, iar la colapsare revine la „Vezi toate resursele utile”;
- focusul rămâne pe buton la colapsare;
- footerul este în afara wrapperului ascuns.

Au fost adăugate numai cele patru reguli CSS minime pentru control, cursor și starea `hidden`. Nu au fost schimbate culorile, cardurile, coloanele, fonturile sau spațierea internă.

## SEO, AEO și structură statică

- FAQPage JSON-LD a fost păstrat;
- toate întrebările din schema FAQ corespund întrebărilor prezente în HTML;
- toate resursele și linkurile sunt prezente static în sursa HTML, fără `fetch`, API sau randare condiționată din rețea;
- title, meta description, H1, canonical, sitemap și `llms.txt` nu au fost modificate;
- nu există ID-uri duplicate sau linkuri goale în homepage.

## Teste

PASS:

- `node scripts/verify-section-cleanup.js` — 3 headinguri eliminate, 6 FAQ vizibile, 17 linkuri statice, 18 rute de program;
- rerulare după `node tools/apply-design-profiles.js` — PASS, blocul nu reapare;
- `node scripts/verify-global-header.js` — PASS, 172 pagini publice și interacțiuni desktop/mobil în Chromium;
- `node scripts/verify-program-heroes.js` — PASS, 13 pagini desktop/mobil;
- `node scripts/verify-structured-data.js` — PASS pentru cele șase pagini prioritare;
- `npm run test:functional` — PASS;
- `npm run verify:visual` — 24/24 verificări PASS;
- `git diff --check` — fără erori de conținut.

`npm run seo:check` rulează noul validator cu PASS, apoi se oprește în auditul generic preexistent `audit-site-links.js`: 1.366 de fragmente din navbar/footer (`#servicii`, `#finantare`, `#blog`, `#contact`) sunt interpretate drept ancore locale lipsă. Auditul raportează 0 ținte locale lipsă, 0 probleme de redirect și 0 probleme de rute de program. Excepția a fost acceptată explicit pentru finalizare, deoarece cerința interzice modificarea navbarului și footerului.

## Verificare vizuală

Suita vizuală a validat homepage desktop/mobil și paginile reprezentative. Validatorul hero a acoperit DR12, DR14, AFIR Autoconsum, PRO INFRA și PoCIDIF la lățimi desktop și mobile, fără overflow orizontal.

Captură homepage desktop:

![Homepage desktop după curățare](section-cleanup-home-desktop.png)

Captură homepage mobil:

![Homepage mobil după curățare](section-cleanup-home-mobile.png)

## Elemente confirmate nemodificate

- navbar și mega-menu;
- hero homepage;
- bannerele și hero-urile programelor;
- secțiunile editoriale detaliate ale programelor;
- footer;
- formular de contact, newsletter și endpointuri;
- carusele;
- canonicale, redirecturi, sitemap și `llms.txt`.

