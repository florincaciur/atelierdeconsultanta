# P1.11 — Template compact și citabil pentru pagini de program

Data QA: 2026-07-21  
Exemplu staging local: `http://127.0.0.1:4173/afir-autoconsum-agroalimentar/`  
Rută canonică: `https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar`

## Rezultat

PASS pentru template-ul pilot. Pagina AFIR Autoconsum Agroalimentar folosește `shortName`, statusul, calendarul, valorile și sursa exclusiv din registrul unic. Analiza editorială este separată în configurația template-ului, iar autorul, revizorul și changelog-ul sunt preluate din registrul de guvernanță editorială.

Nu a fost făcut deploy pe un mediu staging extern în acest task. Exemplul a fost servit local din artefactul canonic și verificat în browser la 1366×768 și 390×844.

## Ordinea implementată

1. H1 din `shortName` + badge/status + data verificării + sursa oficială;
2. răspuns direct de 58 de cuvinte;
3. tabelul „La o privire”, cu sursă lângă fiecare valoare;
4. „Cine se poate încadra”;
5. „Ce se finanțează / ce nu se finanțează”;
6. „Punctaj, condiții eliminatorii și riscuri”;
7. „Documente și pași”;
8. „Analiza consultantului” — ipoteze, documente care pot schimba concluzia și limite;
9. surse, versiune și changelog-ul registrului editorial;
10. opt întrebări în HTML, dintre care primele trei deschise inițial;
11. CTA contextual cu programul, investiția și canalul de origine precompletate.

Pagina are 1.502 cuvinte editoriale, deci include cuprinsul cerut. Conținutul critic rămâne în HTML; numai întrebările secundare folosesc elemente native `<details>`.

## Separarea câmpurilor CMS

| Proprietar | Câmpuri | Regula |
|---|---|---|
| Registrul unic | `slug`, `shortName`, `status`, `statusLabel`, `verifiedAt`, `sourceName`, `sourceUrl`, `sourceVersion`, `applicationStart`, `applicationEnd`, `grantSummary`, `cofinancingSummary`, `lastMeaningfulUpdate` | Nu pot fi declarate în fișa editorială a template-ului. |
| Fișa template | răspuns direct, beneficiar rezumat, document-cheie, eligibilitate, finanțabil/nefinanțabil, punctaj/riscuri, documente/pași, analiza consultantului, întrebări și CTA | Fiecare secțiune factuală cere `sourceKeys`. |
| Guvernanță editorială | autor, rol, revizor, rol, verificare, următoarea revizie și `changelog[]` | Este injectată în slotul „Surse, versiune și modificări”; nu este duplicată local. |

Schema JSON Schema 2020-12 documentează explicit această separare. Validatorul oprește sincronizarea când răspunsul direct nu are 50–80 de cuvinte, când programul nu este public/verificat, când ruta nu corespunde registrului, când lipsește o sursă oficială sau când apar câmpuri factuale locale interzise.

## QA automat

| Verificare | Rezultat |
|---|---|
| `npm run test:program-page-template` | PASS |
| `npm run test:long-form-layout` | PASS — 27 pagini, 410 ancore |
| `npm run test:breadcrumbs` | PASS — 91 URL-uri, paritate HTML/JSON-LD |
| `npm run test:editorial-governance` | PASS — 32 pagini |
| `npm run test:program-contextual-links` | PASS după resincronizarea generată |
| `npm run test:responsive-accessibility` | PASS — 7 rute × 6 viewporturi declarate |
| `npm run test:design-system` | PASS — 13 perechi de contrast |
| `npm run audit:program-facts` | PASS — 20 programe, 0 erori, 0 avertismente |

Contractul P1.11 verifică ordinea secțiunilor, derivarea H1/status/date/sursă din registru, sursa apropiată fiecărei valori din tabel, un singur disclaimer, absența etichetei „Pe scurt”, maximum șase întrebări deschise, CTA-ul precompletat și paritatea Article/Breadcrumb cu HTML-ul vizibil.

Auditul global existent pentru date structurate mai raportează zece probleme pe alte rute; exemplul P1.11 nu apare în lista problemelor. Aceste constatări nu au fost mascate și nu fac parte din patch-ul template-ului.

## QA vizual și interacțiuni

- desktop 1366 px: H1 60 px înălțime, fără overflow orizontal;
- mobil 390 px: H1 84 px înălțime, `scrollWidth` mai mic decât viewport-ul, fără overflow al documentului;
- cuprinsul este disclosure închis pe mobil;
- trei FAQ-uri sunt deschise inițial; un FAQ închis a fost deschis cu controlul nativ și răspunsul a rămas disponibil în DOM;
- CTA unic: `/contact?program=afir-energie-autoconsum&investment=...&source_channel=program_page`;
- Article folosește același headline ca H1 și citează URL-ul oficial din registru.

Capturi:

- `reports/p1-11-program-template-desktop.png`
- `reports/p1-11-program-template-mobile.png`

## Fișiere principale

- `config/program-page-template.schema.json` — schema câmpurilor editoriale;
- `config/program-page-template.json` — exemplul pilot și analiza editorială;
- `tools/sync-program-page-template.js` — validatorul și rendererul reutilizabil;
- `assets/program-page-template.css` — layout-ul compact și responsive;
- `tests/program-page-template-contract.mjs` — contractul de acceptanță;
- `reports/program-page-template-pilot-2026-07-21.json` — raportul determinist al generatorului.

