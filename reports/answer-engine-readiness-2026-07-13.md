# Raport answer-engine readiness – 13 iulie 2026

## Obiectiv

Cele 11 pagini prioritare au fost verificate pentru răspuns direct, structură editorială naturală, delimitarea statutului documentelor, citarea sursei oficiale și paritatea FAQ vizibil/JSON-LD. Nu au fost folosite carduri compacte, blocuri „Răspuns rapid”, text ascuns sau conținut injectat exclusiv prin JavaScript.

## Rezultate pe rută

| Rută | Cuvinte în răspunsul direct | FAQ | Rezultat | Sursa oficială apropiată |
|---|---:|---:|---|---|
| / | 49 | 6 | CONFORM | Ghidul solicitantului și anexele apelului selectat |
| /verificare-eligibilitate-fonduri-europene | 48 | 8 | CONFORM | Ghidul solicitantului și anexele apelului identificat |
| /calculator-soc | 47 | 7 | CONFORM | Ghidurile solicitantului DR12 și DR14 și coeficienții Standard Output aplicabili |
| /dr12-afir | 52 | 8 | CONFORM | Ghidul solicitantului DR12 – Investiții în consolidarea exploatațiilor tinerilor fermieri |
| /dr14 | 50 | 8 | CONFORM | Ghidul solicitantului DR14 – Investiții în fermele de mici dimensiuni |
| /por-adr-nord-est | 51 | 8 | CONFORM | Programul Regional Nord-Est 2021–2027 și ghidul apelului selectat |
| /afir-autoconsum-agroalimentar | 50 | 8 | CONFORM | Ghidul Solicitantului Schemă Energie Autoconsum V7 – iunie 2026 |
| /pro-infra | 50 | 8 | CONFORM | Schema de ajutor de stat PRO INFRA – formă consolidată |
| /pocidif-21 | 53 | 8 | CONFORM | Ghidul aprobat și anexele Acțiunii 2.1 PoCIDIF |
| /femeia-antreprenor-2026 | 54 | 8 | CONFORM | Comunicat oficial privind Programul Femeia Antreprenor |
| /e-move | 51 | 8 | CONFORM | Ghidul solicitantului e-MOVE RO – Promovarea infrastructurii pentru o mobilitate cu emisii zero |

## Structura aplicată

- paragraf autonom de 45–80 de cuvinte imediat după introducerea vizuală;
- un H2 formulat ca intenție și opt răspunsuri în listă de definiții;
- document, instituție, statut și data ultimei verificări lângă răspunsurile factuale;
- „Interpretarea FABER” numai unde explică o consecință practică, marcată explicit ca neoficială;
- 5–8 întrebări FAQ vizibile și identice cu datele structurate.

## Fișiere modificate

- `config/priority-pages.json`
- `config/seo-programs.json`
- `tools/priority-aeo.js`
- `tools/generate-internal-link-map.js`
- `scripts/verify-answer-readiness.js`
- `scripts/verify-structured-data.js`
- `package.json`
- `index.html`
- `verificare-eligibilitate-fonduri-europene/index.html`
- `calculator-soc.html`
- `dr12-afir/index.html`
- `dr14/index.html`
- `por-adr-nord-est/index.html`
- `afir-autoconsum-agroalimentar/index.html`
- `pro-infra/index.html`
- `pocidif-21/index.html`
- `femeia-antreprenor-2026/index.html`
- `e-move/index.html`

## Verificări

- `node scripts/verify-answer-readiness.js --report`: trece;
- lungime răspuns direct: 11/11 conforme;
- statut și sursă oficială apropiată: 11/11 conforme;
- FAQ vizibil/JSON-LD: 11/11 conforme;
- text ascuns și rezumate compacte: zero probleme.

### Verificări de regresie executate după build

- `npm run test:functional`: trece, inclusiv validatorul answer-readiness;
- `npm run check:structured-data-sync`: trece, 102/102 pagini sincronizate;
- `node scripts/verify-structured-data.js`: trece pentru cele 6 pagini de program din auditul structurat;
- `npm run verify:visual`: trece, 26/26 verificări;
- `npm run verify:seo`: trece, 179/179 fișiere;
- `npm run audit:structured-data`: trece, 102 pagini indexabile și zero probleme;
- `npm run verify:seo-local`: trece, 102 rute și 10.249 linkuri interne;
- `npm run build`: trece;
- `npm run validate:cloudflare`: trece.
