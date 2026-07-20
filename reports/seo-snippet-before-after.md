# Optimizare controlată a snippeturilor SEO

Data auditului: 2026-07-13
Prioritizare: exportul Microsoft Clarity furnizat pentru cele 11 rute
Sursa recomandărilor: `config/seo-snippets.json`

## Rezultat

- Au fost configurate și sincronizate 11 seturi de `title`, meta-description, `og:title` și `og:description`.
- Toate titlurile au 45–60 de caractere și o lățime estimată sub 600 px.
- Toate descrierile au 126–148 de caractere.
- Nu există titluri sau descrieri duplicate în setul prioritar.
- Titlurile includ intenția principală, iar title, H1 și meta-description rămân distincte.
- URL-urile, canonicalurile, H1-urile și conținutul principal nu au fost modificate de aplicatorul de snippeturi.

## Decizii factuale

| Rută | Decizie |
| --- | --- |
| `/femeia-antreprenor-2026` | Sursa locală indică un program național al Ministerului Economiei. Referirea eronată la „fonduri europene” a fost eliminată, iar regulile ediției 2026 sunt marcate ca neconfirmate. |
| `/dr12-afir` | Pragul de minimum 12.000 SO este păstrat împreună cu statutul consultativ; procentele nu mai sunt prezentate în snippet ca valori finale. |
| `/dr14` | Sunt comunicate fermele mici, pragurile SO diferențiate, componentele și actele, cu mențiunea explicită că ghidul este consultativ. |
| `/e-move` | Schema este descrisă ca fiind în consultare; nu sunt promovate valori indicative drept condiții finale. |
| `/por-adr-nord-est` | Este folosită denumirea actuală „Programul Regional Nord-Est”, iar apelul aplicabil trebuie confirmat în portalul oficial. |

## Before / after

| # | Rută | Titlu anterior | Titlu nou | Caractere / lățime estimată | Descriere nouă |
| ---: | --- | --- | --- | ---: | --- |
| 1 | `/` | Consultanță și proiectare fonduri europene \| FABER | Consultanță și proiectare fonduri europene \| FABER | 50 / ~375 px | FABER oferă consultanță și proiectare pentru proiecte cu fonduri europene: eligibilitate, cereri de finanțare, documentații tehnice și implementare. |
| 2 | `/verificare-eligibilitate-fonduri-europene` | Verificare eligibilitate fonduri europene | Verificare eligibilitate fonduri europene \| FABER | 49 / ~352 px | Verificăm solicitantul, codul CAEN, locația, investiția, bugetul, cofinanțarea și documentele înainte de alegerea programului. |
| 3 | `/calculator-soc` | calculator SO AFIR \| ghid AFIR | Calculator SO AFIR 2026 pentru DR12 și DR14 \| FABER | 51 / ~381 px | Calculează orientativ dimensiunea economică SO pentru exploatația vegetală sau zootehnică și verifică încadrarea pentru DR12 și DR14. |
| 4 | `/femeia-antreprenor-2026` | Femeia Antreprenor 2026 \| ghid FABER | Femeia Antreprenor 2026: condiții, buget și punctaj | 51 / ~379 px | Verifică acționariatul, CAEN-ul, bugetul, punctajul și documentele pentru Femeia Antreprenor; condițiile ediției 2026 se confirmă în sursa oficială. |
| 5 | `/dr12-afir` | DR12 AFIR 2026: ghid, lansare, eligibilitate și acte \| FABER | DR12 AFIR 2026: eligibilitate, sprijin și acte \| FABER | 54 / ~377 px | DR12 pentru tineri fermieri: eligibilitate, minimum 12.000 SO, sprijin și acte. Valorile sunt din ghidul consultativ și se reconfirmă la lansare. |
| 6 | `/dr14` | DR14 AFIR 2026: ferme mici, condiții și calculator SO \| FABER | DR14 AFIR 2026: condiții, praguri SO și acte \| FABER | 52 / ~374 px | DR14 pentru ferme mici: praguri SO diferențiate, componente, investiții și acte. Valorile sunt din ghidul consultativ și se reconfirmă la lansare. |
| 7 | `/por-adr-nord-est` | Programul Regional Nord-Est: apeluri pentru IMM \| FABER | Programul Regional Nord-Est pentru IMM \| FABER | 46 / ~355 px | Apeluri pentru IMM și microîntreprinderi din Nord-Est: verifică județul, CAEN-ul, amplasamentul, bugetul, cofinanțarea și documentele. |
| 8 | `/contact` | Contact FABER \| verificare eligibilitate | Contact FABER pentru eligibilitate și proiecte | 46 / ~335 px | Trimite datele proiectului către FABER: solicitant, CAEN, localitate, investiție, buget, cofinanțare și documente disponibile pentru analiză. |
| 9 | `/e-move` | e-MOVE RO \| ghid FABER | e-MOVE RO: stații de încărcare și stocare \| FABER | 49 / ~361 px | Schema e-MOVE RO aflată în consultare: stații de încărcare, energie regenerabilă, stocare, solicitanți și documente pentru pregătire. |
| 10 | `/despre-faber` | Despre FABER \| Atelier de Consultanță | Despre FABER: consultanță prudentă pentru proiecte | 50 / ~386 px | Cum verifică FABER eligibilitatea, programul, bugetul și documentele, cu surse oficiale, limite clare și fără promisiuni de aprobare. |
| 11 | `/consultanta-fonduri-europene` | Consultanță fonduri europene pentru proiecte \| FABER | Consultanță fonduri europene pentru firme \| FABER | 49 / ~374 px | Consultanță pentru firme, fermieri și organizații: eligibilitate, program potrivit, buget, dosar, clarificări și suport în implementare. |

Valorile complete before/after pentru descrieri și Open Graph sunt în `reports/seo-snippet-before-after.csv`.

## Scorul de oportunitate CTR

`tools/import-gsc-query-export.js` compară fiecare rând cu maximum 10 rânduri din același export care au pozițiile cele mai apropiate. Benchmarkul CTR este ponderat cu afișările.

- `click gap = afișări × max(0, CTR benchmark − CTR actual)`
- `opportunity score = 100 × click gap / cel mai mare click gap din export`

Scorul nu folosește un CTR standard universal. Exporturile de interogări și pagini sunt evaluate separat, iar recomandarea din `config/seo-snippets.json` este atașată rutei când există.

## Fișiere și integrare

- `config/seo-snippets.json` — sursa unică pentru cele 11 recomandări și statutul lor factual.
- `tools/apply-seo-snippets.js` — sincronizează numai metadatele din `<head>` și verifică invariabilitatea canonicalului, H1-ului și corpului paginii.
- `tools/validate-seo-snippets.js` — verifică duplicatele, lungimea, lățimea estimată, intenția, afirmațiile interzise și concordanța config–HTML.
- `tools/import-gsc-query-export.js` — calculează oportunitatea CTR relativă la export și asociază recomandări pe rută.
- `tools/sync-structured-data.js` — citește explicit titlul documentului din `head > title`.
- `package.json` — rulează aplicarea snippeturilor în build și expune verificarea dedicată.

## Teste

| Comandă | Rezultat |
| --- | --- |
| `node --check tools/import-gsc-query-export.js` | Trecut |
| Test sintetic GSC cu trei rânduri și CTR 1% / 3% / 5% | Trecut; scorul maxim este 100, benchmarkul și recomandarea pe rută sunt prezente |
| `npm run apply:seo-snippets` | Trecut; 11 fișiere sincronizate |
| `npm run verify:seo-snippets` | Trecut; 11 rute valide, fără avertismente |
| `node tools/apply-seo-snippets.js --check` | Trecut; 0 abateri |
| `npm run build` | Trecut; 102 pagini indexabile sincronizate și 165 active Cloudflare generate |
| `npm run audit:structured-data` | Trecut; 102 pagini indexabile, 0 probleme |
| `npm run verify:seo` | Trecut; 179/179 fișiere |
| `npm run verify:seo-local` | Trecut; 102 URL-uri și 10.018 linkuri interne |
| `npm run test:functional` | Trecut; verificările funcționale de navigare sunt valide |
| `npm run verify:visual` | Trecut; 26/26 verificări |
| `npm run validate:cloudflare` | Trecut |
| `git diff --check` | Trecut; numai avertismente informative CRLF, fără erori de whitespace |
