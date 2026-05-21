# Final SEO & AI QA

Data audit: 2026-05-21

## Concluzie executiva

Site-ul este publicabil tehnic: buildul trece, sitemapul este valid, linkurile interne nu au tinte lipsa, structured data nu are erori detectate, iar verificarea vizuala trece.

Recomandarea critica este publicare cu revizie editoriala obligatorie pentru paginile care contin `TODO_*`, mai ales surse oficiale, reviewer, date juridice si dovezi pentru claims. Nu am modificat codul in aceasta runda; am creat doar acest raport si am rulat verificarile.

## 1. Build

Comenzi rulate:

```powershell
npm run build
npm run verify:seo
npm run audit:structured-data
node tools/audit-site-links.js
npm run verify:visual
npm run validate:cloudflare
npm run lint
git diff --check
```

Rezultate:

| Comanda | Rezultat | Observatii |
| --- | --- | --- |
| `npm run build` | PASS | `Cloudflare assets built in dist (181 files).` |
| Inspectie `dist` | PASS | 195 fisiere in `dist`, dintre care 160 HTML. Diferenta fata de mesajul buildului pare sa tina de modul intern de numarare al scriptului. |
| `npm run verify:seo` | PASS | 148 fisiere verificate, 148 pass, 0 fail. |
| `npm run audit:structured-data` | PASS | 148 fisiere verificate, 91 cu schema, 0 cu probleme. |
| `node tools/audit-site-links.js` | PASS | 169 fisiere scanate, 2886 linkuri locale, 0 tinte lipsa, 0 ancore lipsa. |
| `npm run verify:visual` | PASS | 18/18 verificari trecute. |
| `npm run validate:cloudflare` | PASS | 308 reguli redirect, deploy validation passed. |
| `npm run lint` | FAIL operational | Nu exista script `lint` in `package.json`. Nu este eroare de cod, dar este TODO tehnic. |
| `git diff --check` | PASS cu warnings | Fara whitespace errors. Git raporteaza doar conversii LF -> CRLF la urmatoarea atingere a unor fisiere. |

Erori/warnings:

- `npm run lint` lipseste din `package.json`.
- `verify:seo` afiseaza warning operational: `Target ... atelierdeconsultanta\\atelierdeconsultanta\\atelierdeconsultanta not found. Using current directory instead.`
- `git diff --check` afiseaza warnings de line endings LF/CRLF, fara erori.

## 2. Sitemap

Sitemap verificat: `sitemap.xml`

Rezultat:

- URL-uri in sitemap: 94
- URL-uri duplicate: 0
- URL-uri din sitemap fara corespondent local detectat: 0

URL-uri noi/importante confirmate in sitemap:

- `/consultanta-fonduri-europene`
- `/despre-faber`
- `/metodologie-verificare-eligibilitate`
- `/surse-oficiale-fonduri-europene`
- `/glosar-fonduri-europene`
- `/studii-de-caz-fonduri-europene`
- `/consultanta-afir`
- `/fonduri-pentru-ferme`
- `/verificare-eligibilitate-fonduri-europene`
- `/greseli-fonduri-europene`
- `/acte-necesare-fonduri-europene-nerambursabile`
- `/dr12-afir`
- `/dr14`
- `/calculator-soc`
- `/start-up-nation-2026`
- `/digitalizare-imm`
- `/digitalizare-imm-pnrr`

URL-uri excluse sau neincluse intentionat:

- `/admin/` - zona administrativa.
- `/404` - pagina tehnica/noindex.
- `google8bbb9999c523a3bd.html` - fisier de verificare.
- Aliasuri `.html` si rute istorice care canonizeaza catre rute curate.
- Pagini locale similare canonizate spre hub-uri regionale/nationale unde continutul nu este suficient de distinct.

## 3. Canonicals

Rezultat:

- Fisiere HTML scanate: 148
- Fisiere cu canonical: 147
- Fisier fara canonical: `google8bbb9999c523a3bd.html`, acceptabil ca fisier de verificare.
- URL-uri canonice publice reprezentate in sitemap: 94
- Aliasuri/rute consolidate care trimit canonical spre alta pagina: 16

Mostre de aliasuri canonizate:

- `autoconsum-publici.html` -> `/autoconsum-public-fotovoltaice-institutii-publice`
- `consultanta-fonduri-europene-bacau/index.html` -> `/fonduri-europene-nord-est`
- `consultanta-fonduri-europene-iasi/index.html` -> `/fonduri-europene-nord-est`
- `consultanta-fonduri-europene-suceava/index.html` -> `/fonduri-europene-nord-est`
- `consultanta-fonduri-europene-bucuresti/index.html` -> `/consultanta-fonduri-europene`
- `consultanta-start-up-nation/index.html` -> `/consultanta-start-up-nation-2026`
- `fonduri-europene-bucuresti/index.html` -> `/fonduri-europene`

Probleme detectate:

- Nu exista probleme pentru paginile canonice din sitemap.
- Recomandare: pastrati paginile locale canonizate doar daca au rol de redirect/compatibilitate. Daca se doreste indexare locala, trebuie rescrise cu dovezi si unghi local real.

## 4. Meta

Audit pe cele 94 URL-uri canonice din sitemap:

- Pagini fara `<title>`: 0
- Pagini fara meta description: 0
- Title duplicate: 0
- Description duplicate: 0

Rezultat automat complementar:

- `verify:seo`: `metaDescription` 148 pass, 0 fail.

## 5. H1

Audit pe cele 94 URL-uri canonice din sitemap:

- Pagini fara H1: 0
- Pagini cu mai multe H1: 0
- H1 duplicate intre pagini canonice: 0

Rezultat automat complementar:

- `verify:seo`: `singleH1` 148 pass, 0 fail.

## 6. Structured Data

Rezultat `npm run audit:structured-data`:

- Fisiere verificate: 148
- Fisiere cu schema: 91
- Fisiere cu probleme: 0

Tipuri folosite:

- `Organization`: 192
- `WebSite`: 67
- `WebPage`: 81
- `FAQPage`: 71
- `Question`: 446
- `Answer`: 446
- `BlogPosting`: 21
- `BreadcrumbList`: 75
- `GovernmentService`: 14
- `Service`: 10
- `CollectionPage`: 7
- `ContactPage`: 1
- `AboutPage`: 1
- `DefinedTermSet`: 1
- `DefinedTerm`: 19
- plus `ImageObject`, `Country`, `ContactPoint`, `CreativeWork`, `Article`, `ItemList`, `ProfessionalService`, `LocalBusiness`, `Offer`, `WebApplication`, `Audience`, `CommunicateAction`.

Acoperire:

- Pagini cu FAQ schema: 71
- Pagini cu `BlogPosting`: 21
- Pagini cu `Organization`: 91
- Probleme detectate: 0

Recomandare:

- Validare manuala in Rich Results Test pentru homepage, `/consultanta-fonduri-europene`, `/despre-faber`, `/dr12-afir`, `/dr14`, `/calculator-soc`, `/start-up-nation-2026`, `/digitalizare-imm` si 3 articole P1.

## 7. Duplicare Continut

Rezultate automate:

- Duplicare exacta de body text intre pagini canonice: 0
- Grupuri FAQ complet identice: 0

Zone cu repetitie partiala:

- Intrebari FAQ individuale se repeta pe multe pagini programatice:
  - `Verificarea garanteaza finantarea?` apare pe 18 fisiere.
  - `Cand trebuie inceputa pregatirea?` apare pe 17 fisiere.
  - `Ce date sunt utile pentru analiza?` apare pe 17 fisiere.
  - `Pot compara mai multe programe?` apare pe 17 fisiere.
  - `Informatiile garanteaza finantarea?` apare pe 8 fisiere.

Pagini locale similare:

- Paginile pentru Iasi, Suceava, Bacau si Bucuresti sunt tratate prudent prin canonical spre hub-uri regionale/nationale.
- Recomandare: nu le promovati ca pagini locale indexabile pana nu exista continut local real: apeluri regionale, exemple locale, institutii, documente sau studii de caz validate.

Recomandari de rescriere:

- Diferentiati FAQ-urile pe fiecare familie de program: AFIR, Start-Up Nation, Digitalizare IMM, energie, regional.
- Pentru paginile locale, pastrati maximum 1-2 intrebari generale si adaugati intrebari locale reale doar cand exista surse.
- Pentru hub-uri vechi, adaugati raspuns scurt si tabel propriu inainte de extinderea cu articole noi.

## 8. AI Visibility

Semnale verificate pe paginile importante:

- raspuns scurt / pe scurt;
- tabele;
- autor/reviewer;
- data actualizarii;
- surse oficiale vizibile in HTML;
- link catre metodologie;
- CTA contextual.

Rezumat:

- Pagini importante evaluate: 94
- Pagini cu cel putin un gap semantic/editorial: 66
- Pagini cu tabele: 73
- Pagini cu linkuri catre surse oficiale: 88
- Pagini cu link catre metodologie: 73
- Pagini cu CTA standard/contextual: 69

Gap-uri principale:

- Homepage: lipseste tabel; nu este blocant, dar un tabel scurt de orientare ar ajuta AI snippets.
- `/consultanta-fonduri-europene`: lipseste eticheta explicita `Raspuns scurt` / `Pe scurt`.
- `/blog`: lipsesc raspuns scurt, tabel si data actualizarii.
- `/metodologie-verificare-eligibilitate`: lipsesc raspuns scurt, tabel si link intern catre propria metodologie nu este aplicabil, dar auditul il marcheaza tehnic.
- `/surse-oficiale-fonduri-europene`: lipseste raspuns scurt explicit.
- `/glosar-fonduri-europene`: lipsesc raspuns scurt si tabel.
- `/contact`: lipsesc autor/reviewer, data actualizarii si link explicit catre metodologie in corpul paginii.
- Paginile vechi `blog-afir-fotovoltaice-ferme-2026`, `calculator-soc`, `cum-alegi-programul-potrivit-fonduri-europene-2026` au nevoie de completari AI-snippet.
- Unele pagini vechi de program sau articol au CTA-uri care nu sunt detectate de lista standard, chiar daca au linkuri de contact.

Observatie:

- Articolele noi P1 si paginile de autoritate sunt mai aproape de formatul dorit, dar contin inca multe `TODO_SURSA_OFICIALA` si `TODO_CLIENT_REVIEWER`, deci nu trebuie tratate ca finale editorial.

## 9. TODO-uri Ramase

Scanare totala fisiere text relevante, excluzand `dist`, `reports`, `.git`, `node_modules`, `.wrangler`: 247 aparitii `TODO*`.

Scanare pagini publice si fisiere publice principale, excluzand `docs`, `tools`, `scripts`: 138 aparitii.

TODO-uri publice pe categorii:

| Marker | Numar |
| --- | ---: |
| `TODO_SURSA_OFICIALA` | 24 public / 52 total |
| `TODO_VERIFICARE_GHID_AFIR` | 14 |
| `TODO_VERIFICARE_GHID_STARTUP` | 8 |
| `TODO_VERIFICARE_GHID_DIGITALIZARE` | 3 |
| `TODO_CLIENT_REVIEWER` | 26 public / 29 total |
| `TODO_CLIENT_DOVADA_CLAIM` | 4 public / 7 total |
| `TODO_CLIENT_CUI` | 2 |
| `TODO_CLIENT_ADRESA` | 2 |
| `TODO_CLIENT_REPREZENTANT` | 2 |
| `TODO_CLIENT_LINKEDIN` | 2 |
| `TODO_CLIENT_GOOGLE_BUSINESS_PROFILE` | 2 |
| `TODO_CLIENT_EXEMPLU` | 4 public / 8 total |
| `TODO_CLIENT_PROGRAM` | 5 |
| `TODO_CLIENT_VALOARE` | 5 |
| `TODO_CLIENT_STATUS` | 5 |
| `TODO_BACKEND_FORM` | 2, doar in documentatia de audit CTA, nu in formularul public |

Fisiere publice cu TODO-uri importante:

- `calculator-so-afir.html`
- `cand-merita-consultant-fonduri-europene.html`
- `cat-costa-consultanta-fonduri-europene-ghid.html`
- `ce-acte-sunt-necesare-fonduri-europene.html`
- `cheltuieli-eligibile-digitalizare-imm.html`
- `cheltuieli-eligibile-startup-nation.html`
- `cod-caen-startup-nation.html`
- `consultanta-fonduri-europene/index.html`
- `cum-se-calculeaza-cofinantarea-fonduri-europene.html`
- `cum-se-verifica-eligibilitatea-fonduri-europene.html`
- `despre-faber/index.html`
- `digitalizare-imm-erp-crm-cloud.html`
- `dr12-afir-tineri-fermieri.html`
- `dr12-afir.html`
- `dr12-vs-dr14.html`
- `dr14-afir-ferme-mici.html`
- `fonduri-europene-nord-est/index.html`
- `glosar-fonduri-europene/index.html`
- `index.html`
- `llms.txt`
- `metodologie-verificare-eligibilitate/index.html`
- `start-up-nation-2026.html`
- `startup-nation-2026-conditii.html`
- `studii-de-caz-fonduri-europene/index.html`
- `surse-oficiale-fonduri-europene/index.html`

Recomandare critica:

- Nu publicati claims comerciale numerice fara dovada interna.
- Nu promovati articolele cu `TODO_SURSA_OFICIALA` drept continut final.
- Inlocuiti `TODO_CLIENT_REVIEWER` cu nume/rol publicabil sau schimbati formularea in "verificare editoriala interna" daca nu se poate publica persoana.

## 10. Checklist Publicare

- [ ] Verificare manuala pagini principale: homepage, consultanta, AFIR, Start-Up Nation, Digitalizare IMM, Despre, Surse, Metodologie, Glosar, Contact.
- [ ] Verificare manuala articole P1 si articole cu `TODO_SURSA_OFICIALA`.
- [ ] Validare Rich Results pentru paginile cu `FAQPage`, `BlogPosting`, `Organization`, `AboutPage`, `ContactPage`.
- [ ] Test sitemap in browser: `https://atelierdeconsultanta.ro/sitemap.xml`.
- [ ] Test robots in browser: `https://atelierdeconsultanta.ro/robots.txt`.
- [ ] Verificare `llms.txt` in browser: `https://atelierdeconsultanta.ro/llms.txt`.
- [ ] Submit sitemap in Google Search Console.
- [ ] Inspect URL pentru paginile noi: Despre, Metodologie, Surse, Glosar, Studii de caz, DR12, DR14, Start-Up Nation, Digitalizare IMM.
- [ ] Verificare indexare dupa publicare pentru paginile canonice din sitemap.
- [ ] Verificare analytics/Clarity dupa deploy.
- [ ] Test formular pe homepage, inclusiv campurile noi si emailul primit prin FormSubmit.
- [ ] Test linkuri din header, footer, CTA-uri si articole conexe.
- [ ] Test mobile pentru homepage, hub-uri program si formular.
- [ ] Confirmare client pentru CUI, adresa, reprezentant, LinkedIn, Google Business Profile.
- [ ] Confirmare dovezi pentru `250+ proiecte`, `45M€`, `98%`, `10 ani experienta` sau eliminarea temporara a acestor claims.

## Decizie QA

Status tehnic: PASS.

Status SEO structural: PASS.

Status AI visibility: PASS partial, cu recomandari editoriale.

Status publicare comerciala: CONDITIONAL. Se poate publica tehnic, dar paginile cu `TODO_CLIENT*`, `TODO_SURSA_OFICIALA` si `TODO_CLIENT_DOVADA_CLAIM` trebuie revizuite manual inainte de a fi promovate activ sau trimise spre indexare accelerata.
