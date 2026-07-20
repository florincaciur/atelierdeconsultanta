# Raport remediere navigare globală — 2026-07-13

## Context

- Repository: `florincaciur/atelierdeconsultanta`
- Branch de bază: `main`
- Sincronizare inițială: `git pull --ff-only origin main` — repository deja la zi
- Domeniu canonic verificat: `https://atelierdeconsultanta.ro`
- Aspectul, culorile, spațierile și regulile responsive ale navbarului nu au fost modificate.

## Linkuri vechi și noi

| Etichetă | Link vechi | Link nou |
| --- | --- | --- |
| Servicii | `#servicii` | `/consultanta-fonduri-europene` |
| Finanțări | `#finantare` | `/fonduri-europene` |
| Blog | `#blog` | `/blog` |
| Contact | `#contact` | `/contact` |

Schimbarea este identică în navbarul desktop și în meniul mobil. Fragmentul funcțional `#eligibility-whatsapp-dialog` a fost păstrat și validat separat ca deschidere de dialog.

## Modificări implementate

- Meniurile desktop și mobil au acum aceleași 20 de destinații, în aceeași ordine.
- Ruta `/fonduri-regionale`, prezentă anterior numai în mega-menu-ul desktop, a fost adăugată și în meniul mobil.
- Rutele principale și toate celelalte destinații interne din header sunt verificate pentru existența sursei HTML și pentru canonical auto-referențial.
- Etichetele au fost corectate: „Stații de încărcare”, „Inovare digitală”, „Producție pentru infrastructură”, „Autoconsum instituții publice”, precum și capitalizările/formulările conexe.
- La închiderea cu `Escape`, meniul mobil restaurează focusul pe hamburger; după dialogul deschis din mobil, focusul revine tot la hamburger.
- Auditurile separă ancorele de document de fragmentele interactive. Niciuna dintre categorii nu este exclusă generic: fiecare fragment este verificat în documentul destinație, inclusiv pentru rute absolute cu fragment.
- Auditul de linkuri rezolvă corect query-stringurile de versionare ale resurselor înainte de verificarea fișierului local.

## Fișiere modificate

### Surse și verificări

- `partials/global-header.html`
- `assets/global-header.js`
- `scripts/verify-global-header.js`
- `tools/audit-site-links.js`
- `tools/audit-indexing.js`

### Pagini HTML publice sincronizate (172)

<details>
<summary>Lista completă</summary>

- `404.html`
- `acte-necesare-fonduri-europene-nerambursabile.html`
- `acte-necesare-fonduri-europene-nerambursabile/index.html`
- `afir-autoconsum-agroalimentar/index.html`
- `afir.html`
- `afir/index.html`
- `apeluri-gal/index.html`
- `autoconsum-public-fotovoltaice-institutii-publice.html`
- `autoconsum-public-fotovoltaice-institutii-publice/index.html`
- `autoconsum-publici.html`
- `blog-afir-fotovoltaice-ferme-2026.html`
- `blog.html`
- `blog/index.html`
- `calculator-so-afir.html`
- `calculator-soc.html`
- `calendar-fonduri-europene.html`
- `calendar-fonduri-europene/index.html`
- `cand-merita-consultant-fonduri-europene.html`
- `cat-costa-consultanta-fonduri-europene-ghid.html`
- `cat-costa-consultanta-fonduri-europene.html`
- `cat-costa-consultanta-fonduri-europene/index.html`
- `ce-acte-sunt-necesare-fonduri-europene.html`
- `cheltuieli-eligibile-digitalizare-imm.html`
- `cheltuieli-eligibile-pocidif-21/index.html`
- `cheltuieli-eligibile-startup-nation.html`
- `cod-caen-start-up-nation-2026/index.html`
- `cod-caen-startup-nation.html`
- `consultant-fonduri-europene-imm.html`
- `consultant-fonduri-europene-imm/index.html`
- `consultanta-afir.html`
- `consultanta-afir/index.html`
- `consultanta-fonduri-europene-bacau/index.html`
- `consultanta-fonduri-europene-bucuresti/index.html`
- `consultanta-fonduri-europene-iasi/index.html`
- `consultanta-fonduri-europene-suceava/index.html`
- `consultanta-fonduri-europene.html`
- `consultanta-fonduri-europene/index.html`
- `consultanta-pnrr-digitalizare.html`
- `consultanta-pnrr-digitalizare/index.html`
- `consultanta-start-up-nation-2026/index.html`
- `consultanta-start-up-nation.html`
- `consultanta-start-up-nation/index.html`
- `contact.html`
- `contact/index.html`
- `cum-alegi-consultant-fonduri-europene.html`
- `cum-alegi-consultant-fonduri-europene/index.html`
- `cum-alegi-programul-potrivit-fonduri-europene-2026.html`
- `cum-se-calculeaza-cofinantarea-fonduri-europene.html`
- `cum-se-verifica-eligibilitatea-fonduri-europene.html`
- `despre-faber/index.html`
- `digitalizare-imm-erp-crm-cloud.html`
- `digitalizare-imm-pnrr.html`
- `digitalizare-imm-pnrr/index.html`
- `digitalizare-imm.html`
- `digitalizare-imm/index.html`
- `documente-punctaj-pocidif-21/index.html`
- `dr-12-afir-instalarea-tinerilor-fermieri.html`
- `dr-14-afir-conditii-eligibilitate-greseli-frecvente.html`
- `dr12-afir-tineri-fermieri.html`
- `dr12-afir/index.html`
- `dr12-vs-dr14.html`
- `dr14-afir-ferme-mici.html`
- `dr14-afir-ferme-mici/index.html`
- `dr14/index.html`
- `e-move/index.html`
- `eligibilitate-fonduri-europene.html`
- `eligibilitate-fonduri-europene/index.html`
- `eligibilitate-pocidif-21/index.html`
- `femeia-antreprenor-2026-conditii-idei-afaceri.html`
- `femeia-antreprenor-2026.html`
- `femeia-antreprenor-2026/index.html`
- `finantari-panouri-fotovoltaice.html`
- `finantari-panouri-fotovoltaice/index.html`
- `firma-consultanta-fonduri-europene.html`
- `firma-consultanta-fonduri-europene/index.html`
- `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html`
- `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum/index.html`
- `fondul-de-modernizare.html`
- `fondul-de-modernizare/index.html`
- `fondul-modernizare-energie-regenerabila-2026.html`
- `fondul-modernizare-energie-regenerabila-2026/index.html`
- `fonduri-europene-agricultura.html`
- `fonduri-europene-agricultura/index.html`
- `fonduri-europene-bacau/index.html`
- `fonduri-europene-bucuresti/index.html`
- `fonduri-europene-caen/0111-culturi-cereale/index.html`
- `fonduri-europene-caen/4321-instalatii-electrice/index.html`
- `fonduri-europene-caen/5610-restaurante/index.html`
- `fonduri-europene-caen/6201-dezvoltare-software/index.html`
- `fonduri-europene-digitalizare.html`
- `fonduri-europene-digitalizare/index.html`
- `fonduri-europene-femei-antreprenor.html`
- `fonduri-europene-femei-antreprenor/index.html`
- `fonduri-europene-herambursabile-2026.html`
- `fonduri-europene-herambursabile-2026/index.html`
- `fonduri-europene-iasi/index.html`
- `fonduri-europene-imm.html`
- `fonduri-europene-imm/index.html`
- `fonduri-europene-nerambursabile-2026.html`
- `fonduri-europene-nerambursabile-2026/index.html`
- `fonduri-europene-nord-est/index.html`
- `fonduri-europene-suceava/index.html`
- `fonduri-europene.html`
- `fonduri-europene/index.html`
- `fonduri-nerambursabile.html`
- `fonduri-nerambursabile/index.html`
- `fonduri-pentru-ferme.html`
- `fonduri-pentru-ferme/index.html`
- `fonduri-pentru-utilaje-agricole.html`
- `fonduri-pentru-utilaje-agricole/index.html`
- `fonduri-regionale/index.html`
- `gal-afir/index.html`
- `gdpr.html`
- `ghiduri.html`
- `ghiduri/index.html`
- `glosar-fonduri-europene/index.html`
- `granturi-digitalizare-imm.html`
- `granturi-digitalizare-imm/index.html`
- `greseli-fonduri-europene.html`
- `greseli-fonduri-europene/index.html`
- `idei-afaceri-fonduri-europene.html`
- `index.html`
- `instrumente/index.html`
- `intrebari-frecvente.html`
- `intrebari-frecvente/index.html`
- `intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html`
- `intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html`
- `intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html`
- `investitii-modernizarea-microintreprinderilor-apel-2.html`
- `investitii-modernizarea-microintreprinderilor-apel-2/index.html`
- `management-proiecte-fonduri-europene/index.html`
- `metodologie-verificare-eligibilitate/index.html`
- `plan-de-afaceri-fonduri-europene/index.html`
- `pnrr-digitalizare-imm-cheltuieli-eligibile.html`
- `pnrr-digitalizare-imm.html`
- `pnrr-digitalizare-imm/index.html`
- `pnrr.html`
- `pnrr/index.html`
- `pocidif-21/index.html`
- `politica-de-confidentialitate.html`
- `por-adr-nord-est/index.html`
- `portofoliu/index.html`
- `pro-infra/index.html`
- `programul-tranzitie-justa-intrebari-documente/index.html`
- `programul-tranzitie-justa/index.html`
- `proiectare-fonduri-europene/index.html`
- `resurse-utile/index.html`
- `resurse/index.html`
- `start-up-nation-2026-cheltuieli-eligibile.html`
- `start-up-nation-2026-cheltuieli-eligibile/index.html`
- `start-up-nation-2026-conditii.html`
- `start-up-nation-2026-conditii/index.html`
- `start-up-nation-2026-idei-afaceri-plan.html`
- `start-up-nation-2026-idei-afaceri.html`
- `start-up-nation-2026-idei-afaceri/index.html`
- `start-up-nation-2026-plan-de-afaceri.html`
- `start-up-nation-2026-plan-de-afaceri/index.html`
- `start-up-nation-2026.html`
- `start-up-nation-2026/index.html`
- `start-up-nation.html`
- `start-up-nation/index.html`
- `startup-nation-2026-conditii.html`
- `studii-de-caz-fonduri-europene/index.html`
- `studii-de-caz.html`
- `studii-de-caz/index.html`
- `studiu-fezabilitate-fonduri-europene/index.html`
- `surse-oficiale-fonduri-europene/index.html`
- `termeni-si-conditii.html`
- `testimoniale.html`
- `testimoniale/index.html`
- `verificare-eligibilitate-fonduri-europene/index.html`
- `webinarii/index.html`

</details>

### Artefacte regenerate de comenzile cerute

- `sitemap.xml` — regenerare normală prin `npm run build`, 102 URL-uri canonice
- `feed.xml` — regenerare normală prin `npm run build`, 35 elemente canonice
- `reports/indexing-audit.json` — audit final cu `issueCount: 0`
- `reports/visual-integrity-report.json` și `reports/visual-screenshots/*.png` — regenerate de `npm run verify:visual`
- `reports/global-navigation-remediation-2026-07-13.md` — acest raport

Directorul `dist/` a fost regenerat de build și conține 162 de fișiere pentru validarea Cloudflare.

## Teste executate și rezultate

| Comandă | Rezultat |
| --- | --- |
| `node scripts/verify-global-header.js` | PASS — 172 pagini publice, 97 `index.html`, 19 destinații canonice; dialog și tastatură validate în Chromium |
| `node tools/audit-site-links.js` | PASS — 11.182 linkuri; 0 ținte lipsă; 0 ancore lipsă; 345 fragmente interactive verificate; 0 probleme interactive |
| `node tools/audit-indexing.js` | PASS — 102 URL-uri canonice; 105 ancore și 205 fragmente interactive verificate; 0 probleme |
| `npm run test:functional` | PASS — Functional navigation checks passed |
| `npm run verify:visual` | PASS — 26/26 verificări, 0 eșecuri |
| `npm run verify:seo-local` | PASS — 102 URL-uri sitemap și 10.007 linkuri interne |
| `npm run build` | PASS — 137 pagini verificate pentru profiluri, sitemap 102 URL-uri, feed 35 elemente, dist 162 fișiere |
| `npm run validate:cloudflare` | PASS — 120 reguli redirect, 9 reguli dinamice |
| `git diff --check` | PASS — fără erori de whitespace |

## Rezultat final

- Zero linkuri principale moarte în navbar.
- Zero apariții în HTML pentru `href="#servicii"`, `href="#finantare"`, `href="#blog"` și `href="#contact"`.
- Dialogul WhatsApp funcționează pe desktop și mobil, inclusiv cu tastatura și restaurarea focusului.
- Ancorele valide din conținut au rămas neschimbate și sunt verificate în pagina lor.
- Toate criteriile de acceptare solicitate au trecut.
