# REPORT SEO

Data: 2026-06-19
Branch: `seo-content`

## Rezumat

- Am extins continutul din `config/seo-programmatic-pages.json` pentru toate cele 12 intrari programatice cu `body` peste 1.100 de cuvinte si minimum 6 intrebari FAQ.
- Am actualizat generatorul `tools/generate-programmatic-seo.js` ca paginile generate sa poata folosi `body` si `faq` configurate, pastrand completarea automata de profunzime.
- Am actualizat `blog.json`, `blog/index.html` si paginile canonice de blog cu titluri, descrieri, imagini WebP si schema `Article`/`BlogPosting` + `BreadcrumbList`.
- Am adaugat linkuri interne semantice intre articolele Start-Up Nation si paginile `/fonduri-europene` si `/consultanta-fonduri-europene`.
- Am reparat problemele de content depth pentru `/pro-infra` si `/studii-de-caz-fonduri-europene`.
- Am rezolvat duplicarile de title/description raportate de auditul de indexare pentru 4 articole de blog.

## Surse oficiale folosite

- AFIR DR12: https://www.afir.ro/comunicate/consultare-publica-pentru-consolidarea-exploatatiilor-tinerilor-fermieri/
- MIPE Digitalizare IMM / PNRR: https://mfe.gov.ro/ghidul-specific-conditii-de-accesare-a-fondurilor-europene-aferente-planului-national-de-redresare-si-rezilienta-in-cadrul-apelului-de-proiecte-digitalizarea-imm-urilor-grant-de-pana-la-100-000-e/
- ADR Nord-Est Apel 2 microintreprinderi: https://adrnordest.ro/comentariiGhid/P1Microintreprinderi/Apel2/
- Ministerul Economiei Start-Up Nation: https://economie.gov.ro/participa-la-definitivarea-procedurii-de-implementare-a-programului-de-succes-start-up-nation-editia-2024/
- Ministerul Economiei Femeia Antreprenor: https://economie.gov.ro/pe-data-de-30-iulie-se-da-startul-inscrierilor-in-cadrul-programului-femeia-antreprenor/
- PRO INFRA: https://legislatie.just.ro/Public/DetaliiDocument/306391

## Pagini programatice actualizate

- `/fonduri-europene-caen/6201-dezvoltare-software`
- `/fonduri-europene-caen/5610-restaurante`
- `/fonduri-europene-caen/4321-instalatii-electrice`
- `/fonduri-europene-caen/0111-culturi-cereale`
- `/fonduri-europene-iasi` (configuratie consolidata catre Nord-Est)
- `/fonduri-europene-suceava` (configuratie consolidata catre Nord-Est)
- `/fonduri-europene-bacau` (configuratie consolidata catre Nord-Est)
- `/fonduri-europene-bucuresti`
- `/consultanta-fonduri-europene-bucuresti`
- `/fonduri-europene-nord-est`
- `/intrebari/ce-documente-sunt-necesare-pentru-dr12`
- `/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm`
- `/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene`

## Pagini de blog actualizate

- `/blog`
- `/start-up-nation-2026-conditii`
- `/cod-caen-start-up-nation-2026`
- `/start-up-nation-2026-cheltuieli-eligibile`
- `/digitalizare-imm-erp-crm-cloud`
- `/cheltuieli-eligibile-digitalizare-imm`
- `/dr12-afir`
- `/dr14-afir-ferme-mici`
- `/calculator-soc`
- `/dr12-vs-dr14`
- `/cand-merita-consultant-fonduri-europene`
- `/cat-costa-consultanta-fonduri-europene-ghid`
- `/cum-se-verifica-eligibilitatea-fonduri-europene`
- `/ce-acte-sunt-necesare-fonduri-europene`
- `/cum-se-calculeaza-cofinantarea-fonduri-europene`
- `/cum-alegi-programul-potrivit-fonduri-europene-2026`
- `/acte-necesare-fonduri-europene-nerambursabile`
- `/dr-14-afir-conditii-eligibilitate-greseli-frecvente`
- `/dr-12-afir-instalarea-tinerilor-fermieri`
- `/start-up-nation-2026-idei-afaceri`
- `/femeia-antreprenor-2026-conditii-idei-afaceri`
- `/pnrr-digitalizare-imm-cheltuieli-eligibile`
- `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum`
- `/dr14`
- `/start-up-nation-2026`
- `/femeia-antreprenor-2026`
- `/digitalizare-imm`
- `/por-adr-nord-est`
- `/investitii-modernizarea-microintreprinderilor-apel-2`
- `/fondul-modernizare-energie-regenerabila-2026`
- `/afir-autoconsum-agroalimentar`
- `/autoconsum-public-fotovoltaice-institutii-publice`
- `/pro-infra`
- `/apeluri-gal`
- `/e-move`
- `/gal-afir`
- `/pocidif-21`

## Imagini si schema

- Imaginile din `/assets/hero/` sunt folosite ca WebP in `blog.json` si in paginile de blog.
- `blog/index.html` are `alt`, `width`, `height`, `loading` si `decoding` pentru imaginile de post.
- Rutele canonice de blog au schema `Article` sau `BlogPosting` si `BreadcrumbList`.
- `blog.json` are 37 postari cu `metaDescription` intre 120 si 160 de caractere si `bannerAlt` descriptiv.

## Audit final

- `node tools/audit-content-depth.js`: PASS, 172 randuri HTML, fara pagini indexabile sub prag.
- `node tools/audit-site-links.js`: PASS, 4.286 linkuri locale, 0 tinte lipsa, 0 ancore lipsa, 0 redirect issues.
- `node tools/audit-gsc-routes.js`: PASS, 39 randuri GSC auditate si raport scris in `reports/gsc-indexing-fix-2026-06-10.*`.
- `node tools/verify-sitemap.js`: PASS, 95 URL-uri canonice.
- `node tools/validate-seo-local.js`: PASS, 95 URL-uri din sitemap si 3.593 linkuri interne.
- `node tools/audit-structured-data.js`: PASS, 172 fisiere, 0 probleme schema.
- `node tools/audit-indexing.js`: PASS, 95 URL-uri din sitemap verificate.

