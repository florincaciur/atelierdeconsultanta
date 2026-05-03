# SEO_NOTES

Data auditului: 2026-04-30

## /index.html și canonical

Homepage-ul canonic este `https://atelierdeconsultanta.ro/`. Fișierul fizic `index.html` rămâne necesar pentru hosting static, dar are canonical către `/`:

```html
<link rel="canonical" href="https://atelierdeconsultanta.ro/">
```

Nu există linkuri interne publice către `/index.html`, iar `sitemap.xml` nu include `https://atelierdeconsultanta.ro/index.html`.

Pe GitHub Pages nu există un mecanism nativ de redirect 301 pentru `/index.html` către `/`. Soluția corectă aplicată este: linkuri interne către `/`, canonical corect pe homepage și excluderea `/index.html` din sitemap. Dacă site-ul este mutat pe un hosting cu reguli de redirect, recomandarea este redirect 301 permanent de la `/index.html` la `/`.

## /admin/ și robots.txt

`/admin/` trebuie să rămână neindexat. Alerta Ubersuggest „Blocked [Robots.txt]” pentru `/admin/` este intenționată și nu trebuie reparată prin deblocarea adminului.

Măsuri aplicate:

- `robots.txt` permite crawl pentru site-ul public și blochează `/admin/`.
- `/admin/index.html` are `<meta name="robots" content="noindex,nofollow">`.
- `/admin/` nu este în `sitemap.xml`.

## Blog thin content

`blog.html` a fost verificat ca hub SEO static, cu peste 1.200 de cuvinte crawlable în HTML, H1 unic și secțiuni despre fonduri europene, AFIR DR12/DR14, Start-Up Nation, Femeia Antreprenor, PNRR Digitalizare, Fondul de Modernizare și FAQ.

## Articole create sau finalizate

Au fost finalizate 8 articole statice crawlable:

- `cum-alegi-programul-potrivit-fonduri-europene-2026.html`
- `acte-necesare-fonduri-europene-nerambursabile.html`
- `dr-14-afir-conditii-eligibilitate-greseli-frecvente.html`
- `dr-12-afir-instalarea-tinerilor-fermieri.html`
- `start-up-nation-2026-idei-afaceri-plan.html`
- `femeia-antreprenor-2026-conditii-idei-afaceri.html`
- `pnrr-digitalizare-imm-cheltuieli-eligibile.html`
- `fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html`

Fiecare articol are peste 1.200 de cuvinte, canonical, meta title, meta description, H1 unic, schema `BlogPosting`, schema `FAQPage`, breadcrumb schema, linkuri interne și CTA prudent către contact/evaluare.

## Sitemap

`sitemap.xml` include homepage, paginile publice de programe/servicii, `blog.html`, cele 8 articole, calculatorul SO, contactul și paginile legale. Nu include `/admin/`, `/index.html`, drafturi, asseturi, JS/CSS sau pagini duplicate.

## Tabel title/canonical

| Fișier/URL | Title final | Lungime | Canonical |
|---|---:|---:|---|
| `/` | Consultanță Fonduri Europene Nerambursabile \| FABER | 51 | `https://atelierdeconsultanta.ro/` |
| `/consultanta-fonduri-europene/` | Consultanță fonduri europene \| FABER | 38 | `https://atelierdeconsultanta.ro/consultanta-fonduri-europene/` |
| `/fonduri-europene-nerambursabile-2026/` | Fonduri europene nerambursabile 2026 \| FABER | 48 | `https://atelierdeconsultanta.ro/fonduri-europene-nerambursabile-2026/` |
| `/blog.html` | Blog Fonduri Europene \| FABER – Atelier de Consultanță | 54 | `https://atelierdeconsultanta.ro/blog.html` |
| `/calculator-soc.html` | Calculator SO AFIR DR12 DR14 \| FABER | 37 | `https://atelierdeconsultanta.ro/calculator-soc.html` |
| `/dr12-afir.html` | DR 12 AFIR – Instalarea Tinerilor Fermieri \| FABER | 50 | `https://atelierdeconsultanta.ro/dr12-afir.html` |
| `/start-up-nation-2026.html` | Start-Up Nation 2026 – Finanțare Antreprenori \| FABER | 53 | `https://atelierdeconsultanta.ro/start-up-nation-2026.html` |
| `/femeia-antreprenor-2026.html` | Femeia Antreprenor 2026 – Finanțare IMM \| FABER | 47 | `https://atelierdeconsultanta.ro/femeia-antreprenor-2026.html` |
| `/digitalizare-imm.html` | Digitalizare IMM 2026 \| FABER – Atelier de Consultanță | 54 | `https://atelierdeconsultanta.ro/digitalizare-imm.html` |
| `/digitalizare-imm-pnrr/` | Digitalizare IMM / PNRR \| FABER | 32 | `https://atelierdeconsultanta.ro/digitalizare-imm-pnrr/` |
| `/fondul-de-modernizare/` | Fondul de Modernizare \| FABER | 29 | `https://atelierdeconsultanta.ro/fondul-de-modernizare/` |
| `/afir-autoconsum-agroalimentar.html` | AFIR Autoconsum Agroalimentar – Fotovoltaice \| FABER | 52 | `https://atelierdeconsultanta.ro/afir-autoconsum-agroalimentar.html` |
| `/autoconsum-public-fotovoltaice-institutii-publice.html` | Fotovoltaice Entități Publice \| Fondul de Modernizare | 53 | `https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice.html` |
| `/por-adr-nord-est.html` | POR Micro Nord-Est 2021-2027 \| FABER Consultanță | 48 | `https://atelierdeconsultanta.ro/por-adr-nord-est.html` |
| `/pro-infra.html` | PRO INFRA – Materiale Construcții Infrastructură \| FABER | 56 | `https://atelierdeconsultanta.ro/pro-infra.html` |
| `/contact/` | Contact FABER \| Evaluare fonduri europene | 42 | `https://atelierdeconsultanta.ro/contact/` |
| `/cum-alegi-programul-potrivit-fonduri-europene-2026.html` | Cum alegi fonduri europene în 2026 \| FABER | 42 | `https://atelierdeconsultanta.ro/cum-alegi-programul-potrivit-fonduri-europene-2026.html` |
| `/acte-necesare-fonduri-europene-nerambursabile.html` | Acte necesare fonduri europene \| Ghid dosar | 43 | `https://atelierdeconsultanta.ro/acte-necesare-fonduri-europene-nerambursabile.html` |
| `/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` | DR 14 AFIR – Condiții și greșeli frecvente | 42 | `https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html` |
| `/dr-12-afir-instalarea-tinerilor-fermieri.html` | DR 12 AFIR – Instalarea tinerilor fermieri | 42 | `https://atelierdeconsultanta.ro/dr-12-afir-instalarea-tinerilor-fermieri.html` |
| `/start-up-nation-2026-idei-afaceri-plan.html` | Start-Up Nation 2026 – Idei și plan de afaceri | 46 | `https://atelierdeconsultanta.ro/start-up-nation-2026-idei-afaceri-plan.html` |
| `/femeia-antreprenor-2026-conditii-idei-afaceri.html` | Femeia Antreprenor 2026 – Condiții și idei | 42 | `https://atelierdeconsultanta.ro/femeia-antreprenor-2026-conditii-idei-afaceri.html` |
| `/pnrr-digitalizare-imm-cheltuieli-eligibile.html` | PNRR Digitalizare IMM – Cheltuieli eligibile | 44 | `https://atelierdeconsultanta.ro/pnrr-digitalizare-imm-cheltuieli-eligibile.html` |
| `/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html` | Fondul de Modernizare – Energie și autoconsum | 45 | `https://atelierdeconsultanta.ro/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum.html` |

## Pași după deploy

1. Verifică live `https://atelierdeconsultanta.ro/robots.txt`.
2. Verifică live `https://atelierdeconsultanta.ro/sitemap.xml`.
3. Inspectează homepage canonical în sursa HTML.
4. Retrimite sitemapul în Google Search Console.
5. Retrimite sitemapul în Bing Webmaster Tools.
6. În Google Search Console, rulează Validate Fix pentru raportarea `/index.html`.

## Notă despre artefacte vechi

Există în proiect o copie descărcată a site-ului (`FABER – Atelier de Consultanță _ Fonduri Europene.html` și folderul asociat). Nu este inclusă în sitemap și nu este tratată ca pagină publică principală. Recomandat: exclude din deploy sau mută într-o arhivă în afara rădăcinii publice înainte de publicare.
