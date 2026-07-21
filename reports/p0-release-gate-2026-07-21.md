# P0.16 — Release gate

Data: 2026-07-21T17:59:19.634Z

Decizie: **BLOCKED**

- PASS: 7
- FAIL: 5
- Blocaje critice: 4
- Staging: nerulat

| Criteriu | Mediu | Status | Severitate | Owner | URL/dovadă | Rezultat | Retest |
|---|---|---|---|---|---|---|---|
| program_status | local | **FAIL** | critical | Consultant FABER + Content owner | /dr12-afir<br>/dr-12-afir-instalarea-tinerilor-fermieri<br>/dr14<br>/dr-14-afir-conditii-eligibilitate-greseli-frecvente<br>/pro-infra<br>/digitalizare-imm<br>/granturi-digitalizare-imm | 4 programe prioritare nu au validare nominală FABER: dr12-afir, dr14-afir, pro-infra, digitalizare-imm. Contract tehnic: PASS. Poarta P0.02: 4 programe blocate, suprafețe factuale eliminate și validare nominală obligatorie. | Consultantul FABER aprobă fiecare rând, apoi se rerulează gate-ul complet. |
| factual_sources | local | **PASS** | critical | Consultant fonduri + Editor senior | config/seo-programs.json | Contract registru: 20 programe verificate pe meniu, homepage, carduri, pagini și JSON-LD. | Reexecută verificarea factual_sources după remediere/aprobare. |
| legal_identity | local | **FAIL** | critical | Business owner + Jurist | /despre-faber<br>/contact<br>/politica-de-confidentialitate<br>/termeni-si-conditii | Fișa juridică este blocked; avizul juridic este pending. Contract tehnic: PASS. Poartă identitate juridică: 16 câmpuri și 11 suprafețe rămân blocate până la aprobarea umană și avizul juristului. | Completați fișa canonică și avizul juridic fără a inventa valori, apoi rerulați gate-ul. |
| contact_privacy | local | **FAIL** | critical | Jurist + Product owner | /contact<br>/politica-de-confidentialitate | Copy Privacy=pending_legal_approval; confirmare email operațional=pending. Contract tehnic: PASS. Contact triage validation PASS (structural). | Juristul aprobă regula email SAU telefon și proprietarul confirmă datele canonice. |
| form_flow | local | **PASS** | critical | Frontend + CRM owner | /contact<br>/api/contact-triage | Contact triage static contract PASS Contact triage server contract PASS Contact triage browser and no-JS flow PASS | Reexecută verificarea form_flow după remediere/aprobare. |
| analytics | local | **PASS** | critical | Analytics owner + Backend | assets/analytics-events.js | Analytics browser checks passed: 9 sanitized events, 50% CTA threshold and server-confirmed submit. \| CRM funnel contract passed: authenticated qualified_lead forwarding contains only non-PII fields. | Reexecută verificarea analytics după remediere/aprobare. |
| redirects | local | **PASS** | critical | SEO lead + Backend | _redirects | Redirect map PASS: 122 rules, 0 loops, 0 chains, 0 sitemap redirects, 0 internal links to redirects. \| Cloudflare domain SEO worker tests passed. | Reexecută verificarea redirects după remediere/aprobare. |
| sitemap | local | **PASS** | critical | Technical SEO | /sitemap.xml | Verified sitemap index with 91 canonical URLs; 13 verified lastmod values. | Reexecută verificarea sitemap după remediere/aprobare. |
| editorial | local | **PASS** | high | Editor coordonator | /sitemap.xml | Editorial copy contract passed: 91 canonical URLs, zero forbidden template labels or control-list forms. \| Editorial terminology contract passed: 91 canonical URLs and 10 P0.14 surfaces. | Reexecută verificarea editorial după remediere/aprobare. |
| robots | local | **FAIL** | critical | Business owner + Technical SEO | /robots.txt | Regula tehnică GPTBot este disallow, dar aprobarea de business este DE_VALIDAT_UMAN. Contract tehnic: PASS. Crawler policy contract passed: OAI/Perplexity search allowed, GPTBot training blocked, private paths protected. | Ownerul aprobă explicit politica GPTBot; nu modificați regula de training automat. |
| accessibility | local | **PASS** | high | Accessibility QA + Frontend | /contact | Contact accessibility static and canonical-contact contract PASS Contact accessibility error summary, focus, ARIA and keyboard order PASS Contact accessibility loading and double-submit prevention PASS Contact accessibility network retry and value preservation PASS Contact accessibility 320px reflow, 200% text zoom and target sizes PASS | Reexecută verificarea accessibility după remediere/aprobare. |
| performance | local | **FAIL** | high | Frontend performance owner | /<br>/fonduri-europene<br>/consultanta-fonduri-europene<br>/digitalizare-imm | Baseline LCP/CLS prezent pentru 4 rute; baseline INP=DE_VALIDAT_UMAN. | Salvați un baseline INP aprobat înainte de deploy și comparați aceeași interacțiune/viewport. |

## Regula de lansare

Orice FAIL critic blochează deploy-ul. FAIL-urile high necesită owner și retest documentat înainte de aprobarea finală. Gate-ul nu modifică conținutul și nu trimite lead-uri reale în producție.
