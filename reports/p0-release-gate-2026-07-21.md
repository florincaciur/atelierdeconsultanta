# P0.16 — Release gate

Data: 2026-07-22T00:20:09.241Z

Decizie: **PASS**

- PASS: 11
- FAIL: 1
- Blocaje critice: 0
- Staging: nerulat

| Criteriu | Mediu | Status | Severitate | Owner | URL/dovadă | Rezultat | Retest |
|---|---|---|---|---|---|---|---|
| program_status | local | **PASS** | critical | Consultant FABER + Content owner | program:dr12-afir<br>program:dr14-afir<br>program:pro-infra<br>program:digitalizare-imm | Poarta P0.02: rândurile aprobate sunt publice, cele disputate rămân blocate și validarea nominală este obligatorie. | Reexecută verificarea program_status după remediere/aprobare. |
| factual_sources | local | **PASS** | critical | Consultant fonduri + Editor senior | config/seo-programs.json | Contract registru: 20 programe verificate pe meniu, homepage, carduri, pagini și JSON-LD. | Reexecută verificarea factual_sources după remediere/aprobare. |
| legal_identity | local | **PASS** | critical | Business owner + Jurist | /despre-faber<br>/contact<br>/politica-de-confidentialitate<br>/termeni-si-conditii | Poartă identitate juridică: 16 câmpuri și 11 suprafețe aprobate nominal. | Reexecută verificarea legal_identity după remediere/aprobare. |
| contact_privacy | local | **PASS** | critical | Jurist + Product owner | /contact<br>/politica-de-confidentialitate | Contact triage validation PASS (structural). | Reexecută verificarea contact_privacy după remediere/aprobare. |
| form_flow | local | **PASS** | critical | Frontend + CRM owner | /contact<br>/api/contact-triage | Contact triage static contract PASS Contact triage server contract PASS Contact triage browser and no-JS flow PASS | Reexecută verificarea form_flow după remediere/aprobare. |
| analytics | local | **PASS** | critical | Analytics owner + Backend | assets/analytics-events.js | Analytics browser checks passed: 9 sanitized events, 50% CTA threshold and server-confirmed submit. \| CRM funnel contract passed: authenticated qualified_lead forwarding contains only non-PII fields. | Reexecută verificarea analytics după remediere/aprobare. |
| redirects | local | **PASS** | critical | SEO lead + Backend | _redirects | Redirect map PASS: 122 rules, 0 loops, 0 chains, 0 sitemap redirects, 0 internal links to redirects. \| Cloudflare domain SEO worker tests passed. | Reexecută verificarea redirects după remediere/aprobare. |
| sitemap | local | **PASS** | critical | Technical SEO | /sitemap.xml | Verified sitemap index with 95 canonical URLs; 17 verified lastmod values. | Reexecută verificarea sitemap după remediere/aprobare. |
| editorial | local | **PASS** | high | Editor coordonator | /sitemap.xml | Editorial copy contract passed: 95 canonical URLs, zero forbidden template labels or control-list forms. \| Editorial terminology contract passed: 95 canonical URLs and 10 P0.14 surfaces. | Reexecută verificarea editorial după remediere/aprobare. |
| robots | local | **PASS** | critical | Business owner + Technical SEO | /robots.txt | Crawler policy contract passed: OAI/Perplexity/GPTBot allowed by policy, private paths protected. | Reexecută verificarea robots după remediere/aprobare. |
| accessibility | local | **PASS** | high | Accessibility QA + Frontend | /contact | Contact accessibility static and canonical-contact contract PASS Contact accessibility error summary, focus, ARIA and keyboard order PASS Contact accessibility loading and double-submit prevention PASS Contact accessibility network retry and value preservation PASS Contact accessibility 320px reflow, 200% text zoom and target sizes PASS | Reexecută verificarea accessibility după remediere/aprobare. |
| performance | local | **FAIL** | high | Frontend performance owner | /<br>/fonduri-europene<br>/consultanta-fonduri-europene<br>/digitalizare-imm | Baseline LCP/CLS prezent pentru 4 rute; baseline INP=DE_VALIDAT_UMAN. | Salvați un baseline INP aprobat înainte de deploy și comparați aceeași interacțiune/viewport. |

## Regula de lansare

Orice FAIL critic blochează deploy-ul. FAIL-urile high necesită owner și retest documentat înainte de aprobarea finală. Gate-ul nu modifică conținutul și nu trimite lead-uri reale în producție.
