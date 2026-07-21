# Poarta de lansare P0

Gate-ul este read-only față de conținutul site-ului. El rulează contractele locale, verifică staging-ul și producția, scrie raportul în `reports/` și întoarce cod diferit de zero când există un FAIL cu severitate `critical`.

## Comenzi

- `npm run test:p0-release-gate` — verifică structura și caracterul blocant al gate-ului.
- `npm run gate:p0:local` — verifică sursa și aprobările, fără acces de rețea.
- `npm run gate:p0:staging -- --staging-url=https://...` — verifică staging-ul configurat.
- `npm run gate:p0:production` — verifică producția fără a trimite lead-uri sau evenimente analytics.
- `npm run gate:p0` — rulează local → staging → producție. Dacă `P0_STAGING_URL` lipsește, folosește `dist` servit local și marchează mediul `staging-local-dist`.

Scripturile de deploy încep cu `gate:p0:local`; informațiile juridice/statusurile neverificate, formularul nefuncțional, PII analytics, redirecturile invalide și sitemap-ul eronat opresc deploy-ul înainte de Wrangler.

Comanda de build din `wrangler.jsonc` începe separat cu `gate:p0:deploy-guard`. Astfel, un build automat declanșat direct de push nu poate ocoli starea `BLOCKED` din ultimul raport și aprobările de guvernanță.

## Ordinea de lansare

1. Rulează gate-ul local și rezolvă numai prin aprobări sau fixuri P0 explicite, nu prin relaxarea testelor.
2. Publică într-un staging real și setează `P0_STAGING_URL`.
3. Rulează gate-ul de staging și completează QA-ul manual cu tastatură și screen reader.
4. După aprobarea release-ului, publică în producție.
5. Rulează gate-ul de producție și atașează raportul la release.

Submit-ul real în CRM nu este executat automat pe producție. Este necesar un endpoint/sink QA sau un flag server-side care garantează că lead-ul sintetic nu ajunge la echipa comercială; până atunci testul E2E de producție rămâne explicit de retestat.

Baseline-urile LCP/CLS provin din rapoartele Lighthouse existente. Nu există un baseline INP de teren aprobat; scriptul raportează o interacțiune sintetică și păstrează această limitare vizibilă.
