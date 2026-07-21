# Crawl tehnic SEO — după patch, înainte de deploy

- Mediu verificat: workspace local + worker Cloudflare executat în test
- Generat: 2026-07-21T13:29:31+03:00
- Stare producție: **nereverificată după deploy**; raportul live `before` rămâne referința până la publicare
- URL-uri canonice locale: 91
- URL-uri orfane: 0
- Pagini la adâncime mai mare de 3 clickuri: 0
- Linkuri interne rupte sau către redirect: 0
- Redirect loops/chains: 0
- URL-uri redirectate prezente în sitemap: 0
- Canonical-uri neconforme: 0
- Duplicate title/H1/meta description: 0
- Probleme tehnice blocante locale: 0

## Comparație înainte / după patch

| Criteriu | Producție înainte | După patch local | Stare |
|---|---:|---:|---|
| URL-uri din sitemap | 102 | 91 | Remediat în generator; deploy necesar |
| Variante `www` fără 301 direct | 102 | 0 în testul worker | Remediat în patch; deploy și recrawl necesare |
| Pagini orfane | 10 | 0 | Remediat prin linkuri interne contextuale |
| Linkuri interne rupte/către redirect | 0 | 0 | PASS |
| Redirect loops/chains | 0 | 0 | PASS |
| Canonical conflictual | 0 | 0 | PASS |
| Duplicate title/H1/meta | 0/0/0 după recrawl; auditul local a identificat un H1 suprascris de generator | 0/0/0 | Generatorul hero folosește acum programul rutei |
| 404/soft-404/5xx/resurse lipsă | 0 confirmate în crawl | 0 probleme locale | PASS |

## Remedieri confirmate

1. Workerul de domeniu acoperă acum `www.atelierdeconsultanta.ro/*` și trimite direct 301 către HTTPS non-www, păstrând calea și query-ul.
2. Cele 10 pagini orfane live au primit linkuri interne contextuale din hub-urile relevante; graful local ajunge la toate cele 91 de URL-uri canonice în maximum 3 clickuri.
3. `/fonduri-regionale` nu mai moștenește H1-ul și statusul rutei `/por-adr-nord-est`; generatorul preia datele programului asociat rutei curente.
4. Sitemap-ul local conține numai 91 de URL-uri 200, indexabile și self-canonical; redirecturile nu apar în sitemap.
5. URL-urile istorice fără destinație semantică aprobată rămân 404; testul interzice redirectarea lor automată către homepage.

## Semnale guvernate, neautomatizate

Auditul extins de indexare raportează separat 36 de apariții care nu sunt defecte tehnice rezolvabile fără decizie editorială:

- 29 de linkuri către 8 pagini de program ținute intenționat `noindex` până la validarea factuală: `/fondul-de-modernizare`, `/programul-tranzitie-justa`, `/dr12-afir`, `/dr14`, `/digitalizare-imm`, `/dr-14-afir-conditii-eligibilitate-greseli-frecvente`, `/dr-12-afir-instalarea-tinerilor-fermieri`, `/granturi-digitalizare-imm`;
- 7 linkuri către `/gdpr`, pagină indexabilă exclusă deliberat din sitemap până la aprobarea consolidării juridice către `/politica-de-confidentialitate`.

Aceste semnale rămân vizibile în `reports/indexing-audit.json` și în registrul de decizii. Nu s-au adăugat redirecturi semantice neaprobate.

## Acceptare și retest

- `npm run test:technical-seo` — PASS
- `npm run test:sitemap` — PASS
- `npm run validate:cloudflare` — PASS
- `npm run build` — PASS
- Retest producție: rulează `node tools/crawl-technical-seo.js --label=after-deploy --max-pages=500` imediat după deploy. Acceptarea live cere 0 variante `www` fără 301, 0 orfani și 0 probleme critice/high.
