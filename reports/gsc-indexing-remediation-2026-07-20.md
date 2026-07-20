# Remediere GSC și baseline SEO — 20 iulie 2026

## Baseline Performance

Ferestrele nu se însumează, deoarece se suprapun.

| Fereastră | Clicuri | Impresii | CTR | Poziție medie ponderată |
|---|---:|---:|---:|---:|
| 7 zile | 16 | 1.617 | 0,99% | 9,83 |
| 28 zile | 76 | 7.140 | 1,06% | 9,51 |
| 3 luni | 318 | 16.494 | 1,93% | 9,60 |

În ultimele 28 de zile, `/dr12-afir` are 6 clicuri din 588 impresii, CTR 1,02% și poziția 7,71, iar `/dr14` are 3 clicuri din 267 impresii, CTR 1,12% și poziția 8,18. De aceea, titlurile și descrierile au fost orientate către întrebările decisive, fără pagini noi pentru variațiile aceleiași intenții.

## Page Indexing

Exportul Coverage primit conține agregate, nu exemple URL. Situația raportată este:

| Motiv | Pagini | Tratament |
|---|---:|---|
| Page with redirect | 73 | Excludere normală dacă aliasul este intenționat, direct și absent din sitemap/linkuri interne. |
| Alternate page with proper canonical | 11 | Excludere normală dacă semnalele canonicale sunt coerente. |
| Redirect error | 3 | Necesită cele trei exemple URL înainte de remediere și Validate Fix. |
| Excluded by noindex tag | 2 | Necesită cele două exemple URL pentru stabilirea intenției publice sau tehnice. |
| Duplicate without user-selected canonical | 1 | Necesită URL-ul exact și comparația canonicalului declarat cu cel ales de Google. |
| Crawled — currently not indexed | 1 | Necesită URL-ul exact, conținut unic, self-canonical, sitemap și două linkuri contextuale. |
| Discovered — currently not indexed | 3 | Validarea apare Passed; nu se redeschide fără un exemplu nou. |
| Duplicate, Google chose different canonical | 2 | Validarea apare Passed; nu se schimbă semnalele fără dovadă nouă. |

Registrul operațional este `reports/gsc-example-registry-2026-07-20.csv`. Cele șapte cazuri neidentificabile rămân marcate `PENDING_GSC_EXAMPLE`; niciunul nu este declarat rezolvat.

## Exemple confirmate din capturile GSC

Capturile din 20 iulie 2026 confirmă încă trei exemple, distincte de cele șapte cazuri fără URL din export:

| Categorie | URL | Diagnostic | Acțiune |
|---|---|---|---|
| Alternate page with proper canonical tag | `http://atelierdeconsultanta.ro/` | Problemă reală: varianta HTTP răspunde `200`, deși declară canonical HTTPS. | Redirect Cloudflare `301` către aceeași cale HTTPS, cu query păstrat. |
| Page with redirect | `https://atelierdeconsultanta.ro/?s={search_term_string}` | URL moștenit din vechea schemă SearchAction; nu este în sitemap sau în linkurile interne. Curățarea client-side nu schimbă răspunsul inițial `200`. | Redirect Cloudflare `301` către homepage fără parametrul `s`; SearchAction rămâne absent din HTML. |
| Page with redirect | `https://atelierdeconsultanta.ro/calendar-fonduri-europene/` | Aliasul cu trailing slash face un singur `301` către URL-ul canonic și este exclus intenționat. | Nu se schimbă. Acesta este un rezultat GSC normal, nu o pagină care trebuie făcută indexabilă. |

Validarea întregii categorii „Page with redirect” nu trebuie folosită pentru a forța indexarea aliasurilor. Categoria va continua corect să conțină URL-uri redirecționate; se validează doar o eroare de redirect după ce răspunsul live a fost remediat.

## Reguli de decizie

- Redirect greșit: 301 într-un singur hop către echivalentul semantic; 410 dacă resursa este retrasă fără echivalent; niciodată redirect general către homepage.
- Noindex: se păstrează pentru admin și resurse tehnice; se elimină de pe o pagină publică doar după confirmarea URL-ului, statusului și canonicalului.
- Duplicat: 301 pentru un alias redundant; 200 și self-canonical numai pentru o intenție și un conținut distincte.
- Crawled-not-indexed: 200, conținut unic, self-canonical, sitemap și minimum două legături contextuale înainte de cererea de indexare.
- Validate Fix se pornește numai pentru rândurile completate și verificate live din registru.

## Limită operațională

La data auditului, `http://atelierdeconsultanta.ro/` răspundea 200. Setarea Always Use HTTPS sau regula permanentă echivalentă trebuie activată în zona Cloudflare și retestată înainte de HSTS. Configurația exactă este documentată în `docs/cloudflare-seo-domain-settings.md`.
