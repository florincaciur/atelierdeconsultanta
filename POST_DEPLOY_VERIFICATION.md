# Post Deploy Verification

## Summary

**Commit referit în task:** b7d356b (nu există local — folderul nu are `.git`)
**Dată verificare:** 2026-05-03
**Verificat de:** Claude Code — inspecție manuală + server local Python + WebFetch live
**Status general:** PARTIAL — marea majoritate a afirmațiilor din SEO_AUDIT_FIXES.md sunt confirmate; au fost detectate și remediate 41 de pagini redirect cu `robots: index, follow` în loc de `noindex, follow`; două afirmații din raport sunt inexacte sau parțial incorecte.

---

### Probleme confirmate ca rezolvate (din raport)

- Linkuri interne la `/dr14.html` și `/autoconsum-publici.html` eliminate din navigație/conținut
- Fallback pages pentru `/contact.html` și `/consultanta-fonduri-europene.html` prezente
- `og-image.jpg` prezent (79 KB) și referit corect în toate huburile și homepage
- Formspree CDN eliminat din homepage — confirmat
- `blog.json` fără cache-busting — confirmat (`fetch('/blog.json')` fără timestamp)
- Phosphor Icons amânat — confirmat (deși folosind interaction events, nu `window.load`)
- `robots.txt` complet cu toate bot-urile AI solicitate
- `llms.txt` reconstruit cu URL-uri canonice, fără afirmații de rată de succes
- 30 hub-uri SEO prezente, toate cu `index.html`, returnând 200 local
- `sitemap.xml` cu 58 URL-uri canonice, fără typo-uri, fără URL-uri fallback
- `_redirects` cu toate regulile 301 solicitate
- Admin sitemap generator folosind URL-uri canonice corecte
- JSON-LD valid în toate paginile publice (80 blocuri valide, 0 invalide publice)
- Nicio schemă Review/AggregateRating introdusă

### Probleme reparate în această verificare

- **41 pagini redirect/fallback** aveau `meta name="robots" content="index, follow"` — corectat la `noindex, follow` în toate

### Probleme rămase sau ne-reparabile din repo

1. **HTTP 301 real nu este posibil pe GitHub Pages** — `_redirects` nu este aplicat. Fallback-urile HTML funcționează ca redirect soft via JS/meta-refresh.
2. **Afirmația din raport despre `loading="lazy"` și `decoding="async"` pe imaginile blog** este incorectă — imaginile card sunt CSS `background-image`, nu `<img>`. Nu pot primi aceste atribute HTML. În practică, impact minim (imaginile sunt sub fold și încărcate dinamic de JS).
3. **Afirmația din raport despre Phosphor Icons „după window.load"** este parțial inexactă — implementarea reală folosește interaction events (`pointerdown`, `mousemove`, `keydown`, `touchstart`, `scroll`). Este o abordare mai bună decât `window.load`, dar diferită de ce s-a declarat.
4. **Statistici și testimoniale homepage neconfirmate:** „250+ proiecte aprobate", „98% rată de succes", „45M€+", testimoniale cu nume generice (`Mihai Ionescu / TechProd SRL`, etc.) există în conținut vizibil și în JSON-LD FAQ. Nu au fost introduse de commitul verificat, dar sunt prezente. Necesită confirmare din date reale sau retragere.
5. **Discrepanță sitemap local vs live:** sitemap.xml local = 58 URL-uri; sitemap.xml live la momentul verificării = 66 URL-uri (probabil articole de blog publicate ulterior prin admin).

---

## Verification Matrix

| Item | Expected | Method | Result | Evidence | Fix Applied |
|------|----------|--------|--------|----------|-------------|
| Git repo / commit b7d356b | commit local | `git log` | N/A | Folderul nu are `.git`; fișierele există cu date mai 2026-05-03 | — |
| Stack: HTML static | HTML/CSS/JS pur | `ls` root | PASS | Nicio dependință build; CNAME, robots, sitemap prezente | — |
| Deployment probabil | GitHub Pages | CNAME + .github/ | PASS | `CNAME=atelierdeconsultanta.ro`, `.github/workflows/` prezent | — |
| Linkuri interne la /dr14.html | Absent din nav/conținut | scan Python href | PASS | 0 referințe în pagini non-fallback | — |
| Linkuri interne la /autoconsum-publici.html | Absent | scan Python href | PASS | 0 referințe în pagini non-fallback | — |
| Linkuri interne la /contact.html | Absent (excl. fallback) | scan Python href | PASS | 0 referințe active | — |
| Linkuri interne la /consultanta-fonduri-europene.html | Absent (excl. fallback) | scan Python href | PASS | 0 referințe active | — |
| Resurse locale lipsă | 0 | scan Python src/href | PASS | 0 fișiere lipsă | — |
| Fallback contact.html | Canonical + redirect | citire fișier | PASS | canonical=/contact/, JS redirect, noindex (fixat) | noindex aplicat |
| Fallback consultanta-fonduri-europene.html | Canonical + redirect | citire fișier | PASS | canonical=/consultanta-fonduri-europene/, noindex (fixat) | noindex aplicat |
| Fallback dr14.html | Canonical + redirect | citire fișier | PASS | canonical=/dr-14-afir-..., noindex (fixat) | noindex aplicat |
| Fallback autoconsum-publici.html | Canonical + redirect | citire fișier | PASS | canonical=/autoconsum-public-..., noindex (fixat) | noindex aplicat |
| Toate fallback-urile au noindex | noindex, follow | scan Python | PASS (după fix) | 41 fișiere corectate | Da, 41 fișiere |
| _redirects: /dr14.html → canonical | 301 prezent | citire fișier | PASS | linia 2 din _redirects | — |
| _redirects: /contact.html → /contact/ | 301 prezent | citire fișier | PASS | linia 3 | — |
| _redirects: /contact → /contact/ | 301 prezent | citire fișier | PASS | linia 4 | — |
| _redirects: /consultanta-fonduri-europene.html | 301 prezent | citire fișier | PASS | linia 5 | — |
| _redirects: /fonduri-europene-herambursabile-2026/ | 301 prezent | citire fișier | PASS | liniile 9-10 | — |
| _redirects: /fonduri-europene-nerambursabile-2026.html | 301 prezent | citire fișier | PASS | linia 11 | — |
| _redirects: .html → / pentru toate hub-urile | 301 prezente | citire fișier | PASS | liniile 12-43 | — |
| HTTP 301 real pe GitHub Pages | N/A | arhitectură | PARTIAL | GitHub Pages nu aplică _redirects; fallback HTML prezent | — |
| Sitemap: 58 URL-uri | 58 | `grep -c <loc>` | PASS | 58 confirmat local | — |
| Sitemap: toate HTTPS | Da | grep | PASS | niciun http:// | — |
| Sitemap: fără herambursabile | Da | grep | PASS | 0 rezultate | — |
| Sitemap: fără URL-uri fallback | Da | verificat manual | PASS | contact.html/dr14.html/etc. absente | — |
| Sitemap: toate 200 local | Da | Python + server | PASS | 58/58 returnează 200 | — |
| Sitemap live vs local | Concordanță | WebFetch | PARTIAL | live: 66 URL-uri, local: 58 (posibil articole noi publicate) | — |
| robots.txt: Googlebot | Allow | citire fișier | PASS | linia prezentă | — |
| robots.txt: Bingbot | Allow | citire fișier | PASS | linia prezentă | — |
| robots.txt: OAI-SearchBot | Allow | citire fișier | PASS | linia prezentă | — |
| robots.txt: ChatGPT-User | Allow | citire fișier | PASS | linia prezentă | — |
| robots.txt: PerplexityBot | Allow | citire fișier | PASS | linia prezentă | — |
| robots.txt: Disallow /admin/ | Da | citire fișier | PASS | toate user-agents blochează /admin/ | — |
| robots.txt: Sitemap URL corect | HTTPS | citire fișier | PASS | `Sitemap: https://atelierdeconsultanta.ro/sitemap.xml` | — |
| llms.txt: URL-uri canonice | Da | citire fișier | PASS | toate URL-urile sunt HTTPS cu trailing slash corecte | — |
| llms.txt: fără rate de succes | Da | citire fișier | PASS | secțiunea „Note" avertizează explicit | — |
| llms.txt: pagini principale incluse | Da | citire fișier | PASS | contact, consultanta, afir, pnrr, start-up-nation, calendar, ghiduri, intrebari incluse | — |
| JSON-LD: toate blocurile valide | Da | Python json.loads | PASS | 80 valide, 0 invalide (admin = false positive) | — |
| JSON-LD: nicio schemă Review | Da | Python grep | PASS | 0 Review/AggregateRating | — |
| 30 hub-uri: index.html prezent | Da | bash for loop | PASS | toate 30 prezente | — |
| 30 hub-uri: returnează 200 | Da | curl local | PASS | toate 200 | — |
| Hub fonduri-europene/: H1+title+canonical+desc | Da | Python check | PASS | toate prezente, HTTPS canonical | — |
| Hub afir/: H1+title+canonical+desc | Da | Python check | PASS | toate prezente | — |
| Hub pnrr/: H1+title+canonical+desc | Da | Python check | PASS | toate prezente | — |
| Hub start-up-nation/: elemente SEO | Da | Python check | PASS | toate prezente | — |
| Hub-uri: breadcrumb vizibil | Da | inspecție cod | PASS | `.breadcrumb` prezent în toate hub-urile verificate | — |
| Hub-uri: CTA vizibil | Da | inspecție cod | PASS | btn btn-primary → /contact/ prezent | — |
| Hub-uri: FAQ vizibil în HTML | Da | inspecție cod | PASS | secțiunile `.faq-item` prezente, concordanță cu FAQPage schema | — |
| og-image.jpg: există | Da | `ls -lh` | PASS | 79 KB prezent | — |
| og-image.jpg: referit în OG meta | Da | grep | PASS | homepage + toate hub-urile verificate | — |
| Formspree CDN eliminat din homepage | Da | grep formspree | PASS | 0 referințe în index.html | — |
| blog.json fără cache-busting | Da | grep fetch | PASS | `fetch('/blog.json')` simplu, fără timestamp | — |
| Phosphor Icons amânat | window.load | citire cod | PARTIAL | Implementat pe interaction events, nu window.load — mai bun în practică | — |
| Blog card images: loading=lazy | img tags | inspecție cod | FAIL (afirmație) | Imaginile sunt CSS background-image, nu <img>; atributele nu se aplică | — |
| Admin: URL-uri canonice corecte | Da | inspecție cod | PASS | dr14 key → URL canonical corect; autoconsum-publici key → URL canonical corect | — |
| Admin: herambursabile absent ca canonic | Da | grep | PASS | absent | — |
| Typo herambursabile: absent din HTML | Da | grep recursiv | PASS | 0 rezultate în fișierele HTML | — |
| HTTP canonical URLs | 0 | Python scan | PASS | 0 găsite | — |
| Titluri duplicate semnificative | 0 | Python Counter | PASS | duplicate sunt doar pagini redirect (intenționat) și fișier backup | — |
| Live /: 200 | Da | WebFetch | PASS | conținut returnat | — |
| Live /contact/: 200 | Da | WebFetch | PASS | conținut + CTA confirmat | — |
| Live /fonduri-europene/: 200 | Da | WebFetch | PASS | H1 confirmat | — |
| Live /dr14.html: redirect HTML | Da | WebFetch | PASS | redirect la canonical confirmat | — |
| Live robots.txt: corect | Da | WebFetch | PASS | concordă cu local | — |
| Live llms.txt: corect | Da | WebFetch | PASS | concordă cu local | — |
| PageSpeed Desktop | scor estimat | Lighthouse | N/A | Lighthouse CLI indisponibil în acest mediu | — |
| PageSpeed Mobile | scor estimat | Lighthouse | N/A | Lighthouse CLI indisponibil în acest mediu | — |
| Statistici neconfirmate homepage | Absent/verificate | inspecție vizuală | FLAG | „250+", „98%", „45M€+", testimoniale cu date specifice — pre-existente, neintroduse de commit | — |

---

## Fixed During This Verification

| Fișier | Modificare | Motivație |
|--------|------------|-----------|
| `contact.html` | `robots: index, follow` → `noindex, follow` | Pagină redirect fallback; indexarea duplică conținut |
| `consultanta-fonduri-europene.html` | idem | idem |
| `dr14.html` | idem | idem |
| `autoconsum-publici.html` | idem | idem |
| `fonduri-europene-herambursabile-2026.html` | idem | Typo fallback; nu trebuie indexat |
| `fonduri-europene-nerambursabile-2026.html` | idem | .html fallback → /fonduri-europene-nerambursabile-2026/ |
| 35 alte pagini `.html` redirect din root | idem | Toate fallback-urile .html pentru hub-uri |
| `femeia-antreprenor-2026/index.html` | idem | Redirect dir fallback |
| `fonduri-europene-herambursabile-2026/index.html` | idem | Redirect dir fallback (typo) |
| `start-up-nation-2026/index.html` | idem | Redirect dir fallback |

**Total: 41 fișiere modificate.**

---

## Remaining Issues

### 1. HTTP 301 real — GitHub Pages
GitHub Pages nu procesează `_redirects`. Redirect-urile funcționează ca HTML fallback (200 + JS redirect), nu ca HTTP 301.
**Soluție recomandată:** Cloudflare Redirect Rules (gratuit, la nivel DNS), Cloudflare Pages, Netlify sau Vercel pentru 301 real la nivel de hosting/CDN.

### 2. Afirmații blog card images
Raportul susține `loading="lazy"` și `decoding="async"` pe imaginile de blog — imposibil de aplicat deoarece acestea sunt `background-image` CSS, nu `<img>`. Impact practic minim (imaginile sunt încărcate dinamic de JS, sub fold).

### 3. Phosphor Icons — discrepanță afirmație vs implementare
Raportul spune „după window.load" — implementarea reală folosește interaction events. Abordarea curentă este corectă, afirmația din raport nu.

### 4. Statistici și testimoniale neconfirmate
Pagina principală afișează vizibil: „250+ Proiecte aprobate", „98% Rată de aprobare dosare", „45M€+ Euro atrași" și testimoniale cu autori generici. Aceleași date apar în JSON-LD FAQPage (answer text). Nu au fost introduse de commitul b7d356b.
**Acțiune recomandată:** Fie înlocuiți cu date reale verificabile, fie eliminați statisticile și înlocuiți cu afirmații generice fără cifre. Testimonialele necesită consimțământ documentat.

### 5. Discrepanță sitemap local vs live (58 vs 66 URL-uri)
Sitemap-ul local are 58 URL-uri; cel live la momentul verificării are 66. Diferența provine probabil din articole de blog publicate ulterior via admin, care actualizează sitemap.xml direct pe GitHub.

---

## Commands Run

```bash
git status                          # FAIL: nu există .git
ls -la                              # structură proiect confirmată
# Verificare stack
ls admin/ assets/ .github/          # prezente
cat CNAME                           # atelierdeconsultanta.ro

# Citire fișiere cheie
# SEO_AUDIT_FIXES.md, _redirects, robots.txt, llms.txt, sitemap.xml
# index.html (Formspree, Phosphor, blog.json, og-image)
# contact.html, consultanta-fonduri-europene.html, dr14.html, autoconsum-publici.html

# Scanare Python — linkuri broken
python3 << scan pentru href/src lipsă       # 0 broken
python3 << scan herambursabile              # 0 găsite
python3 << scan old URLs active             # 0 găsite
python3 << validare JSON-LD                # 80 valide

# Verificare hub-uri
bash for loop — 30 hub-uri index.html      # toate prezente

# Server local
python3 -m http.server 8088
curl http://localhost:8088/<url>           # toate 200

# Sitemap URLs
python3 urllib.request — toate 58 URL-uri  # toate 200

# Verificare H1/canonical/title pe hub-uri
python3 check_page()                       # toate PASS

# Fix robots noindex
python3 — înlocuire în 41 fișiere          # Fix aplicat

# WebFetch live
https://atelierdeconsultanta.ro/           # 200, conținut confirmat
https://atelierdeconsultanta.ro/sitemap.xml # 200, 66 URL-uri live
https://atelierdeconsultanta.ro/robots.txt  # 200, concordă cu local
https://atelierdeconsultanta.ro/llms.txt    # 200, concordă cu local
https://atelierdeconsultanta.ro/contact/   # 200, CTA prezent
https://atelierdeconsultanta.ro/dr14.html  # 200, redirect HTML confirmat
https://atelierdeconsultanta.ro/fonduri-europene/ # 200, H1 confirmat
```

---

## URLs to Recrawl

Retrimiteți în Google Search Console, Bing Webmaster Tools și PageSpeed Insights după deploy:

### Prioritate înaltă (modificate noindex → pot fi acum ignorate de Google)
- https://atelierdeconsultanta.ro/contact.html
- https://atelierdeconsultanta.ro/consultanta-fonduri-europene.html
- https://atelierdeconsultanta.ro/dr14.html
- https://atelierdeconsultanta.ro/autoconsum-publici.html
- https://atelierdeconsultanta.ro/fonduri-europene-herambursabile-2026/

### Canonice (reconfirmare indexare)
- https://atelierdeconsultanta.ro/
- https://atelierdeconsultanta.ro/contact/
- https://atelierdeconsultanta.ro/consultanta-fonduri-europene/
- https://atelierdeconsultanta.ro/fonduri-europene/
- https://atelierdeconsultanta.ro/fonduri-nerambursabile/
- https://atelierdeconsultanta.ro/pnrr/
- https://atelierdeconsultanta.ro/afir/
- https://atelierdeconsultanta.ro/start-up-nation/
- https://atelierdeconsultanta.ro/fonduri-europene-imm/
- https://atelierdeconsultanta.ro/fonduri-europene-agricultura/
- https://atelierdeconsultanta.ro/fonduri-europene-digitalizare/
- https://atelierdeconsultanta.ro/calendar-fonduri-europene/
- https://atelierdeconsultanta.ro/eligibilitate-fonduri-europene/
- https://atelierdeconsultanta.ro/ghiduri/
- https://atelierdeconsultanta.ro/intrebari-frecvente/
- https://atelierdeconsultanta.ro/dr-14-afir-conditii-eligibilitate-greseli-frecvente.html
- https://atelierdeconsultanta.ro/autoconsum-public-fotovoltaice-institutii-publice.html
- https://atelierdeconsultanta.ro/sitemap.xml
