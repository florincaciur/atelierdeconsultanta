# Audit acces crawlere — 2026-07-21

## Rezultat executiv

| Criteriu | Rezultat | Dovadă / acțiune |
|---|---|---|
| OAI-SearchBot permis în `robots.txt` | PASS | grup explicit `Allow: /`; prefixurile `/admin` și `/api` excluse |
| GPTBot blocat pentru training | PASS — regulă păstrată | `Disallow: /`; confirmarea de business rămâne `DE_VALIDAT_UMAN` |
| PerplexityBot permis în `robots.txt` | PASS | grup explicit adăugat; zonele private excluse |
| Googlebot/Bingbot pagini publice | PASS sintetic | homepage, robots, sitemap și CSS au răspuns 200 la verificarea live |
| OAI-SearchBot pagini publice | PASS sintetic | homepage, robots, sitemap și CSS au răspuns 200 la verificarea live |
| PerplexityBot oficial neblocat de Cloudflare | DE_VALIDAT_UMAN | proba cu UA spoofed a primit 403; trebuie verificat IP + UA în Security Events |
| CSS/JS/imagini neblocate în `robots.txt` | PASS | nu există reguli Disallow pe extensii/`/assets/` |
| Sitemap declarat o singură dată | PASS | `https://atelierdeconsultanta.ro/sitemap.xml` |
| Schimbare `llms.txt` | PASS | nicio schimbare în P0.15 |

## Rezumat anonim al verificării live

Verificarea sintetică a folosit patru URL-uri publice: homepage, `robots.txt`, sitemap și un fișier CSS. Googlebot, bingbot și OAI-SearchBot au primit răspunsuri 200. Proba PerplexityBot a primit 200 pentru `robots.txt`, iar pentru homepage, sitemap și CSS a primit 403 la edge; identificatorii Cloudflare și IP-urile nu sunt incluși în raport. Deoarece solicitarea nu a venit de pe un IP oficial Perplexity, rezultatul nu poate fi tratat ca log al crawlerului real. Endpoint-ul oficial Perplexity a fost accesibil și conținea 8 prefixe la momentul auditului; lista nu a fost copiată în repository.

| User-Agent sintetic | `/` | `/robots.txt` | `/sitemap.xml` | `/assets/home.min.css` | Interpretare |
|---|---:|---:|---:|---:|---|
| Googlebot | 200 | 200 | 200 | 200 | acces public sintetic PASS |
| bingbot | 200 | 200 | 200 | 200 | acces public sintetic PASS |
| OAI-SearchBot | 200 | 200 | 200 | 200 | acces public sintetic PASS |
| PerplexityBot | 403 | 200 | 403 | 403 | `REVIEW_REQUIRED`; verificare în loguri după IP + UA |

Răspunsul live `robots.txt` este gestionat și de funcția Cloudflare Managed `robots.txt`, care precedă fișierul origin cu `Content-Signal: search=yes,ai-train=no`. Conținutul origin rămâne prezent după secțiunea gestionată. Orice schimbare a acestei setări din dashboard intră sub `APROBARE_UMANĂ_NECESARĂ`.

Logurile Cloudflare/server nu au fost accesibile din workspace. Ownerul trebuie să exporte un rezumat anonim din Security Events, după verificarea sursei prin IP + User-Agent, și să completeze:

- interval verificat: `DE_VALIDAT_UMAN`;
- număr cereri oficiale Googlebot/Bingbot/OAI-SearchBot/PerplexityBot: `DE_VALIDAT_UMAN`;
- acțiuni 401/403/429 și serviciul Cloudflare responsabil: `DE_VALIDAT_UMAN`;
- decizie și aprobator pentru orice excepție: `APROBARE_UMANĂ_NECESARĂ`.

## Modificări

- adăugat grupul explicit PerplexityBot;
- excluse formele exacte și cu slash ale prefixelor `/admin` și `/api` din grupurile de căutare și din regula generală;
- păstrate neschimbate toate blocările de training;
- adăugat contract CI pentru OAI/Perplexity/GPTBot, zone private, sitemap și asset-uri;
- adăugat audit live sintetic, separat de build, pentru a nu confunda o probă spoofed cu traficul oficial;
- nu s-a introdus nicio regulă Cloudflare/Worker bazată doar pe User-Agent.

## Teste

- `npm run test:crawler-policy` — PASS;
- `npm run build` — PASS, inclusiv gate-ul `test:crawler-policy` și copierea în `dist/robots.txt`;
- `npm run audit:crawlers:live` — `REVIEW_REQUIRED` pentru 3 probe Perplexity spoofed; tabelul de mai sus conține rezultatele;
- `dist/robots.txt` vs `robots.txt` — PASS, conținut identic.
