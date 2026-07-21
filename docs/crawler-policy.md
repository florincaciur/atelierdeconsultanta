# Politica de acces a crawlerelor

Data auditului: 2026-07-21

## Decizia aplicată

Paginile și asset-urile publice sunt accesibile crawlerelor de căutare. Prefixurile `/admin` și `/api` sunt excluse explicit în `robots.txt`, atât în forma exactă, cât și cu slash. OAI-SearchBot și PerplexityBot au grupuri separate cu `Allow: /`; GPTBot rămâne blocat cu `Disallow: /`. Regulile existente pentru ClaudeBot, `anthropic-ai`, Google-Extended și CCBot au fost păstrate fără schimbare.

Politica de căutare și politica de antrenare sunt independente. Confirmarea proprietarului pentru blocările de training rămâne `DE_VALIDAT_UMAN`; nicio astfel de regulă nu a fost adăugată, eliminată sau relaxată în P0.15.

Nu s-a creat și nu s-a modificat `llms.txt` în acest task.

## Matrice

| Crawler | Acces public | Zone private | Scop / motiv | Stare aprobare |
|---|---|---|---|---|
| Googlebot | Allow | `/admin/`, `/api/` disallow | indexare clasică | politică standard |
| bingbot | Allow | `/admin/`, `/api/` disallow | indexare clasică | politică standard |
| OAI-SearchBot | Allow | `/admin/`, `/api/` disallow | căutare și răspunsuri ChatGPT cu surse | aprobat prin P0.15 |
| PerplexityBot | Allow | `/admin/`, `/api/` disallow | căutare Perplexity | aprobat prin P0.15 |
| Claude-SearchBot | Allow | `/admin/`, `/api/` disallow | căutare și răspunsuri cu surse | regulă existentă păstrată |
| GPTBot | Disallow | tot site-ul | antrenare OpenAI | `DE_VALIDAT_UMAN` |
| ClaudeBot | Disallow | tot site-ul | antrenare Anthropic | `DE_VALIDAT_UMAN` |
| anthropic-ai | Disallow | tot site-ul | utilizare AI Anthropic | `DE_VALIDAT_UMAN` |
| Google-Extended | Disallow | tot site-ul | utilizare pentru modele Google | `DE_VALIDAT_UMAN` |
| CCBot | Disallow | tot site-ul | Common Crawl / seturi de date | `DE_VALIDAT_UMAN` |

## Cloudflare și verificarea anti-spoofing

Nu există în repository o regulă WAF/Bot Management bazată pe User-Agent. Configurația efectivă este în dashboard, iar accesul la Security Events nu a fost disponibil în acest mediu. Probele sintetice din 2026-07-21 au primit 200 pentru Googlebot, bingbot și OAI-SearchBot. O probă cu User-Agent `PerplexityBot`, trimisă de pe un IP care nu aparține Perplexity, a primit 403 de la Cloudflare. Acest rezultat nu demonstrează că botul oficial este blocat și nu justifică o excepție după User-Agent.

Înaintea oricărei schimbări Cloudflare:

1. Filtrează Security Events pe hostname, User-Agent și statusurile 401/403/429 pentru ultimele 7–30 de zile.
2. Verifică IP-ul solicitantului față de lista oficială publicată la `https://www.perplexity.com/perplexitybot.json`; pentru Googlebot și Bingbot folosește mecanismele oficiale de verificare/Verified Bots ale platformei.
3. Dacă IP + User-Agent oficial sunt blocate, identifică serviciul Cloudflare care a aplicat acțiunea. Nu crea o regulă `Allow` bazată numai pe User-Agent.
4. Dacă planul permite o regulă Skip, limiteaz-o la botul verificat și numai la regulile care produc falsul pozitiv; nu o aplica pentru `/admin/` sau `/api/`.
5. Dacă blocarea vine din Bot Fight Mode, verifică mai întâi capabilitățile planului: modul standard nu poate fi ocolit printr-o regulă WAF. Orice dezactivare sau schimbare de plan cere aprobarea proprietarului și a responsabilului de securitate.

Expresie candidată, numai după sincronizarea unei liste Cloudflare numite `perplexitybot_official` din endpoint-ul oficial și confirmarea falsului pozitiv în loguri:

```text
(http.user_agent contains "PerplexityBot"
 and ip.src in $perplexitybot_official
 and not starts_with(http.request.uri.path, "/admin")
 and not starts_with(http.request.uri.path, "/api"))
```

Acțiunea recomandată este `Skip` doar pentru produsul/regula care a produs falsul pozitiv, cu logging activ. Nu folosi acțiunea globală `Allow`, nu omite verificarea IP și nu aplica expresia dacă traficul oficial nu apare blocat.

Stare: `DE_VALIDAT_UMAN` pentru logurile crawlerelor oficiale și `APROBARE_UMANĂ_NECESARĂ` pentru orice schimbare Cloudflare.

## Monitorizare

Rulează local `npm run test:crawler-policy`. După deploy rulează `npm run audit:crawlers:live`; acesta este un test sintetic, nu înlocuiește verificarea IP-urilor reale în Security Events. Raportul nu trebuie să includă IP-uri complete, query strings sau alte date care pot identifica vizitatori.
