# Setări Cloudflare pentru protocol și HSTS

Aceste setări sunt împărțite între configurația versionată a celor două Workers și controale de zonă care există numai în dashboard/API. La verificarea din 24 august 2026, `http://atelierdeconsultanta.ro/` răspundea cu un singur `301` către HTTPS apex, iar variantele `www`, trailing slash, `.html` și `/index.html` erau normalizate într-un singur hop.

Repository-ul include și alternativa operațională `cloudflare/domain-seo-redirects.mjs`, configurată separat prin `wrangler.redirects.jsonc`. Worker-ul rulează ca proxy transparent în fața origin-ului existent, aplică numai redirecturile de protocol și SearchAction, iar pentru toate celelalte cereri folosește `fetch(request)` către origin. Configurația separată evită înlocuirea accidentală a deploy-ului de active statice.

Workerul este activ pe ambele rute, `atelierdeconsultanta.ro/*` și `www.atelierdeconsultanta.ro/*`. ID-urile de versiune sunt dovezi tranzitorii din Wrangler și nu sunt păstrate ca desired state în config; commitul live este verificat prin `/release.json`.

## 1. Redirect HTTP către HTTPS

În Cloudflare, activează **SSL/TLS → Edge Certificates → Always Use HTTPS**. Alternativ, creează o singură Redirect Rule permanentă pentru toate cererile cu schema HTTP:

- condiție: `http.request.full_uri` începe cu `http://atelierdeconsultanta.ro`;
- destinație dinamică: aceeași gazdă, aceeași cale și același query, cu schema `https`;
- status: `301`;
- păstrarea query-ului: activă.

Nu crea o regulă care trimite toate căile către homepage. Nu dubla Always Use HTTPS cu o altă regulă care produce două hopuri.

## 1.1. Eliminarea URL-ului SearchAction moștenit

Captura GSC confirmă URL-ul `https://atelierdeconsultanta.ro/?s={search_term_string}`. SearchAction nu mai există în schema publică și URL-ul nu este în sitemap sau în linkurile interne, însă curățarea JavaScript din homepage nu schimbă răspunsul HTTP inițial primit de crawler.

În **Rules → Redirect Rules**, adaugă înaintea celorlalte reguli o regulă permanentă:

- condiție: hostul este `atelierdeconsultanta.ro`, iar query-ul începe cu `s=`, conține `&s=` sau conține `search_term_string`;
- destinație: `https://atelierdeconsultanta.ro/`;
- status: `301`;
- păstrarea query-ului: dezactivată.

Această regulă este deliberat limitată la parametrul de căutare moștenit. Parametrii de campanie sau măsurare ai celorlalte pagini nu trebuie eliminați.

După modificare, rulează:

```powershell
npm run verify:priority-urls:live
```

Testul trebuie să confirme pentru homepage și cele patru pagini de program: HTTP → un singur 301 către aceeași cale HTTPS, păstrarea query-ului, alias → canonical într-un singur hop și canonical → 200 direct.

## 2. HSTS după verificare

Activează HSTS numai după ce testul HTTP/HTTPS este verde și după inventarierea subdomeniilor. Configurația inițială:

- `max-age`: 6 luni (`15552000` secunde);
- `includeSubDomains`: dezactivat;
- `preload`: dezactivat;
- `no-sniff`: poate rămâne activ dacă este oferit de setarea Cloudflare.

`includeSubDomains` se activează doar după confirmarea HTTPS pentru fiecare subdomeniu folosit. `preload` nu se activează în această etapă, deoarece înscrierea este greu de retras și impune cerințe mai stricte.

## 3. Crawlere AI

Fișierul `robots.txt` permite explicit `OAI-SearchBot` și `Claude-SearchBot` pentru descoperirea în produse de căutare și blochează crawlerele de training declarate. Dacă **AI Crawl Control** sau **Managed robots.txt** este activ în Cloudflare, politica din dashboard trebuie să păstreze aceleași decizii; conținutul injectat de Cloudflare nu trebuie să inverseze regulile repository-ului.

Nu dezactiva WAF-ul și nu crea o regulă globală de allow/skip pentru toate user-agent-urile de crawler. Dacă un crawler legitim este blocat, verifică mai întâi identitatea Cloudflare `Verified bot` și evenimentul de securitate, apoi limitează orice excepție la regula, ruta și produsul care produc falsul pozitiv. Un test cu user-agent sintetic verifică accesul HTTP, nu identitatea oficială a botului.

## 4. Cache și răspunsuri dinamice

- workerul de domeniu păstrează politica `Cache-Control` explicită primită de la workerul de active;
- activele cu nume mutabile folosesc `public, max-age=86400, must-revalidate`, fără `immutable` pe un an;
- `robots.txt`, sitemap-urile și `llms.txt` folosesc o fereastră de o oră;
- răspunsurile fără politică explicită eșuează sigur la `no-store`;
- API-urile, formularele, cererile autorizate, metodele non-GET/HEAD, răspunsurile cu `Set-Cookie`, `release.json` și 404 nu se cache-uiesc.

Cache Rules/Cache Response Rules din dashboard pot avea precedență față de headerele origin și trebuie confirmate separat. Nu crea `Cache Everything` pentru `/api/*`, răspunsuri personalizate sau formulare.

## 5. Închiderea operațiunii

După deploy și validarea live:

1. păstrează `deploymentState` activ numai cât timp rutele pot fi confirmate prin Wrangler și probe live;
2. trimite sitemap-ul actualizat în GSC;
3. rulează IndexNow pentru URL-urile modificate;
4. solicită indexarea celor cinci pagini prioritare;
5. pornește Validate Fix numai pentru rândurile completate și verificate din registrul GSC.
