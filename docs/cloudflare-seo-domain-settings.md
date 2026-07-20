# Setări Cloudflare pentru protocol și HSTS

Aceste setări sunt la nivelul zonei Cloudflare și nu pot fi impuse prin `_redirects` într-un deploy de active statice. La verificarea din 20 iulie 2026, `http://atelierdeconsultanta.ro/` răspundea `200`, deși paginile declară canonical HTTPS.

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

## 4. Închiderea operațiunii

După deploy și validarea live:

1. schimbă `deploymentState` din `config/cloudflare-domain-seo.json` numai după confirmarea efectivă din zonă;
2. trimite sitemap-ul actualizat în GSC;
3. rulează IndexNow pentru URL-urile modificate;
4. solicită indexarea celor cinci pagini prioritare;
5. pornește Validate Fix numai pentru rândurile completate și verificate din registrul GSC.
