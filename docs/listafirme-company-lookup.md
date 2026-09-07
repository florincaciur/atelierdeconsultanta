# Verificarea firmei prin ListaFirme

Simulatorul pentru „Modernizarea microîntreprinderilor – Apel 2” folosește endpoint-ul intern `GET /api/company/:cui`. Browserul trimite numai CUI-ul normalizat. Worker-ul de domeniu validează din nou CUI-ul, aplică limitarea de 20 de cereri/minut, verifică cache-ul intern și apelează server-side API-ul oficial ListaFirme v3.

Nu este necesar un server separat, o bază de date, KV sau alt serviciu de găzduire. Integrarea rulează în Worker-ul Cloudflare deja folosit de domeniu și utilizează Cache API disponibil în aceeași infrastructură.

## Configurare

API-ul ListaFirme necesită serviciu API activ, un plan compatibil și o cheie secretă. Cheia nu se salvează în repository și nu este returnată browserului.

```powershell
npx wrangler secret put LISTAFIRME_API_KEY --config wrangler.redirects.jsonc
npx wrangler deploy --config wrangler.redirects.jsonc
```

Variabila este inventariată și în `.env.example`. Pentru dezvoltare locală poate fi pusă într-un fișier `.dev.vars`, care este ignorat de Git.

Înainte de activarea cheii pe un formular public, titularul contului trebuie să confirme că acordul său ListaFirme permite acest mod de afișare a datelor. Documentația tehnică este la <https://listafirme.ro/specificatii/api-info-v3.asp>, iar condițiile de utilizare la <https://listafirme.ro/specificatii/termeni.asp>.

Fără secret configurat, endpoint-ul răspunde controlat cu `503`, iar simulatorul rămâne integral utilizabil manual.

## Model și mapping

Providerul solicită `Name`, `Status`, `LegalForm`, `NACE`, `Date`, `County`, `City`, `Inactive` și `Balance`. Bilanțurile sunt indexate după proprietatea explicită `Year`; ordinea elementelor din răspuns nu este folosită.

Mapping-ul completează numai:

- `caen`, numai când ListaFirme confirmă CAEN Rev. 3;
- `establishedAt`, `headquartersCounty`, `employees2025`;
- `turnover2023`, `turnover2024`, `turnover2025`;
- `netProfit2025`, `assets2025`, `debts2025`.

Județul de implementare, grantul, contribuția proprie, noile locuri de muncă, tipul lucrătorului și toate criteriile care necesită declarații sau documente rămân exclusiv manuale.

Activele totale sunt calculate explicit și numai când ambele componente există:

```js
totalAssets = fixedAssets !== null && currentAssets !== null
  ? fixedAssets + currentAssets
  : null;
```

Dacă una dintre componente lipsește, `assets2025` rămâne necompletat și interfața cere completare manuală. Rezultatele normalizate reușite sunt păstrate 24 de ore în Cache API, cu cheia logică `company:${cui}`; răspunsul către browser are întotdeauna `Cache-Control: no-store`. Serviciul acceptă intern opțiunea `forceRefresh`, dar endpoint-ul public nu o citește din URL sau din browser; ea rămâne disponibilă doar pentru o viitoare rută administrativă autentificată.
