# Raport de Audit de Securitate — FABER Website
**Data:** 18 Aprilie 2026  
**Auditor:** Claude (Cowork Mode)  
**Scope:** Codebase complet — `/FABER - Website/`

---

## Sumar Executiv

Au fost identificate **5 vulnerabilități critice/înalte** și remediate integral. Website-ul este acum semnificativ mai securizat, cu autentificare server-side, rate limiting real și sanitizare completă a inputurilor.

---

## Vulnerabilități Găsite și Remediate

### 🔴 CRITIC — Hash parolă expus în frontend
**Fișier:** `admin/index.html` linia 433  
**Problemă:** Hash SHA-256 al parolei admin era hardcodat direct în JavaScript-ul public.  
```javascript
// COD VECHI — INSECUR
const DEFAULT_HASH = 'ad324fc24b34b833d611df3a3e2a4f9aa93a8cc26e9fdc6291338c72c8221ea5';
```
Oricine putea accesa sursa paginii, extrage hash-ul și folosi tabele rainbow sau atacuri dictionary pentru a recupera parola originală.

**Fix aplicat:** Hash-ul a fost eliminat complet din frontend. Autentificarea se face acum exclusiv server-side prin `admin/auth.php` care folosește `password_verify()` cu bcrypt (cost factor 12).

---

### 🔴 CRITIC — Autentificare exclusiv client-side (bypass trivial)
**Fișier:** `admin/index.html`  
**Problemă:** Întreaga logică de autentificare era în JavaScript din browser. Orice utilizator putea bypassa login-ul executând în consolă:
```javascript
sessionStorage.setItem('adminLoggedIn', '1');
sessionStorage.setItem('adminEmail', 'orice@email.com');
```
Niciun server nu verifica dacă sesiunea era legitimă.

**Fix aplicat:** Creat `admin/auth.php` cu:
- Verificare server-side cu PHP sessions
- `session_regenerate_id()` pentru prevenirea session fixation
- Rate limiting 5 tentative / 15 minute per IP
- Logare completă a tentativelor (succes + eșec)
- Timing-safe comparison pentru a preveni user enumeration

---

### 🔴 CRITIC — Email și credențiale hardcodate în frontend
**Fișier:** `admin/index.html` linia 434  
**Problemă:**
```javascript
const DEFAULT_EMAIL = 'atelier.consultanta@gmail.com';
```
Email-ul admin era vizibil în sursa publică a paginii.

**Fix aplicat:** Email-ul eliminat din frontend. Credențialele se citesc acum din `.env` server-side prin `admin/auth.php`.

---

### 🟠 ÎNALT — Fără rate limiting pe login
**Fișier:** `admin/index.html` (JavaScript)  
**Problemă:** Zero protecție împotriva atacurilor brute-force pe formularul de login admin. Un atacator putea face mii de încercări pe secundă.

**Fix aplicat:** Rate limiting implementat în `admin/auth.php`:
- Maximum **5 tentative** per IP per **15 minute**
- Header `Retry-After` returnat la depășirea limitei
- Fișiere JSON per-IP stocate în `/data/auth_rate/` (protejat cu `.htaccess`)
- La login reușit, contorul se resetează

---

### 🟠 ÎNALT — Formular de contact fără backend real
**Problemă:** Formularul de contact afișa un mesaj de succes fals fără a trimite niciun email. Utilizatorii credeau că au trimis o solicitare care nu ajungea niciodată.

**Fix aplicat:** Creat `contact.php` cu:
- **Rate limiting:** 5 cereri / 15 minute per IP
- **Sanitizare completă:** `strip_tags()`, `htmlspecialchars()`, eliminare caractere control
- **Validare strictă:** email `FILTER_VALIDATE_EMAIL`, lungimi maxime per câmp
- **Honeypot anti-bot:** câmp ascuns care detectează bots
- **Respingere payload supradimensionat:** max 10KB
- **Email de confirmare** trimis automat clientului
- **Verificare origine** (protecție CSRF de bază)

---

### 🟡 MEDIU — Niciun `.gitignore` — risc expunere credențiale în git
**Problemă:** Lipsea `.gitignore`, ceea ce putea duce la commit-area accidentală a fișierelor `.env` cu credențiale.

**Fix aplicat:** Creat `.gitignore` care exclude:
- `.env` și toate variantele lui
- `/data/` (rate limiting și logs)
- Fișiere backup, log, cache

---

### 🟡 MEDIU — GitHub PAT stocat în localStorage
**Fișier:** `admin/index.html`  
**Problemă:** Personal Access Token-ul GitHub (cu permisiuni `repo` — acces complet read/write) era stocat în `localStorage`, vulnerabil la atacuri XSS.  
**Status:** Parțial remediat — PAT-ul rămâne în localStorage dar acum nu mai există hash-uri sau credențiale admin expuse. **Recomandare viitoare:** mutați PAT-ul server-side printr-un endpoint PHP care să proxy-uiască API calls GitHub.

---

### 🟡 MEDIU — GitHub owner/repo hardcodat în frontend
**Fișier:** `admin/index.html` liniile 429-431  
**Problemă:** Username-ul GitHub `florincaciur` și repo-ul `atelierdeconsultanta` erau hardcodate ca fallback-uri publice.

**Fix aplicat:** Fallback-urile au fost schimbate în șiruri goale — utilizatorul trebuie să configureze explicit repo-ul în panoul de setări.

---

## Fișiere Noi Create

| Fișier | Rol |
|--------|-----|
| `contact.php` | Backend formular contact cu rate limiting și sanitizare |
| `admin/auth.php` | Autentificare server-side cu bcrypt și sesiuni PHP |
| `admin/setup.php` | Utilitar configurare parolă inițială (de șters după utilizare) |
| `.env.example` | Template variabile de mediu (nu se commit-ează) |
| `.gitignore` | Excludere fișiere sensibile din git |

---

## Configurare Necesară (Acțiuni Manuale)

### Pasul 1 — Creați fișierul `.env`
```bash
cp .env.example .env
nano .env
```

### Pasul 2 — Configurați parola admin
Accesați `https://atelierdeconsultanta.ro/admin/setup.php?token=TOKENUL_VOSTRU`, introduceți email-ul și parola dorită. Scriptul va scrie automat hash-ul bcrypt în `.env`.

**IMPORTANT:** Ștergeți `admin/setup.php` imediat după configurare!

### Pasul 3 — Verificați că `.env` nu este în git
```bash
git status  # .env NU trebuie să apară
```

### Pasul 4 — Protejați directorul `/data/`
Directorul se creează automat la prima cerere. Verificați că `.htaccess`-ul din `/data/` este activ (serverul Apache trebuie să aibă `AllowOverride All` sau `AllowOverride Limit`).

---

## Recomandări Viitoare (Ne-implementate)

1. **Mutați PAT GitHub server-side** — creați un endpoint PHP care să proxy-uiască apelurile GitHub API, eliminând PAT-ul din browser complet.

2. **Activați CSRF token complet** — adăugați un token CSRF generat server-side la formularul de contact.

3. **Content Security Policy mai strictă** — înlocuiți `unsafe-inline` cu nonces pentru script-urile inline.

4. **2FA pentru admin** — adăugați autentificare cu doi factori (TOTP) la panoul de administrare.

5. **Subdomeniu separat pentru admin** — mutați panoul admin pe `admin.atelierdeconsultanta.ro` cu acces restricționat la IP-uri specifice.

6. **HTTPS-only cookie pentru sesiunile PHP** — verificați că `session.cookie_secure=1` este setat și în `php.ini`.

---

## Stare Securitate Înainte vs. După

| Aspect | Înainte | După |
|--------|---------|------|
| Autentificare admin | Client-side, bypass trivial | Server-side bcrypt + PHP sessions |
| Parolă expusă | SHA-256 hash în sursă publică | Eliminat complet din frontend |
| Rate limiting login | Nu exista | 5 tentative / 15 min per IP |
| Formular contact | Fals (no backend) | PHP real cu validare + email |
| Rate limiting contact | Nu exista | 5 cereri / 15 min per IP |
| Sanitizare inputuri | Doar regex email | Sanitizare completă + honeypot |
| Credențiale în git | Risc ridicat (fără .gitignore) | .gitignore configurat |

---

*Raport generat automat de Claude — FABER Atelier de Consultanță | 2026*
