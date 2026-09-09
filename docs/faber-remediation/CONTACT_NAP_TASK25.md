# Task 25 — Contact, NAP, formulare și consimțământ

Data auditului: 27 august 2026.

## Sursa de adevăr

Publicarea se bazează exclusiv pe `config/legal-identity.json` și `config/contact-triage.json`, ambele având aprobările necesare din 22.07.2026. Nu a fost necesară o presupunere sau o confirmare nouă.

- brand: **FABER – Atelier de Consultanță**;
- entitate juridică: **FABER PUBLISHING S.R.L.**, CUI **35339809**, ONRC **J2015000489070**;
- sediu social: **Sat Gorbănești, comuna Gorbănești, nr. 88, Str. Principală, județul Botoșani**;
- puncte de lucru publice: **Iași / Suceava**;
- email: **atelier.consultanta@gmail.com**;
- telefon principal și WhatsApp: **+40 769 828 338**;
- telefon secundar și WhatsApp: **+40 753 326 229**;
- profil social oficial: **https://www.instagram.com/atelier.de.consultanta/**.

## Rezultatul auditului

Auditul acoperă cele 183 de fișiere HTML publice și verifică linkurile `tel:`, `mailto:`, `wa.me`, profilurile sociale, blocurile de footer gestionate și entitatea `Organization` din JSON-LD. Numerele WhatsApp din header sunt acum derivate din registrul juridic, iar verificarea sincronizării contactului normalizează terminatorii de linie fără a relaxa comparația semantică.

Adresa greșită `atelier.consultanță@gmail.com` a fost eliminată din placeholderul publicat la `/admin`. Pagina `/contact`, suprafețele juridice și schema structurată folosesc valorile aprobate de mai sus.

## Formulare, confidențialitate și securitate

Formularul canonic `/contact` păstrează endpointul Cloudflare `/api/contact-triage`, regula email **sau** telefon, validarea client/server, honeypotul, limita de payload, verificarea same-origin, mesajele de eroare/succes și comportamentul accesibil existent. Textul de confidențialitate este publicat cu starea `approved` numai când registrele juridic și de formular permit publicarea.

Confirmarea obligatorie nu este prebifată și privește numai procesarea solicitării; textul precizează explicit că nu reprezintă acord pentru newsletter sau marketing. Configurația interzice trimiterea câmpurilor sensibile către analytics, iar workerul nu jurnalizează payloadul formularului.

Formularul legacy din `/idei-afaceri-fonduri-europene` rămâne pe transportul HTTPS FormSubmit aprobat anterior, cu email obligatoriu, telefon opțional, confirmare nebifată și mascarea Clarity. Migrarea lui nu a fost făcută fără aprobarea destinației operaționale.

## Decizii încă deschise

- T00-004 rămâne `NEEDS_CONFIRMATION`: temeiul și comportamentul Clarity/CMP trebuie stabilite juridic înaintea unei schimbări de tracking.
- T00-020 rămâne `NEEDS_CONFIRMATION`: activarea CRM/webhook cere alegerea și aprobarea destinației.
- T00-019 rămâne deschis până la aprobarea migrării transportului formularului legacy.

Gate-ul `test:contact-nap` rulează în prebuild, la finalul pipeline-ului de generare și separat pe `dist`, astfel încât o regenerare târzie nu poate reintroduce valori necanonice.
