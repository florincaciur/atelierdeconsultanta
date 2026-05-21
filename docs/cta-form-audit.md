# Audit CTA-uri si formulare

Data audit: 2026-05-21

## Rezumat

Auditul a verificat CTA-urile din homepage, pagina principala de consultanta fonduri europene, hub-uri de programe, blog si contact. Formularea veche folosea frecvent `Evaluare gratuita`, `Verifica eligibilitatea`, `Trimite datele proiectului`, `Ghid oficial` si cateva CTA-uri mai comerciale precum `Consultanta gratuita`.

CTA-urile au fost standardizate catre formulari prudente:

- `Solicită verificare eligibilitate`
- `Trimite detaliile proiectului`
- `Vezi metodologia`
- `Consultă sursele oficiale`
- `Discută cu un consultant`

## Harta CTA-urilor

| Zona | CTA gasit initial | CTA standardizat | Observatie |
| --- | --- | --- | --- |
| Homepage - header, hero, mobil | `Verifică eligibilitatea` | `Solicită verificare eligibilitate` | CTA principal de lead, fara promisiune de rezultat. |
| Homepage - hero secundar | `Vezi programe active` | `Vezi metodologia` | Mutat spre pagina de metoda pentru incredere si AI visibility. |
| Homepage - program cards | `Ghid oficial` | `Consultă sursele oficiale` | Linkurile raman catre surse oficiale externe sau pagini oficiale. |
| Homepage - formular contact | `Trimite solicitarea` | `Trimite detaliile proiectului` | Mai specific pentru lead qualification. |
| Consultanta fonduri europene | `Evaluare gratuita`, `Solicită evaluare pentru cost`, `Vezi metodologia de lucru`, `Vezi serviciile` | `Solicită verificare eligibilitate`, `Discută cu un consultant`, `Vezi metodologia` | Am eliminat accentul pe gratuit si pe servicii generice. |
| Hub-uri programatice | `Evaluare gratuita`, `Verifica eligibilitatea`, `Discuta cu un consultant`, `Trimite datele proiectului`, `Vezi serviciile` | `Solicită verificare eligibilitate`, `Discută cu un consultant`, `Trimite detaliile proiectului`, `Vezi metodologia` | Aplicat mecanic pe paginile publice cu aceeasi structura. |
| Blog hub | `Solicită o evaluare gratuită`, `Consultanță gratuită` | `Solicită verificare eligibilitate`, `Trimite detaliile proiectului` | Microcopy mai prudent, fara promisiuni de contractare sau rezultat. |
| Contact | `Formular`, `Deschide formularul` | `Trimite detaliile proiectului` | Pagina Contact trimite in continuare catre formularul de pe homepage. |

## Formulare identificate

| Formular | Fisier | Backend | Modificare |
| --- | --- | --- | --- |
| Formular contact / lead | `index.html` | `https://formsubmit.co/ajax/atelier.consultanta@gmail.com` | Campuri extinse, microcopy si linkuri de incredere adaugate. |
| Newsletter | `index.html` | Handler JS existent `handleNewsletterSubmit` | Nu a fost transformat in formular de lead; este separat de fluxul de eligibilitate. |
| Pagina Contact | `contact/index.html` | Nu are formular propriu | CTA catre formularul principal de pe homepage. |

## Campuri formular contact

Campuri existente pastrate:

- nume
- email
- telefon
- program de interes
- mesaj

Campuri adaugate:

- judet / localitate
- tip solicitant
- domeniu activitate
- cod CAEN, daca exista
- investitie dorita
- buget estimat / cofinantare

Microcopy adaugat langa formular:

`Analiza inițială nu garantează finanțarea. Verificăm eligibilitatea pe baza informațiilor transmise și a ghidurilor disponibile.`

Linkuri adaugate langa formular:

- metodologia FABER
- surse oficiale
- politica de confidentialitate

## Riscuri evitate

- Nu au fost adaugate promisiuni de aprobare garantata.
- Nu au fost adaugate promisiuni de finantare sigura.
- Nu a fost modificat endpoint-ul formularului.
- Nu au fost adaugate praguri, procente sau conditii oficiale noi.

## TODO tehnic

- Nu este necesar `TODO_BACKEND_FORM` pentru modificarile curente: endpoint-ul FormSubmit primeste campuri suplimentare in payload JSON.
- Daca leadurile vor fi trimise intr-un CRM, Sheets sau alt backend propriu, trebuie introdus `TODO_BACKEND_FORM` si mapate campurile noi.
