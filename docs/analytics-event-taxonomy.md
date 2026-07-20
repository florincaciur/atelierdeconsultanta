# Taxonomia evenimentelor Microsoft Clarity

Implementarea FABER are un singur punct de intrare: `/assets/analytics-events.js`. Scriptul inițializează proiectul Microsoft Clarity, validează taxonomia, filtrează payloadul și folosește event delegation pentru controalele declarate prin atribute `data-analytics-*`.

Nu se folosește API-ul Clarity `identify`. Nu sunt instalate GA4, Meta Pixel sau alte trackere.

## Evenimente

| Eveniment | Se emite când | Componentă tipică |
| --- | --- | --- |
| `nav_click` | Utilizatorul activează un link sau un control din navigarea globală | `desktop_nav`, `mobile_nav`, `mobile_menu_toggle` |
| `program_menu_click` | Este activat meniul Programe sau o destinație de program | `desktop_program_menu`, `mobile_program_menu`, `program_carousel` |
| `eligibility_cta_click` | Este activat CTA-ul care cere verificarea eligibilității | `eligibility_cta`, `desktop_nav`, `mobile_nav` |
| `whatsapp_dialog_open` | Dialogul WhatsApp s-a deschis efectiv | `whatsapp_dialog` |
| `whatsapp_number_click` | Este ales unul dintre linkurile WhatsApp | `whatsapp_dialog`, `whatsapp_link` |
| `contact_page_click` | Este activat un CTA contextual către `/contact` | `contact_cta` |
| `form_start` | Utilizatorul interacționează prima dată cu un formular | `public_form` |
| `form_submit_attempt` | Este inițiată o încercare de trimitere, inclusiv una invalidă | `public_form` |
| `form_submit_success` | Endpointul AJAX a răspuns cu HTTP success și confirmare explicită `success` | `public_form` |
| `form_validation_error` | Browserul sau validarea proprie respinge formularul | `public_form` |
| `calculator_start` | Are loc prima interacțiune de calcul | `calculator_so` |
| `calculator_complete` | Calculatorul a produs primul rezultat nenul | `calculator_so` |
| `calculator_result_to_dr12` | Utilizatorul urmează linkul DR12 afișat în rezultat | `calculator_result` |
| `calculator_result_to_dr14` | Utilizatorul urmează linkul DR14 afișat în rezultat | `calculator_result` |
| `source_document_click` | Este activată o sursă sau o documentație oficială | `official_source`, `program_carousel_source` |
| `next_step_click` | Este activat un link din blocul editorial „Următorul pas util” | componenta declarată în pagină |
| `phone_click` | Este activat un link `tel:` | `contact_link` |
| `email_click` | Este activat un link `mailto:` | `contact_link` |

Un click poate produce două evenimente diferite numai când măsoară două stări distincte. De exemplu, CTA-ul WhatsApp produce `eligibility_cta_click`, iar după deschiderea reală a dialogului se emite separat `whatsapp_dialog_open`. Fiecare dintre ele se emite o singură dată pentru acțiunea respectivă.

## Payload permis

Stratul comun acceptă și transmite către Clarity numai următoarele taguri:

| Cheie | Conținut permis | Exemplu |
| --- | --- | --- |
| `route` | Calea paginii curente, fără query string sau fragment | `/calculator-soc` |
| `component_type` | Tip generic de componentă | `desktop_nav` |
| `cta_id` | Identificator generic, fără text introdus de utilizator | `eligibility_whatsapp` |
| `destination_route` | Calea destinației; query stringul și fragmentul sunt eliminate | `/dr12-afir` |
| `program_category` | Categorie editorială generică | `agriculture` |
| `status` | Numai `success` sau `error` | `success` |

Tagurile apar în Clarity cu prefixul `faber_event_`. Numele evenimentului este trimis prin API-ul oficial `clarity("event", numeEveniment)`. Ruta curentă este calculată din `location.pathname`; atributul istoric `data-analytics-source` al blocurilor next-step nu este citit și nu este transmis.

## Date interzise

Implementarea nu citește și nu transmite:

- nume, telefon, e-mail, CUI sau cod CAEN introdus;
- textul mesajului ori orice altă valoare de câmp;
- `FormData`, textul vizibil al controlului sau conținutul formularului;
- suprafețe, efective, coeficienți sau rezultatul SO;
- query stringuri și fragmente din destinații;
- identificatori de utilizator Clarity.

Toate formularele publice au `data-clarity-mask="true"`. Aceasta completează filtrarea din cod cu mascarea explicită recomandată de [Microsoft Clarity Client API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-api).

## Reguli pentru formulare

`form_start` este emis o singură dată, la prima interacțiune. `form_submit_attempt` este emis la fiecare acțiune reală de submit și este deduplicat între clickul butonului și evenimentul DOM `submit`. Mai multe câmpuri invalide produc un singur `form_validation_error` pentru aceeași încercare.

`form_submit_success` nu este dedus din click, din ascunderea formularului sau din navigare. Pe homepage este emis numai după ce răspunsul FormSubmit îndeplinește ambele condiții existente: `response.ok` și `data.success`. Formularele care navighează către un endpoint sau deschid clientul de e-mail nu emit automat success, deoarece pagina nu primește o confirmare verificabilă. Endpointurile nu sunt modificate de analytics.

## Reguli pentru calculator

Prima interacțiune cu zona de calcul emite `calculator_start`. Primul total nenul emite `calculator_complete`; payloadul conține doar componenta generică și statusul. Linkurile afișate în rezultat către DR12 și DR14 au propriile evenimente, fără valoarea SO care a determinat afișarea lor.

## Marcaj HTML

Exemplu de CTA contextual:

```html
<a href="/contact"
   data-analytics-event="contact_page_click"
   data-analytics-component="contact_cta"
   data-analytics-cta-id="contact_page"
   data-analytics-target="/contact">Contact</a>
```

Exemplu de formular:

```html
<form data-analytics-form="homepage_contact"
      data-analytics-component="public_form"
      data-clarity-mask="true">
```

Nu se adaugă handler separat pentru fiecare control. Evenimentele de click, form și calculator sunt capturate de listener-ele delegate din `analytics-events.js`.

## Verificare

- `npm run apply:analytics-events` sincronizează scriptul și atributele în HTML;
- `node tools/sync-analytics-events.js --check` verifică idempotent sincronizarea;
- `npm run verify:analytics` rulează verificarea statică și scenariile Playwright;
- evenimentul local `faber:analytics-event` poate fi ascultat în testare, dar nu transmite date către un serviciu extern.

Dacă Microsoft Clarity este blocat sau indisponibil, apelurile rămân în coada locală, iar navigarea, dialogurile, formularele și calculatorul continuă să funcționeze normal.
