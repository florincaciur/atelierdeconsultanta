# Raport QA — funnel analytics și atribuire lead-uri

Data: 2026-07-21 · implementare locală, fără deploy.

## Rezultat

- 177 pagini publice au exact un loader de atribuire first-party și un loader analytics.
- 646 CTA-uri sunt instrumentate cu `cta_view` + `cta_click` și ID-uri deterministe; `cta_view` se emite o singură dată la minimum 50% vizibilitate.
- Cele 10 evenimente obligatorii există în registru; payload-ul acceptă 14 chei non-PII controlate.
- Testul browser a produs 9 evenimente client sanitizate și a confirmat: zero `form_start` la load/focus programatic, `step_1_complete` o singură dată, zero `form_submit` la tentativa client, apoi un singur `form_submit` după confirmarea serverului.
- Testul webhook a confirmat `qualified_lead` autentificat și respingerea oricărei proprietăți suplimentare, inclusiv `email`.
- `utm_source=chatgpt.com`, UTM medium/campaign, referrer-ul first-touch și contextul programului sunt păstrate numai pentru CRM; analytics primește `source_channel=chatgpt`.
- Honeypot-ul/timing filter nu forwardează spam și nu returnează `leadId`, deci nu produce `form_submit`.

## QA UI în browser controlat

URL local: `/contact/?program=dr12-afir&utm_source=chatgpt.com&utm_medium=referral&analytics_debug=1`.

- La load: formularul este precompletat cu `dr12-afir`; niciun eveniment de form nu este declanșat automat.
- Submit invalid: sumarul erorilor devine vizibil, toate erorile au `aria-invalid`, focusul ajunge la `applicant_type`.
- După completarea locală a Pasului 1: rezumatul este vizibil; câmpurile CRM conțin `dr12-afir`, `afir-agricultura`, `chatgpt.com` și canalul normalizat `chatgpt`.
- Formularul nu a fost trimis către o destinație externă în QA-ul manual.

## Comenzi verificate

- `npm run verify:analytics` — PASS
- `npm run test:contact-triage` — PASS
- `npm run test:contact-accessibility` — PASS
- `npm run verify:cloudflare-domain-worker` — PASS, inclusiv Wrangler dry-run
- `npm run build` — PASS; funnel-ul este poartă obligatorie în build

## Confirmare PII

Testele resping cheile neaprobate și caută explicit scurgeri de email, telefon, descriere, valoare de investiție, UTM brut și destinații `tel:`/`mailto:`/WhatsApp. Valorile de input nu sunt citite de `assets/analytics-events.js`; formularul este mascat pentru Clarity prin `data-clarity-mask="true"`.

## DE_VALIDAT_UMAN înainte de activarea live

1. Alegerea și configurarea destinației HTTPS pentru `ANALYTICS_EVENT_FORWARD_URL`.
2. Configurarea secretului `CRM_ANALYTICS_WEBHOOK_SECRET`.
3. Maparea stării business „calificat” în CRM și garantarea emiterii webhook-ului o singură dată.
4. Crearea dashboard-ului în contul analytics ales pe baza `config/funnel-dashboard.json` și validarea filtrelor bot/internal traffic.
5. Validarea în modul debug al platformei live după deploy, fără lead-uri reale.
