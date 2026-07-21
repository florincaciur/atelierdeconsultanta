# P0.06 — raport de implementare

## Stare

Implementarea locală este completă tehnic, dar publicarea rămâne blocată de poarta juridică existentă. Textul de confirmare a citirii informării are starea `pending_legal_approval`; nu este consimțământ de marketing și nu trebuie publicat înainte de aviz.

## Suprafețe și componente modificate

- `/contact`: formularul cu 11 controale obligatorii a fost înlocuit cu triere în două etape;
- `tools/rebuild-core-pages.js`: generatorul paginii folosește componenta centrală, astfel încât build-ul nu reintroduce formularul vechi;
- `assets/contact-triage.js`: navigare între etape, precompletare program, rezumat, validare email OR telefon și trimitere;
- `assets/contact-triage.css`: layout responsive, focus și stări de eroare/succes;
- `cloudflare/domain-seo-redirects.mjs`: validare server-side, honeypot, control origine/dimensiune/timp și adaptor de forward;
- `config/contact-triage-payload.schema.json`: contractul payload-ului `1.0.0`;
- `docs/contact-triage-crm-migration.md`: maparea câmpurilor și activarea transportului.

## Decizii de siguranță

- emailul și telefonul sunt alternative; niciunul nu are atribut `required` individual;
- numele nu este cerut la trierea inițială;
- documentele sunt descrise, nu încărcate în formular;
- succesul nu promite SLA sau eligibilitate;
- destinația de forward este secret Cloudflare și nu este hardcodată;
- câmpurile formularului nu sunt trimise către Clarity/analytics;
- fără JavaScript, formularul rămâne trimis prin POST și este validat de Worker.

## DE_VALIDAT_UMAN înainte de publicare

1. textul juridic exact al confirmării de citire;
2. operatorul de date și politica de confidențialitate asociată;
3. adresa sau endpointul operațional care va fi salvat în `CONTACT_FORM_FORWARD_URL`;
4. proprietarul mapării către CRM, dacă beneficiarul folosește un CRM în afara repository-ului;
5. eventuala perioadă de păstrare și regulile interne pentru revocarea/ștergerea lead-urilor.
