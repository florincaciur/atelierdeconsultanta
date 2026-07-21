# Filtrarea traficului bot

Politica este „păstrează brut, filtrează la raportare”. Nu se șterg evenimente din Clarity, dataLayer sau destinația server-side fără aprobare explicită.

1. Formularul folosește honeypot și prag minim de timp. Solicitările suspecte primesc un răspuns neutru, nu sunt trimise în CRM și nu primesc `leadId`; prin urmare clientul nu emite `form_submit`.
2. `form_submit` și `qualified_lead` se numără distinct după `lead_correlation_id`. Evenimentele fără identificator sunt excluse din cele două trepte de conversie ale dashboard-ului.
3. În dashboard se aplică, fără ștergere, flag-urile de bot/internal traffic ale destinației analytics, sesiunile de debug și volumele anormale repetate pe același `cta_id`.
4. `cta_view`, `cta_click` și `form_start` rămân disponibile ca volum brut. Raportul trebuie să ofere separat „raw” și „filtered”; filtrul nu rescrie istoricul.
5. User-agent, IP, scorul bot Cloudflare și fingerprint-uri nu sunt adăugate în payload-ul evenimentelor FABER.

Orice regulă nouă de excludere trebuie înregistrată cu data, autorul, motivul, procentul afectat și aprobarea responsabilului analytics.
