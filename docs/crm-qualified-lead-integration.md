# Integrare CRM → `qualified_lead`

Endpoint: `POST /api/crm/qualified-lead`, `Content-Type: application/json`, autentificare `Authorization: Bearer <CRM_ANALYTICS_WEBHOOK_SECRET>`.

Payload minim:

```json
{
  "lead_correlation_id": "uuid-primit-la-crearea-leadului",
  "program_slug": "dr12-afir",
  "program_family": "afir-agricultura",
  "form_version": "short_v1",
  "source_channel": "chatgpt"
}
```

Worker-ul respinge proprietățile suplimentare, deci numele, emailul, telefonul, notele și documentele nu pot fi forwardate accidental. La validare, evenimentul este trimis prin HTTPS către secretul `ANALYTICS_EVENT_FORWARD_URL`.

Maparea CRM trebuie configurată astfel:

1. la crearea lead-ului, salvează `lead_id` drept cheie tehnică neschimbată și câmpurile first-party UTM/referrer/program din payload;
2. la prima tranziție în starea aprobată de business „calificat”, emite webhook-ul o singură dată;
3. nu trimite datele de contact sau descrierile;
4. la retry păstrează același `lead_correlation_id`; destinația deduplică după eveniment + ID;
5. nu emite eveniment pentru spam, test sau lead revocat înainte de calificare.

Activarea rămâne `DE_VALIDAT_UMAN` până la alegerea CRM-ului/destinației analytics și configurarea celor două secrete. Codul și contractele sunt pregătite, dar nu a fost făcut deploy.
