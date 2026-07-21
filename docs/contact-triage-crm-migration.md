# Migrarea transportului și a câmpurilor de contact

## Situația detectată

Repository-ul nu conține un CRM și nici un API propriu de lead-uri. Înainte de această schimbare, formularul canonic `/contact` deschidea clientul de email prin `mailto:`, iar formularul distinct de pe homepage trimitea direct la FormSubmit. Prin urmare, livrabilul nu poate fi descris corect ca o migrare CRM finalizată.

Noul endpoint `/api/contact-triage` validează payload-ul pe server și îl transmite către destinația HTTPS configurată în secretul Cloudflare `CONTACT_FORM_FORWARD_URL`. După aprobarea adresei operaționale, secretul poate indica endpointul FormSubmit existent. Când există un CRM real, același secret poate fi mutat către un adaptor CRM care respectă schema `1.0.0`, fără schimbarea formularului public.

## Maparea câmpurilor

| Câmp vechi | Câmp nou | Regula de migrare |
|---|---|---|
| `name` | — | eliminat din trierea inițială; poate fi cerut ulterior de consultant |
| `email` | `email` | opțional individual; obligatoriu numai în alternativa email OR telefon |
| `phone` | `phone` | opțional individual; obligatoriu numai în alternativa email OR telefon |
| `location` | `location` | obligatoriu |
| `applicant` / `applicant_type` | `applicant_type` | obligatoriu, taxonomie controlată |
| `caen` | `caen_or_so` | opțional; acceptă explicit „Nu știu încă” |
| `program` | `program_slug` | opțional; slug din registrul unic sau `unknown` |
| `budget` | `budget_estimate` | opțional; include buget/cofinanțare |
| `investment` | `investment` | obligatoriu, răspuns scurt |
| `message` | `extended_description` | mutat în pasul 2, opțional |
| — | `documents_summary` | pasul 2, opțional; nu încarcă fișiere |
| — | `expenses_summary` | pasul 2, opțional |
| — | `contact_preference` | pasul 2, opțional |
| checkbox GDPR vechi | `privacy_notice_acknowledged` | confirmare de citire, nu acord de marketing |
| — | `lead_id`, `schema_version`, `submitted_at` | trasabilitate tehnică; `submitted_at` este adăugat pe server |

## Activare și rollback

1. Juristul aprobă informarea și fișa juridică; poarta `validate:legal-identity:publish` trebuie să treacă.
2. Proprietarul aprobă adresa/destinația operațională.
3. Operatorul setează secretul Worker: `npx wrangler secret put CONTACT_FORM_FORWARD_URL --config wrangler.redirects.jsonc`.
4. Se rulează `npm run deploy:contact-triage`; comanda publică atât activele formularului, cât și Worker-ul de domeniu care deservește endpointul.
5. Se testează o solicitare cu email fără telefon și una cu telefon fără email, fără date reale sensibile.
6. Pentru rollback, secretul se mută către adaptorul anterior; formularul și schema nu trebuie schimbate.

Nu se adaugă valori de câmp în analytics. Worker-ul nu scrie payload-ul în loguri și nu repetă valorile în paginile HTML de eroare.

## Atribuire și calificare

Schema păstrează pentru CRM `lead_id`, `program_slug`, `program_family`, `source_channel`, UTM-urile și referrer-ul first-touch. Valorile brute de atribuire nu sunt trimise în analytics; acolo intră numai canalul normalizat.

La calificare, CRM-ul apelează o singură dată `/api/crm/qualified-lead` cu același `lead_id` în `lead_correlation_id`. Activarea necesită secretele `CRM_ANALYTICS_WEBHOOK_SECRET` și `ANALYTICS_EVENT_FORWARD_URL`; până la configurarea și validarea lor, integrarea rămâne `DE_VALIDAT_UMAN`.
