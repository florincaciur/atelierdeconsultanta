# Dicționar evenimente funnel FABER

Versiune: `1.0.0` · formular: `short_v1` · registru tehnic: `config/funnel-analytics.json`.

Toate evenimentele sunt împinse în `window.dataLayer` și în stratul de evenimente Clarity prin același payload filtrat. Niciun eveniment nu citește valoarea unui input sau textul vizibil al CTA-ului.

| Eveniment | Moment determinist | Parametri specifici |
|---|---|---|
| `cta_view` | O singură dată/pagină/`cta_id`, când `IntersectionObserver` raportează cel puțin 50% | `cta_id`, `cta_copy_variant`, context program |
| `cta_click` | Click delegat pe CTA marcat explicit | aceiași ca `cta_view` |
| `form_start` | Prima interacțiune reală `pointerdown`, `keydown`, `input` sau `change`; nu la load/focus programatic | `form_version`, `step=1` |
| `step_1_complete` | Prima validare reușită a Pasului 1 | `form_version`, `step=1` |
| `field_error` | Fiecare eroare afișată | `field_name_generic`, `error_type`, fără valoare |
| `form_submit` | Numai după răspuns server `success=true` cu `leadId` pentru formularul scurt | `form_version`, `lead_correlation_id` |
| `contact_whatsapp` | Click pe linkul WhatsApp | `cta_id` |
| `contact_phone` | Click pe linkul `tel:` | `cta_id` |
| `contact_email` | Click pe linkul `mailto:` | `cta_id` |
| `qualified_lead` | Webhook autentificat trimis de CRM după schimbarea stării în „calificat” | `lead_correlation_id` și contextul non-PII păstrat în CRM |

Parametrii comuni permiși sunt: `page_path`, `page_type`, `cta_id`, `cta_copy_variant`, `program_slug`, `program_family`, `form_version`, `step`, `field_name_generic`, `device_category`, `source_channel`, `experiment_id`.

Două extensii controlate sunt necesare pentru a satisface integral contractul: `error_type` descrie categoria erorii, iar `lead_correlation_id` este UUID-ul first-party aleator care leagă `form_submit` de `qualified_lead`. Niciuna nu identifică direct persoana.

Evenimentele istorice `eligibility_cta_click`, `contact_page_click`, `whatsapp_number_click`, `phone_click`, `email_click`, `form_submit_success` și `form_validation_error` sunt normalizate intern la evenimentele canonice și nu mai formează funnel-uri paralele.

`source_channel` este o categorie (`chatgpt`, `google`, `bing`, `meta`, `linkedin`, `email`, `referral`, `direct`, `internal`, `campaign`). UTM-urile și referrer-ul integral nu intră în analytics; ele rămân first-party în sesiune și sunt trimise numai în payload-ul CRM.
