# Dashboard funnel

Definiția executabilă pentru implementarea în instrumentul ales este `config/funnel-dashboard.json`.

Fluxul este:

`cta_view → cta_click → form_start → step_1_complete → form_submit → qualified_lead`

Primele patru trepte folosesc numărul de evenimente deduplicate conform regulilor client. Ultimele două folosesc `COUNT DISTINCT lead_correlation_id`. Rata fiecărei trepte este `treapta curentă / treapta anterioară`; se afișează și conversia totală `qualified_lead / cta_view`.

Filtre/dimensiuni: pagină, tip pagină, program, familie, CTA, variantă copy, versiune formular, device, canal și experiment. Dashboard-ul pornește în vizualizarea filtrată anti-bot, dar păstrează un toggle pentru volumul brut.

Crearea efectivă în contul analytics rămâne `DE_VALIDAT_UMAN`: repository-ul nu conține credențiale sau identificatorul unei destinații server-side pentru `qualified_lead`.
