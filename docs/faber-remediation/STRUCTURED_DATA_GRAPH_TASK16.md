# Task 16 — graph Schema.org coerent și fără spam

Data verificării: **2026-08-24**.

## Model canonic

- FABER este definit o singură dată pe pagină prin `Organization` + `ProfessionalService`, cu date exclusiv din registrul juridic aprobat.
- Fiecare rută indexabilă are `WebSite` și un singur `WebPage`; paginile editoriale reale folosesc `Article`, serviciile folosesc `Service`, iar Calculatorul SO folosește `WebApplication`.
- Paginile de program folosesc tipul oficial [`FinancialIncentive`](https://schema.org/FinancialIncentive). FABER rămâne publisher-ul paginii, în timp ce autoritatea programului este o entitate `Organization` distinctă, referită prin `provider`.
- Documentul oficial este un `CreativeWork` distinct, legat prin `subjectOf`. URL-ul documentului nu este folosit ca `sameAs` al programului.
- `BreadcrumbList` și `FAQPage` sunt publicate numai când există echivalent vizibil și au ID-uri stabile derivate din canonical.
- Sursele editoriale sunt definite o singură dată și apoi referite prin `@id`; autorii/reviewerii necunoscuți nu sunt transformați în persoane sau organizații inventate.

## Garanții automate

Auditul verifică JSON valid, un singur bloc determinist, ID-uri stabile și definiții unice, o singură variantă FABER, profiluri `sameAs` aprobate, tipuri corecte pe rută, concordanța H1/meta/FAQ și separarea publisher–autoritate–sursă oficială.

Sunt respinse explicit `FundingProgram`, rating-uri/review-uri/premii inventate, număr de angajați, `foundingDate`, certificări și atribuiri neverificate.

## Rezultat

- 188 fișiere HTML parseate;
- 104 rute indexabile auditate;
- 551 ID-uri top-level stabile verificate;
- 24 entități `FinancialIncentive` pe rutele indexabile;
- 66 `FAQPage`, cu 405 întrebări/răspunsuri identice cu HTML-ul vizibil;
- 1 variantă canonică FABER;
- 0 probleme în `reports/structured-data-audit.json`.
