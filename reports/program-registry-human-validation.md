# Înregistrări DE_VALIDAT_UMAN

Sursa unică: `config/seo-programs.json#programs`.

Înregistrările de mai jos au `publicationState=pending_validation` și sunt excluse din meniu, homepage, carduri, carusel și JSON-LD. Paginile lor primesc un mesaj neutru și `noindex, follow` până la confirmarea editorială.

| Program | Pagină | Câmpuri de confirmat | Sursă candidată | Acțiune umană |
|---|---|---|---|---|
| digitalizare-imm | /digitalizare-imm | verifiedAt, sourceUrl, sourceVersion, lastMeaningfulUpdate, status, validatorName | https://diaspora.gov.ro/povesti/364-pnrr-mipe-a-dat-startul-apelului-de-proiecte-de-350-de-milioane-de-euro-pentru-digitalizarea-imm-urilor | Apelul PNRR istoric apare închis, dar documentul oficial curent și delimitarea față de hub trebuie confirmate de consultantul FABER. |
| pro-infra | /pro-infra | verifiedAt, sourceUrl, sourceVersion, lastMeaningfulUpdate, status, applicationStart, applicationEnd, grantSummary, cofinancingSummary, validatorName | https://legislatie.just.ro/Public/DetaliiDocumentAfis/306916 | Sursa confirmă o schemă aprobată, nu un ghid și nu un apel deschis; intervalul de depunere rămâne DE_VALIDAT_UMAN. |
| pnrr | /pnrr | verifiedAt, sourceName, sourceUrl, sourceVersion, lastMeaningfulUpdate, status | https://mfe.gov.ro/pnrr/ | Înregistrare creată dintr-o suprafață homepage care nu avea corespondent în registrul vechi. |
| programul-tranzitie-justa | /programul-tranzitie-justa | verifiedAt, sourceName, sourceUrl, sourceVersion, lastMeaningfulUpdate, status | DE_VALIDAT_UMAN | Înregistrare creată dintr-o suprafață homepage care nu avea corespondent în registrul vechi. |
| fondul-de-modernizare | /fondul-de-modernizare | verifiedAt, sourceName, sourceUrl, sourceVersion, lastMeaningfulUpdate, status | https://energie.gov.ro/category/fondul-pentru-modernizare/ | Înregistrare creată dintr-o suprafață homepage care nu avea corespondent în registrul vechi. |

## Regula de publicare

Un responsabil uman trebuie să verifice documentul oficial, versiunea și data, apoi să completeze câmpurile și să schimbe `publicationState` în `public`. Pentru DR12, statusul `consultare_publica` este doar candidat de migrare și nu trebuie tratat ca actual fără această confirmare.
