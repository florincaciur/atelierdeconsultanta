# Înregistrări DE_VALIDAT_UMAN

Sursa unică: `config/seo-programs.json#programs`.

Înregistrările de mai jos au `publicationState=pending_validation` și sunt excluse din meniu, homepage, carduri, carusel și JSON-LD. Paginile lor primesc un mesaj neutru și `noindex, follow` până la confirmarea editorială.

| Program | Pagină | Câmpuri de confirmat | Sursă candidată | Acțiune umană |
|---|---|---|---|---|
| pnrr | /pnrr | verifiedAt, sourceName, sourceUrl, sourceVersion, lastMeaningfulUpdate, status | https://mfe.gov.ro/pnrr/ | Înregistrare creată dintr-o suprafață homepage care nu avea corespondent în registrul vechi. |
| programul-tranzitie-justa | /programul-tranzitie-justa | verifiedAt, sourceName, sourceUrl, sourceVersion, lastMeaningfulUpdate, status | DE_VALIDAT_UMAN | Înregistrare creată dintr-o suprafață homepage care nu avea corespondent în registrul vechi. |
| fondul-de-modernizare | /fondul-de-modernizare | verifiedAt, sourceName, sourceUrl, sourceVersion, lastMeaningfulUpdate, status | https://energie.gov.ro/category/fondul-pentru-modernizare/ | Înregistrare creată dintr-o suprafață homepage care nu avea corespondent în registrul vechi. |

## Regula de publicare

Un responsabil uman trebuie să verifice documentul oficial, versiunea și data, apoi să completeze câmpurile și să schimbe `publicationState` în `public`. Pentru DR12, statusul `consultare_publica` este doar candidat de migrare și nu trebuie tratat ca actual fără această confirmare.
