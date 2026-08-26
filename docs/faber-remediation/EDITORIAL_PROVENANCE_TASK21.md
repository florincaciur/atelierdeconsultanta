# Task 21 — proveniență și date editoriale

Registrul canonic este `config/editorial-governance.json` (schema v2). Implementarea separă cinci momente care nu sunt interschimbabile:

| Câmp conceptual | Sursă | Publicare |
|---|---|---|
| `datePublished` | dovada primei publicări a paginii | HTML și JSON-LD numai când data este confirmată |
| `dateModified` | `lastMeaningfulUpdate`, egal cu ultima intrare `changelog[].meaningful=true` | HTML, JSON-LD și sitemap `lastmod` |
| `verifiedAt` | reverificare reală în sursa oficială | HTML; poate avansa fără schimbarea `dateModified` |
| `officialSourceUpdatedAt` | data explicită a versiunii/actualizării sursei oficiale | HTML și `citation.dateModified` numai când este cunoscută |
| `nextReviewAt` | politica internă de prospețime | numai CMS și raport intern |

Buildul, timpul fișierului și data globală a colecției nu sunt surse pentru aceste câmpuri. O valoare necunoscută rămâne `DE_VALIDAT_UMAN` în registrul intern și este omisă din conținutul public și din schema paginii.

Publisherul organizațional folosește identitatea juridică aprobată. Author/reviewer nominal se publică numai după confirmarea persoanei, rolului, acordului și profilului vizibil; până atunci etichetele interne de workflow nu sunt transformate în entități Schema.org.

Istoricul existent nu a fost completat retroactiv. Generatorul sortează și afișează doar intrările materiale deja înregistrate, fără identitatea internă neconfirmată a reviewerului.
