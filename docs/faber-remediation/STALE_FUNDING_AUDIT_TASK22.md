# Task 22 — audit automat al statusurilor de finanțare

Auditul citește `config/seo-programs.json#programs`, taxonomia canonică și registrele existente de surse/aprobări. Nu accesează sursele online, nu confirmă factualitatea documentelor și nu modifică registrul, statusurile, HTML-ul, `verifiedAt`, `dateModified` sau sitemap `lastmod`. Un rezultat fără probleme înseamnă doar că datele înregistrate nu prezintă combinațiile suspecte testate.

## Comenzi și integrare

- `npm run audit:funding-status`: Markdown la stdout, data curentă UTC; fără scriere de fișiere.
- `npm run audit:funding-status -- --format=json`: rezultat machine-readable.
- `npm run audit:funding-status -- --today=2026-08-26`: audit reproductibil la o dată explicită, nu reverificare editorială.
- `npm run audit:funding-status -- --report`: scrie numai `reports/funding-status-audit.json` și `.md`, ignorate de Git și excluse din activele Cloudflare.
- `npm run test:funding-status`: fixture-uri deterministe, limite de dată, rezolvarea surselor, coduri de ieșire și verificarea read-only prin hash-uri.

Coduri de ieșire: **0** fără HIGH (poate avea WARNING), **1** cu HIGH, **2** audit indisponibil din cauza intrărilor/argumentelor invalide. Erorile de configurare nu sunt tratate ca audit reușit. `npm run build` rulează fixture-urile și auditul prin `prebuild`, înainte de generatoare. Workflow-ul `Funding status audit` rulează la push și PR către `main`/`master`, zilnic la 08:15 UTC și manual. Nu are permisiuni de scriere în repo și nu deschide/salvează automat corecții. Rapoartele sunt păstrate ca artefacte CI timp de 30 de zile, inclusiv când auditul identifică HIGH.

## Politică și reguli

Pragurile provin exclusiv din `config/editorial-governance.json#policy`: `openCallReviewDays` (30) și `programReviewDays` (60). Depășirea este WARNING, nu dovadă de închidere. Configurația lipsă/invalidă produce exit 2; nu există fallback ascuns care să relaxeze politica.

Datele sunt strict `YYYY-MM-DD`, validate calendaristic. Comparațiile sunt pe zile UTC, ca în guvernanța editorială existentă. Sfârșitul sesiunii este inclusiv: expirarea este `sessionEnd < today`. Auditul nu interpretează ore, date din text liber, mtime, data buildului ori `taxonomy.reviewedAt` ca data curentă.

| Situație | Severitate | Comportament |
|---|---|---|
| `OPEN` cu termen efectiv trecut | HIGH | Reverificare urgentă; niciodată schimbare automată în `CLOSED`. |
| `OPEN` fără sursă oficială completă | HIGH | Cere instituție, versiune/document și URL HTTPS acceptat de politica oficială existentă. |
| `OPEN` fără dovadă de sesiune rezolvabilă | HIGH | Referința trebuie să existe și să aparțină programului, dacă are asociere explicită. O listă nevidă cu referințe rupte nu este dovadă. |
| `OPEN` fără interval valid, încă neînceput ori cu date inversate | HIGH | Verificare a ferestrei oficiale. |
| `SCHEDULED` cu început trecut, fără `verifiedAt >= applicationStart` | WARNING | Verificare a începerii/amânării/suspendării; fără promovare automată la `OPEN`. |
| `PUBLIC_CONSULTATION` cu sfârșit trecut, fără `verifiedAt > consultationEnd` | WARNING | Verificare ulterioară închiderii perioadei de observații. |
| Dată de început SCHEDULED sau termen de consultare lipsă | WARNING | Completează din dovadă oficială, fără inferențe. |
| `verifiedAt` mai vechi decât pragul | WARNING | Include și programele istorice; nu blochează singur buildul. |
| `verifiedAt` absent, imposibil calendaristic sau viitor | HIGH pentru OPEN; altfel WARNING | Înregistrează numai data reală a verificării. |
| Prelungire fără sursă ori cu date incoerente | HIGH | Nu poate elimina eroarea de expirare. |
| Prelungire validă neaplicată încă în `applicationEnd` | WARNING | Raportul păstrează termenul brut și termenul efectiv; corecția publică rămâne editorială. |
| Status canonic necunoscut sau legacy OPEN în contradicție cu el | HIGH | Nu permite ocolirea regulilor OPEN prin schimbarea unui singur câmp. |

`canonicalStatus` este autoritativ. Codul legacy `consultare_publica` poate reprezenta un `CONSULTATIVE_GUIDE` după încheierea consultării; auditul nu îl confundă cu `PUBLIC_CONSULTATION`. `consultationStart`/`consultationEnd` sunt câmpuri opționale distincte de `applicationStart`/`applicationEnd`, adăugate în schema registrului. Nu au fost inventate sau completate intervale pentru programele actuale.

Un `CLOSED`/`COMPLETED` istoric nu primește eroare de expirare doar pentru că data de depunere a trecut. O reverificare recentă după un reper SCHEDULED/CONSULTATION suprimă alerta de reverificare lipsă; nu constituie confirmarea automată a statusului rămas în registry.

## Prelungiri documentate

`extensionData`, opțional și anterior fără structură definită, descrie ultima prelungire înregistrată:

- `originalEnd`: termenul înainte de prelungire;
- `extendedEnd`: termenul ulterior, strict mai mare;
- `sourceRef`: referință în formatul existent (`guide:…`, `registry:…`, `approval:…`, obiect `{ref,label}` sau `program` când acea pagină este explicit atribuită ca dovadă de sesiune/corrigendă);
- `verifiedAt`: data reală a verificării prelungirii, cel târziu data verificării programului și fără date în viitor.

Referința trebuie să se rezolve la o sursă oficială conform listei de domenii existente și să fie atribuită aceluiași program în `officialSources.roles.corrigenda` sau `sessionAnnouncement`. `applicationEnd` trebuie să fie fie `originalEnd`, fie `extendedEnd`. Un simplu URL sau existența unei corrigende fără aceste date nu justifică excepția. Auditul nu citește sensul documentului: persoana care înregistrează datele trebuie să confirme că documentul prelungește exact sesiunea respectivă. Dacă și termenul prelungit a trecut, eroarea HIGH rămâne.

## Rezolvare editorială și limite

Fiecare problemă include programul, statusul, începutul/sfârșitul sesiunii, `verifiedAt`, sursa, problema, severitatea și acțiunea recomandată; raportul adaugă și termenul efectiv și intervalul consultării. Verifică manual anunțul, platforma, corrigenda, suspendările și redeschiderile. Numai după verificare actualizezi faptele și jurnalul material folosind procedura existentă, apoi rerulezi auditul și testele.

Nu s-au schimbat facts sau surse și nu sunt necesare date interne FABER noi în `NEEDS_CONFIRMATION.md`. Problemele online neînregistrate, orele exacte de închidere, validitatea juridică ori semnificația unui document nu sunt deduse de acest audit offline. Aceste limite nu trebuie confundate cu un rezultat factual „apel confirmat”.
