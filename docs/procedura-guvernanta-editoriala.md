# Procedură de guvernanță editorială

Se aplică paginilor de program, ghidurilor și instrumentelor. Registrul operațional este `config/editorial-governance.json`; statusurile și valorile programelor rămân în registrul factual `config/seo-programs.json#programs`.

## Roluri și separarea responsabilităților

1. **Verifică — consultantul de specialitate.** Deschide sursa oficială, confirmă instituția, documentul/versiunea, caracterul final ori consultativ, datele de depunere și orice valoare numerică. Notează data verificării și schimbarea substanțială. Agregatoarele pot ajuta la orientare, dar nu sunt sursă primară.
2. **Aprobă — editorul coordonator sau responsabilul de conformitate.** Compară pagina cu registrul programului, verifică formularea și stabilește `nextReviewAt`: maximum 30 de zile pentru apel deschis, maximum 60 de zile pentru altă pagină de program și 60–90 de zile pentru conținut evergreen. Completează changelogul.
3. **Publică — persoana cu drept de publicare în CMS.** Publică numai după trecerea validărilor și a testelor. Un singur om poate îndeplini mai multe roluri doar dacă aprobarea rămâne explicită în istoric.

Se afișează nume personale numai după acord documentat. În lipsa acordului se folosește atribuirea organizațională aprobată, de exemplu „Echipa editorială FABER”.

## Flux înainte de publicare

1. Actualizează sursa factuală și registrul editorial; nu edita statusul sau valorile în HTML, carduri ori JSON-LD.
2. Pentru o schimbare substanțială, adaugă în `changelog[]` data, rezumatul și reviewerul, apoi actualizează `lastMeaningfulUpdate`. Sunt substanțiale: statusul, calendarul, eligibilitatea, bugetul/cofinanțarea, documentul-sursă și concluzia unui instrument. Nu sunt substanțiale: deploy-ul, CSS-ul, formatarea și corecțiile pur tehnice.
3. Rulează `npm run validate:editorial-governance`, `npm run sync:editorial-governance`, `npm run test:editorial-governance` și build-ul complet.
4. Verifică filtrul CMS și raportul `reports/editorial-governance-expiry.md`. O alertă expirată nu rescrie automat conținutul, statusul sau datele.

## Revocarea unei informații greșite

Oprește imediat promovarea informației și setează înregistrarea editorială la `revoked` sau programul factual la `pending_validation`, după caz. Elimină valorile nesusținute, păstrează un mesaj neutru, adaugă în changelog ce s-a revocat și de ce, apoi rulează validările și sincronizarea. Reviewerul reface verificarea din sursa oficială; numai după aprobare se revine la `public`. Nu se schimbă retroactiv istoricul și nu se inventează un status provizoriu. `noindex` pentru arhive se aplică numai printr-o decizie editorială explicită privind valoarea evergreen.
