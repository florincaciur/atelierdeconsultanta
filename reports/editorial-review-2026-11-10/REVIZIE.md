# Revizia editorială a celor 106 pagini

Revizie din 10 noiembrie 2026. Jurnalul urmează scorul descrescător și ordinea din CSV pentru scoruri egale. Fiecare rând identifică HTML-ul canonic, sursa de generare, rezultatul, secțiunile păstrate, documentele aplicabile și dependențele specifice paginii.

- `JURNAL.csv` este tabelul de lucru pentru Excel. `JURNAL.json` păstrează structurat dovezile, textul vizibil extras din browser și amprenta HTML-ului final.
- `corrections.json` păstrează fragmentele înainte și după pentru corecțiile sistematice. Corecțiile punctuale sunt rezumate pe URL în jurnal.
- `no-js-local.json` păstrează verificările browserului la 390 și 1440 px. `official-link-check.json` consemnează răspunsurile HTTP ale legăturilor instituționale. Răspunsul serverului și verificarea conținutului documentului sunt consemnate separat.

Paginile despre alegerea consultantului și implementarea PNRR au primit exemple ipotetice cu documente și decizii concrete. Hubul digitalizare separă investițiile noi în Regiunea Centru de proiectele PNRR contractate și de apelul PoCIDIF încheiat. Din șabloane au fost eliminate explicațiile despre redactare, câmpurile „CTA”, paragrafele adăugate pentru lungime și calculele generale de grant care nu răspundeau întrebării paginii.

Pentru programele din registru, jurnalul trimite la verificarea documentară din 10 noiembrie, care consemnează autoritatea, versiunea, statutul și calendarul. Revizia a confruntat textele cu acele fișe și a verificat punctual ghidurile pentru afirmațiile corectate. Verificarea proprie a unui proiect depinde în continuare de ghidul aplicabil, de documentele solicitantului și de situația apelului la depunere. [Fișele programelor](../funding-review-2026-11-10/VERIFICARE.md)

Pentru Apelul 2 ADR Centru au fost folosite ghidul disponibil local și informația indexată de autoritatea emitentă. Pagina instituțională a returnat HTTP 403 la accesul direct. Valorile din exemplul ERP sunt ipoteze, iar starea efectivă în MySMIS se verifică la deschiderea sesiunii. [Pagina ADR Centru](https://www.regiocentru.ro/actiuni/2-2-intreprinderi-digitale-pentru-o-economie-avansata-apel-2/)

Ghidul AFIR V7 și ordinul de aprobare atribuie schema de autoconsum agroalimentar Fondului pentru Modernizare. Nota calculatorului SO folosește ghidurile finale DR-12 și DR-14. Conținutul de proiectare se raportează la domeniul de aplicare al HG 907/2016. [Schema de energie AFIR](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/), [DR-12](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/), [DR-14](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/), [HG 907/2016](https://legislatie.just.ro/Public/DetaliiDocument/185166)

Profilurile de echipă, calificările, studiile de caz și rezultatele reale depind de dovezi ale firmei și de dreptul de publicare. Jurnalul păstrează aceste condiții în rândurile despre FABER și studii de caz. Textele explicative publicate folosesc situații ipotetice când nu există un caz de client aprobat.

Compararea brută a rezultatului generatoarelor `generate-2026-program-pages.js --check` și `sync-calculator-so-methodology.js --check` semnala diferențe și la commitul de bază `f16bee6f`. Pentru această revizie au fost validate separat HTML-ul canonic final, metadatele, schema, ancorele și fișierele de publicare Cloudflare. Rezultatul de pe site este verificat față de sursa canonică, după aplicarea generatoarelor și sincronizărilor relevante.
