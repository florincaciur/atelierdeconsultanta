# Legături contextuale · 10 noiembrie 2026

Referința inițială este `origin/main` la `fafcf98cd71e4b0e65550dbeccfa20c309631ff1`. Inventarul cuprinde cele 107 URL-uri canonice din sitemap. Graful direcționat păstrează numai trimiterile către o altă pagină canonică de pe domeniul principal. Aliasurile, redirecționările, resursele descărcabile și fragmentele din aceeași pagină sunt în afara grafului.

Am numărat separat ancorele din conținutul principal vizibil, ancorele incluse în paragrafe și ancorele din meniul global desktop și mobil. Conținutul principal include și trimiterile tematice afișate în blocurile de program, ghid sau serviciu. Breadcrumb-urile au fost validate separat. Două ancore de pe aceeași pagină către aceeași destinație reprezintă o singură sursă distinctă.

| Indicator | Înainte | După |
| --- | ---: | ---: |
| Pagini canonice | 107 | 107 |
| Ancore în conținutul principal | 1.328 | 1.383 |
| Perechi sursă–destinație în conținutul principal | 980 | 1.026 |
| Destinații cu sub două surse în conținutul principal | 24 | 0 |
| Destinații fără surse în conținutul principal | 8 | 0 |
| Ancore în paragrafe | 107 | 162 |
| Perechi sursă–destinație în paragrafe | 88 | 143 |
| Destinații cu sub două surse strict în paragrafe | 92 | 69 |
| Ancore în meniul global | 8.056 | 8.056 |
| Perechi sursă–destinație în meniul global | 3.498 | 3.498 |
| Destinații respinse în conținutul principal sau în meniu | 0 | 0 |
| Neconcordanțe între breadcrumb vizibil și JSON-LD | 0 | 0 |
| Trasee complete program → ghid → serviciu → contact | 15 din 27 | 27 din 27 |

Cele 55 de ancore editoriale noi apar în paragrafe din 40 de pagini. Pentru prioritățile din inspecția Search Console din 9 noiembrie, sursele distincte strict în paragrafe au crescut de la 0 la 2 pentru `/consultanta-pnrr-digitalizare`, de la 1 la 3 pentru `/fonduri-europene-digitalizare` și de la 0 la 2 pentru `/cum-alegi-consultant-fonduri-europene`. Fiecare dintre cele trei răspunsuri din `/intrebari/`, cele patru ghiduri CAEN și cele două pagini de resurse are acum câte două surse în paragrafe. Măsurătoarea privește legăturile și folosește inspecția istorică pentru stabilirea priorităților.

## Corecții în registrul programelor

| Program | Trimitere actualizată | Justificare |
| --- | --- | --- |
| PNRR Digitalizare IMM | Ghidul de documentare a cheltuielilor PNRR Digitalizare IMM | Beneficiarul contractat găsește dovezile pentru achiziții, recepție și plată. |
| PNRR | Textul ancorei către serviciul PNRR | Delimitează sprijinul la implementarea proiectelor de digitalizare contractate. |
| Digitalizare IMM Regiunea Centru · Apel 2 | Consultanță pentru finanțarea IMM-urilor | Cititorul verifică investiția și documentele apelului regional. |
| PoCIDIF 2.1 | Consultanță pentru fonduri europene | Ghidul cheltuielilor trimite către sprijin pentru clarificări și contractare la dosarele deja depuse. |
| Apeluri GAL și GAL-AFIR | Consultanță AFIR | Cititorul ajunge la serviciul dedicat investițiilor rurale și documentelor intervenției. |

Fiecare program păstrează și trimiterea directă către formular, cu `program_slug` și `source_page`. Nu au fost necesare reguli noi de redirecționare. Verificarea locală a găsit 140 de reguli existente fără bucle, lanțuri sau legături interne către acestea.

## Dovezi

- Graful cu numărul de ancore pe fiecare pereche [înainte](graf-inainte.csv) și [după](graf-dupa.csv).
- [Sursele distincte pentru fiecare dintre cele 107 canonice](canonice.csv).
- [Ancorele inserate, paragrafele și justificarea editorială](legaturi-editoriale.csv).
- [Traseele celor 27 de programe și fragmentele de atribuire la contact](trasee-programe.csv).

Pentru reproducere, rulează `npm run test:editorial-links` sau exportă graful cu `node tools/audit-editorial-links.js --output=graf.json`. Configurația legăturilor se află în `config/editorial-contextual-links.json`. Generatorul o aplică în pipeline după sincronizarea conținutului.
