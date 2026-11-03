# Registrul surselor oficiale FABER

Snapshot factual de bază al programelor: **2026-08-23**. Fiecare înregistrare poate avea o reverificare mai nouă, publicată în câmpul `verifiedAt`. Revizia structurii registrului: **2026-08-28**. Rolurile per program: `config/seo-programs.json#programs[*].officialSources`; surse suplimentare: `config/program-source-registry.json#supplementalSources`; catalog documente: `official-guides.json`. Document generat de `tools/generate-status-governance-docs.js`.

## Reguli de audit

- Sunt acceptate numai surse primare ale autorității competente, Portalului Legislativ/Monitorului Oficial ori platformelor publice oficiale.
- `Pagină oficială` este punctul stabil de pornire; `ghid`, `anexe`, `schemă/ordin`, `anunț sesiune`, `corrigenda` și `clarificări` sunt roluri distincte și nu se substituie reciproc.
- Un câmp neidentificat este un gol explicit al registry-ului, nu afirmația că documentul nu există. Golul nu poate susține o stare mai optimistă.
- `Latest official update` înseamnă ultima actualizare consemnată pentru program la data lui `verifiedAt`, nu o garanție că instituția nu a publicat ulterior alt document.
- URL-ul accesibil nu este singur dovadă de `OPEN`; sunt obligatorii identificarea sesiunii, fereastra curentă și controlul actualizărilor ulterioare.
- Cele 32 de categorii solicitate sunt documentate pentru fiecare program. Când sursa oficială verificată nu stabilește un câmp, fișa publică exact golul factual, fără completări speculative.

## Acoperire

| Stable program ID | Autoritate | Status canonic | Ultima actualizare oficială înregistrată | Verificat |
|---|---|---|---|---|
| `program-regional-nord-est` | Autoritatea de Management pentru Programul Regional Nord-Est | `UNCONFIRMED` | 2026-08-18 | 2026-11-03 |
| `fonduri-regionale` | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 | `UNCONFIRMED` | 2026-08-18 | 2026-11-03 |
| `dr12-afir` | Agenția pentru Finanțarea Investițiilor Rurale (AFIR) | `OPEN` | 2026-11-03 | 2026-11-03 |
| `dr14-afir` | Agenția pentru Finanțarea Investițiilor Rurale (AFIR) | `OPEN` | 2026-11-03 | 2026-11-03 |
| `dr18-afir` | Agenția pentru Finanțarea Investițiilor Rurale (AFIR) | `OPEN` | 2026-11-03 | 2026-11-03 |
| `start-up-nation` | Ministerul Economiei – platforma oficială MINIMIS | `CLOSED` | 2026-05-29 | 2026-11-03 |
| `femeia-antreprenor` | Ministerul Economiei – platforma oficială MINIMIS | `CLOSED` | 2026-09-02 | 2026-11-03 |
| `digitalizare-imm` | Ministerul Investițiilor și Proiectelor Europene | `CLOSED` | 2026-07-22 | 2026-11-03 |
| `modernizare-microintreprinderi-ne-2` | Autoritatea de Management pentru Programul Regional Nord-Est | `CLOSED` | 2026-11-03 | 2026-11-03 |
| `fondul-modernizare-autoconsum` | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 | `COMPLETED` | 2026-08-18 | 2026-11-03 |
| `fondul-modernizare-regenerabile` | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 | `COMPLETED` | 2026-08-18 | 2026-11-03 |
| `afir-energie-autoconsum` | Ministerul Agriculturii și Dezvoltării Rurale / AFIR | `CLOSED` | 2026-08-15 | 2026-11-03 |
| `autoconsum-institutii-publice` | Ministerul Energiei / AFIR | `OPEN` | 2026-11-03 | 2026-11-03 |
| `fondul-modernizare-pc1-stocare-entitati-publice` | Ministerul Energiei / AFIR | `OPEN` | 2026-11-03 | 2026-11-03 |
| `pro-infra` | Ministerul Transporturilor și Infrastructurii | `APPROVED_SCHEME` | 2026-09-06 | 2026-11-03 |
| `apeluri-gal` | Platforma oficială AFIR pentru Grupurile de Acțiune Locală | `UNCONFIRMED` | 2026-08-18 | 2026-11-03 |
| `gal-afir-leader` | Platforma oficială AFIR pentru Grupurile de Acțiune Locală | `UNCONFIRMED` | 2026-09-02 | 2026-11-03 |
| `e-move-ro` | Ministerul Transporturilor și Infrastructurii / Portal Legislativ | `APPROVED_SCHEME` | 2026-08-10 | 2026-11-03 |
| `pocidif-21` | Ministerul Investițiilor și Proiectelor Europene | `CLOSED` | 2026-11-03 | 2026-11-03 |
| `pnrr` | Ministerul Investițiilor și Proiectelor Europene – tabloul de bord PNRR | `UNCONFIRMED` | 2026-09-10 | 2026-11-03 |
| `diaspora-investeste-acasa` | Banca de Investiții și Dezvoltare (BID) | `APPROVED_SCHEME` | 2026-09-06 | 2026-11-03 |
| `e-drive` | Ministerul Transporturilor și Infrastructurii – DGPET | `PUBLIC_CONSULTATION` | 2026-11-03 | 2026-11-03 |
| `e-mobility-ro` | Ministerul Transporturilor și Infrastructurii – DGPET | `OPEN` | 2026-11-03 | 2026-11-03 |
| `fondul-modernizare-pc1-stocare` | Ministerul Energiei | `OPEN` | 2026-11-03 | 2026-11-03 |
| `programul-tranzitie-justa` | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 | `UNCONFIRMED` | 2026-09-10 | 2026-11-03 |
| `fondul-de-modernizare` | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 | `UNCONFIRMED` | 2026-09-10 | 2026-11-03 |

## `program-regional-nord-est` — Programul Regional Nord-Est 2021–2027

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `program-regional-nord-est` |
| Denumire oficială | Programul Regional Nord-Est 2021–2027 |
| Acronim | PR Nord-Est |
| Autoritate | Autoritatea de Management pentru Programul Regional Nord-Est |
| Fond / program | Programul Regional Nord-Est 2021–2027 |
| Temei / document | Registrul oficial al apelurilor Programului Regional Nord-Est, verificat la 29.08.2026 — [document oficial](https://regionordest.ro/apeluri-de-proiecte/) |
| Stadiu | UNCONFIRMED — Program activ – statutul și calendarul diferă pentru fiecare apel |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Solicitanții definiți de fiecare apel regional |
| Regiune | Regiunea Nord-Est |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Județul, codul CAEN, amplasamentul și dreptul asupra spațiului se verifică în ghidul apelului selectat. |
| Documente | [Registrul oficial al apelurilor Programului Regional Nord-Est](https://regionordest.ro/apeluri-de-proiecte/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Registrul oficial al apelurilor Programului Regional Nord-Est](https://regionordest.ro/apeluri-de-proiecte/) |
| Latest official update | 2026-08-18 — [Registrul oficial al apelurilor Programului Regional Nord-Est, verificat la 29.08.2026](https://regionordest.ro/apeluri-de-proiecte/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Registrul oficial al apelurilor Programului Regional Nord-Est](https://regionordest.ro/apeluri-de-proiecte/) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Registrul oficial al apelurilor Programului Regional Nord-Est, verificat la 29.08.2026](https://regionordest.ro/apeluri-de-proiecte/) (verificat 2026-11-03) |
| Chei surse repo | `adr-ne-program`, `adr-ne-region` |
| Notes | Pagină agregată. Statutul și calendarul trebuie verificate pentru fiecare apel; o stare de apel nu se propagă asupra întregului program. |

## `fonduri-regionale` — Programele regionale 2021–2027

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `fonduri-regionale` |
| Denumire oficială | Programele regionale 2021–2027 |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 |
| Fond / program | Programele regionale 2021–2027 |
| Temei / document | Registrul oficial MySMIS2021 al apelurilor validate 2021–2027 — [document oficial](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Stadiu | UNCONFIRMED — Programe active – statutul și calendarul se verifică pentru fiecare apel |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Solicitanții definiți în ghidul fiecărui apel regional |
| Regiune | regional |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Regiunea, categoria solicitantului și apelul concret trebuie identificate înainte de folosirea unor valori financiare. |
| Documente | [Catalogul oficial MySMIS2021 al finanțărilor 2021–2027](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Catalogul oficial MySMIS2021 al finanțărilor 2021–2027](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Latest official update | 2026-08-18 — [Registrul oficial MySMIS2021 al apelurilor validate 2021–2027](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Catalogul oficial MySMIS2021 al finanțărilor 2021–2027](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Registrul oficial MySMIS2021 al apelurilor validate 2021–2027](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (verificat 2026-11-03) |
| Chei surse repo | `fonduri-regionale` |
| Notes | Pagină agregată pentru programe regionale; ghidurile și sesiunile se urmăresc la nivelul apelului selectat. |

## `dr12-afir` — DR-12 Investiții în consolidarea exploatațiilor tinerilor fermieri instalați și a fermierilor cu vârsta de până la 45 de ani

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `dr12-afir` |
| Denumire oficială | DR-12 Investiții în consolidarea exploatațiilor tinerilor fermieri instalați și a fermierilor cu vârsta de până la 45 de ani |
| Acronim | DR-12 |
| Autoritate | Agenția pentru Finanțarea Investițiilor Rurale (AFIR) |
| Fond / program | Planul Strategic PAC 2023–2027 / FEADR |
| Temei / document | Ghid final DR-12, Ediția I, Revizia 0, aprobat prin OMADR 268/17.09.2026; publicat de AFIR la 18.09.2026 — [document oficial](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/) |
| Stadiu | OPEN — Sesiune deschisă – depuneri 6 octombrie–2 decembrie 2026 |
| Sesiune | [Anunț AFIR: sesiunea DR-12, 6 octombrie–2 decembrie 2026](https://www.afir.ro/info-la-zi/sesiune-depunere-de-proiecte-dr-12/) (`registry:afir-dr12-session-2026`, verificat 2026-11-03)<br>[Contorul AFIR al sesiunilor active](https://depunerepspac.afir.ro/Sesiune/Lista) (`registry:afir-active-sessions-20261103`, verificat 2026-11-03) |
| Data deschiderii | 06.10.2026 |
| Deadline | 02.12.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 200.000 EUR / proiect |
| Intensitate | rate: 80; scope: maximum pentru tinerii fermieri sub 41 de ani, șefi de exploatație cu competențe adecvate; rate: 65; scope: maximum pentru celelalte categorii eligibile |
| Cofinanțare | Minimum 20% sau 35% din costurile eligibile, după categoria beneficiarului, plus costurile neeligibile și TVA recuperabilă. Plafonul de 200.000 EUR poate majora contribuția efectivă. |
| Beneficiari | Tineri fermieri instalați, cu maximum 40 de ani inclusiv (înainte de 41).; Fermieri care au finalizat planul de afaceri sM 6.1, indiferent de vârstă.; Fermieri instalați cu maximum 45 de ani inclusiv (înainte de 46). PFA, II, IF sau SRL în condițiile ghidului; persoanele fizice neautorizate nu sunt eligibile. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Minimum 12.000 EUR SO la depunere, calculat cu coeficienții SOC 2020 și dovedit prin registrele fermei.; Șef al exploatației, control efectiv și competențe profesionale adecvate proiectului.; Înregistrare IACS-APIA și în registrele relevante pe forma solicitantului, cofinanțare și viabilitate economică demonstrate.; Sesiune de depunere deschisă între 06.10.2026 și 02.12.2026, ora 16:00; disponibilitatea se verifică pe componente în platforma AFIR.; Costuri generale: maximum 10% cu construcții-montaj sau 3% pentru achiziții fără construcții-montaj; marketing maximum 5%. Minimum 50% materie primă proprie la procesare/condiționare/depozitare. Extrasul pentru cofinanțare se însoțește de angajamentul folosirii a minimum 50% din disponibil pentru proiect. |
| Documente | [Pagina AFIR DR-12 și anexele finale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/)<br>[Ghidul final DR-12 (PDF AFIR), 18.09.2026](https://www.afir.ro/media/aqtlitop/ghidul-solicitantului-dr-12.pdf)<br>[OMADR 268/17.09.2026 – aprobarea ghidului](https://www.afir.ro/instrumente/normative/legislatie-nationala/)<br>[Anunț AFIR: sesiunea DR-12, 6 octombrie–2 decembrie 2026](https://www.afir.ro/info-la-zi/sesiune-depunere-de-proiecte-dr-12/)<br>[Contorul AFIR al sesiunilor active](https://depunerepspac.afir.ro/Sesiune/Lista) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Pagina AFIR DR-12 și anexele finale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/)<br>[Ghidul final DR-12 (PDF AFIR), 18.09.2026](https://www.afir.ro/media/aqtlitop/ghidul-solicitantului-dr-12.pdf)<br>[OMADR 268/17.09.2026 – aprobarea ghidului](https://www.afir.ro/instrumente/normative/legislatie-nationala/)<br>[Anunț AFIR: sesiunea DR-12, 6 octombrie–2 decembrie 2026](https://www.afir.ro/info-la-zi/sesiune-depunere-de-proiecte-dr-12/)<br>[Contorul AFIR al sesiunilor active](https://depunerepspac.afir.ro/Sesiune/Lista) |
| Latest official update | 2026-11-03 — [Ghid final DR-12, Ediția I, Revizia 0, aprobat prin OMADR 268/17.09.2026; publicat de AFIR la 18.09.2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Pagina AFIR DR-12 și anexele finale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul final DR-12 (PDF AFIR), 18.09.2026](https://www.afir.ro/media/aqtlitop/ghidul-solicitantului-dr-12.pdf) (`approval:evidence:0`, verificat 2026-11-03) |
| Anexe | [Cererea de finanțare și anexele DR-12](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/) (`program`, verificat 2026-11-03) |
| Schemă / ordin | [OMADR 268/17.09.2026 – aprobarea ghidului](https://www.afir.ro/instrumente/normative/legislatie-nationala/) (`approval:evidence:3`, verificat 2026-11-03) |
| Anunț sesiune | [Anunț AFIR: sesiunea DR-12, 6 octombrie–2 decembrie 2026](https://www.afir.ro/info-la-zi/sesiune-depunere-de-proiecte-dr-12/) (`registry:afir-dr12-session-2026`, verificat 2026-11-03)<br>[Contorul AFIR al sesiunilor active](https://depunerepspac.afir.ro/Sesiune/Lista) (`registry:afir-active-sessions-20261103`, verificat 2026-11-03) |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Ghid final DR-12, Ediția I, Revizia 0, aprobat prin OMADR 268/17.09.2026; publicat de AFIR la 18.09.2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/) (verificat 2026-11-03) |
| Chei surse repo | `dr12` |
| Notes | Sesiunea DR-12 este activă în platforma AFIR la 03.11.2026; disponibilul se verifică separat pe componente. |

## `dr14-afir` — DR-14 Investiții în fermele de mici dimensiuni

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `dr14-afir` |
| Denumire oficială | DR-14 Investiții în fermele de mici dimensiuni |
| Acronim | DR-14 |
| Autoritate | Agenția pentru Finanțarea Investițiilor Rurale (AFIR) |
| Fond / program | Planul Strategic PAC 2023–2027 / FEADR |
| Temei / document | Contorul oficial al sesiunilor active DR-14; cererea v1.1 din 25.08.2026 și clarificarea pe componente din 21.08.2026 — [document oficial](https://depunerepspac.afir.ro/Sesiune/Lista) |
| Stadiu | OPEN — Depuneri până la 16 noiembrie; componenta achiziții simple este închisă |
| Sesiune | [Anunțul cererii de proiecte DR-14, publicat la 14.08.2026](https://depunerepspac.afir.ro/Sesiune/Lista) (`guide:dr14`, verificat 2026-11-03) |
| Data deschiderii | 01.09.2026 |
| Deadline | 16.11.2026 |
| Prelungiri | originalEnd: 2026-10-31; extendedEnd: 2026-11-16; sourceRef: registry:afir-dr14-dr18-extension-2026; verifiedAt: 2026-11-03 |
| Buget | 108.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 50.000 EUR / proiect |
| Intensitate | rate: 85; scope: maximum din costurile eligibile |
| Cofinanțare | Beneficiarul acoperă diferența eligibilă, cheltuielile neeligibile și orice sumă care depășește plafonul ajutorului public. |
| Beneficiari | Fermieri, cu excepția persoanelor fizice, constituiți într-o formă eligibilă și activi în România.; Exploatații agricole încadrate în pragul SO aplicabil sectorului și componentei alese. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Dimensiune economică generală de 4.000–11.999 SO, cu praguri minime speciale de 2.000 SO sau 2.300 SO pentru sectoarele prevăzute în ghid.; Un singur proiect pe DR 14 și alegerea unei singure componente: legumicol, zootehnic, achiziții simple sau național – alte sectoare.; Ajutor public de maximum 50.000 EUR/proiect și intensitate de maximum 85% din costurile eligibile.; Investițiile secundare prevăzute de ghid se mențin sub 50% din valoarea eligibilă a proiectului.; Costurile generale sunt limitate la maximum 10% pentru proiectele cu lucrări și maximum 3% pentru proiectele cu achiziții simple.; Dimensiunea economică poate scădea cu maximum 15% în implementare, fără coborârea sub pragul minim eligibil.; Sesiunea a început la 1 septembrie 2026 și a fost prelungită până la 16 noiembrie 2026, ora 16:00. Componenta de achiziții simple este închisă din 6 octombrie; disponibilul și pragul aplicabil se verifică pe fiecare componentă în platforma AFIR.; Bugetul sesiunii este de 108 milioane EUR: câte 30 milioane EUR pentru zootehnie, legumicultură și alte sectoare și 18 milioane EUR pentru achiziții simple.; Achizițiile simple nu includ utilaje sau echipamente cu montaj/instalare. Proiectele cu asemenea echipamente se încadrează pe componenta sectorială potrivită, conform notei AFIR din 21.08.2026.; Se utilizează Cererea de finanțare DR-14 v1.1, actualizată la 25.08.2026.; Componenta achiziții simple este închisă din 06.10.2026; prelungirea până la 16.11.2026 privește componentele active. |
| Documente | [Pagina AFIR pentru sesiuni de primire proiecte](https://depunerepspac.afir.ro/Sesiune/Lista)<br>[Detalii și documentație DR-14 (AFIR)](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/)<br>[AFIR: prelungirea sesiunilor DR-14 și DR-18 până la 16 noiembrie](https://www.afir.ro/info-la-zi/prelungire-sesiune-depunere-proiecte-de-investitii-aferente-dr-14-si-dr-18/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Pagina AFIR pentru sesiuni de primire proiecte](https://depunerepspac.afir.ro/Sesiune/Lista)<br>[Detalii și documentație DR-14 (AFIR)](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/)<br>[AFIR: prelungirea sesiunilor DR-14 și DR-18 până la 16 noiembrie](https://www.afir.ro/info-la-zi/prelungire-sesiune-depunere-proiecte-de-investitii-aferente-dr-14-si-dr-18/) |
| Latest official update | 2026-11-03 — [Contorul oficial al sesiunilor active DR-14; cererea v1.1 din 25.08.2026 și clarificarea pe componente din 21.08.2026](https://depunerepspac.afir.ro/Sesiune/Lista) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Pagina AFIR pentru sesiuni de primire proiecte](https://depunerepspac.afir.ro/Sesiune/Lista) (`program`, verificat 2026-11-03) |
| Ghid | [Detalii și documentație DR-14 (AFIR)](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/) (`approval:evidence:1`, verificat 2026-11-03) |
| Anexe | [Detalii și anexe DR-14 (AFIR)](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-14/) (`approval:evidence:1`, verificat 2026-11-03) |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | [Anunțul cererii de proiecte DR-14, publicat la 14.08.2026](https://depunerepspac.afir.ro/Sesiune/Lista) (`guide:dr14`, verificat 2026-11-03) |
| Corrigenda / erate | [AFIR: prelungirea sesiunilor DR-14 și DR-18 până la 16 noiembrie](https://www.afir.ro/info-la-zi/prelungire-sesiune-depunere-proiecte-de-investitii-aferente-dr-14-si-dr-18/) (`registry:afir-dr14-dr18-extension-2026`, verificat 2026-11-03) |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Contorul oficial al sesiunilor active DR-14; cererea v1.1 din 25.08.2026 și clarificarea pe componente din 21.08.2026](https://depunerepspac.afir.ro/Sesiune/Lista) (verificat 2026-11-03) |
| Chei surse repo | `dr14` |
| Notes | Sesiune prelungită până la 16 noiembrie 2026, ora 16:00, pentru componentele active. Componenta achiziții simple s-a închis la 6 octombrie 2026 prin epuizarea fondurilor. |

## `dr18-afir` — DR-18 Investiții în floricultură, plante medicinale și aromatice

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `dr18-afir` |
| Denumire oficială | DR-18 Investiții în floricultură, plante medicinale și aromatice |
| Acronim | DR-18 |
| Autoritate | Agenția pentru Finanțarea Investițiilor Rurale (AFIR) |
| Fond / program | Planul Strategic PAC 2023–2027 / FEADR |
| Temei / document | Anunțul A1.2/01/2026 pentru sesiunea DR 18, publicat la 14.08.2026 — [document oficial](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/) |
| Stadiu | OPEN — Sesiune prelungită – depuneri până la 16 noiembrie 2026 |
| Sesiune | [Anunțul cererii de proiecte DR-18, publicat la 14.08.2026](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/) (`program`, verificat 2026-11-03) |
| Data deschiderii | 01.09.2026 |
| Deadline | 16.11.2026 |
| Prelungiri | originalEnd: 2026-10-31; extendedEnd: 2026-11-16; sourceRef: registry:afir-dr14-dr18-extension-2026; verifiedAt: 2026-11-03 |
| Buget | 5.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 100.000 EUR / proiect |
| Intensitate | rate: 85; scope: maximum pentru exploatații de 2.000–11.999 SO; rate: 65; scope: maximum pentru exploatații de minimum 12.000 SO |
| Cofinanțare | Beneficiarul acoperă diferența eligibilă, cheltuielile neeligibile, TVA potrivit regimului fiscal și orice depășire de cost. |
| Beneficiari | Fermieri organizați juridic, cu excepția persoanelor fizice.; Cooperative agricole și societăți cooperative care deservesc interesele membrilor fermieri.; Grupuri și organizații de producători recunoscute de MADR. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Dimensiune economică de minimum 2.000 SO, calculată cu coeficienții SOC 2020.; Solicitantul figurează înaintea depunerii în APIA, ANSVSA și/sau ANZ, după caz, pe aceeași formă juridică.; Ajutor public de maximum 100.000 EUR/proiect; intensitate de maximum 85% pentru 2.000–11.999 SO și 65% de la 12.000 SO.; Dimensiunea economică poate scădea cu maximum 15% în implementare, fără a coborî sub 2.000 SO.; Condiționarea, depozitarea și procesarea folosesc în proporție de minimum 50% producția proprie sau a membrilor și rămân activități secundare.; Energia regenerabilă este dimensionată pentru autoconsum și nu urmărește statutul de prosumator.; Costurile generale sunt limitate la 10% pentru proiecte cu lucrări și la 3% pentru achiziții simple.; Cheltuielile de marketing sunt limitate la maximum 5% din valoarea eligibilă.; Pentru costuri de peste 15.000 EUR sunt necesare minimum două oferte; până la 15.000 EUR este acceptată o ofertă sau un printscreen verificabil.; Criteriul pentru spații protejate folosește ponderile peste 50%, 25–50% și 15–25%; energia regenerabilă punctată reprezintă minimum 2% din eligibil.; Un proiect nu poate dubla finanțarea și respectă demarcarea față de DR 14, DR 22, DR 25 și intervențiile energetice. |
| Documente | [Pagina AFIR pentru sesiuni de primire proiecte](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/)<br>[Ghidul final DR-18](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-18/)<br>[AFIR: prelungirea sesiunilor DR-14 și DR-18 până la 16 noiembrie](https://www.afir.ro/info-la-zi/prelungire-sesiune-depunere-proiecte-de-investitii-aferente-dr-14-si-dr-18/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Pagina AFIR pentru sesiuni de primire proiecte](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/)<br>[Ghidul final DR-18](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-18/)<br>[AFIR: prelungirea sesiunilor DR-14 și DR-18 până la 16 noiembrie](https://www.afir.ro/info-la-zi/prelungire-sesiune-depunere-proiecte-de-investitii-aferente-dr-14-si-dr-18/) |
| Latest official update | 2026-11-03 — [Anunțul A1.2/01/2026 pentru sesiunea DR 18, publicat la 14.08.2026](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Pagina AFIR pentru sesiuni de primire proiecte](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul final DR-18](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-18/) (`registry:afir-dr18-guide-annexes`, verificat 2026-08-28) |
| Anexe | [Anexele DR-18](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-18/) (`registry:afir-dr18-guide-annexes`, verificat 2026-08-28) |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | [Anunțul cererii de proiecte DR-18, publicat la 14.08.2026](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/) (`program`, verificat 2026-11-03) |
| Corrigenda / erate | [AFIR: prelungirea sesiunilor DR-14 și DR-18 până la 16 noiembrie](https://www.afir.ro/info-la-zi/prelungire-sesiune-depunere-proiecte-de-investitii-aferente-dr-14-si-dr-18/) (`registry:afir-dr14-dr18-extension-2026`, verificat 2026-11-03) |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Anunțul A1.2/01/2026 pentru sesiunea DR 18, publicat la 14.08.2026](https://www.afir.ro/instrumente/sesiuni/sesiuni-primire-proiecte/) (verificat 2026-11-03) |
| Chei surse repo | `dr18` |
| Notes | Sesiune prelungită până la 16 noiembrie 2026, ora 16:00. Disponibilul și eventualele închideri anticipate se verifică în platforma AFIR. |

## `start-up-nation` — Programul Start-Up Nation

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `start-up-nation` |
| Denumire oficială | Programul Start-Up Nation |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Economiei – platforma oficială MINIMIS |
| Fond / program | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Temei / document | Start-Up Nation 2024 – transparența înscrierilor persoanelor juridice; ultima înscriere la 29.05.2026, ora 20:00 — [document oficial](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) |
| Stadiu | CLOSED — Apel închis – înscrierile persoanelor juridice s-au încheiat la 29 mai 2026, ora 20:00 |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | 29.05.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | O eventuală sesiune nouă trebuie confirmată în platforma MINIMIS și în procedura oficială aplicabilă. |
| Documente | [Transparența înscrierilor Start-Up Nation 2024 — MINIMIS](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Transparența înscrierilor Start-Up Nation 2024 — MINIMIS](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) |
| Latest official update | 2026-05-29 — [Start-Up Nation 2024 – transparența înscrierilor persoanelor juridice; ultima înscriere la 29.05.2026, ora 20:00](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Transparența înscrierilor Start-Up Nation 2024 — MINIMIS](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) (`program`, verificat 2026-11-03) |
| Ghid | [Procedura oficială referită de registru](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) (`guide:startup`, verificat 2026-11-03) |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Start-Up Nation 2024 – transparența înscrierilor persoanelor juridice; ultima înscriere la 29.05.2026, ora 20:00](https://minimis.imm.gov.ro/sn2024/transparenta_persoane_juridice) (verificat 2026-11-03) |
| Chei surse repo | `startup` |
| Notes | Depunerea persoanelor juridice este închisă. Registrul nu consemnează separat finalizarea întregii proceduri. |

## `femeia-antreprenor` — Femeia Antreprenor 2026 — ediție neconfirmată

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `femeia-antreprenor` |
| Denumire oficială | Femeia Antreprenor 2026 — ediție neconfirmată |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Economiei – platforma oficială MINIMIS |
| Fond / program | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Temei / document | Femeia Antreprenor 2024 – ordinea finală la evaluare — [document oficial](https://minimis.imm.gov.ro/fa2024/ordine_evaluare) |
| Stadiu | CLOSED — Apel 2024 închis – este publicată ordinea finală la evaluare |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | O ediție nouă, condițiile și calendarul trebuie confirmate într-un document oficial actual. |
| Documente | [Ordinea finală la evaluare Femeia Antreprenor 2024 — MINIMIS](https://minimis.imm.gov.ro/fa2024/ordine_evaluare) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Ordinea finală la evaluare Femeia Antreprenor 2024 — MINIMIS](https://minimis.imm.gov.ro/fa2024/ordine_evaluare) |
| Latest official update | 2026-09-02 — [Femeia Antreprenor 2024 – ordinea finală la evaluare](https://minimis.imm.gov.ro/fa2024/ordine_evaluare) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Ordinea finală la evaluare Femeia Antreprenor 2024 — MINIMIS](https://minimis.imm.gov.ro/fa2024/ordine_evaluare) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Femeia Antreprenor 2024 – ordinea finală la evaluare](https://minimis.imm.gov.ro/fa2024/ordine_evaluare) (verificat 2026-11-03) |
| Chei surse repo | `femeia` |
| Notes | Ordinea finală la evaluare dovedește o etapă ulterioară depunerii, nu finalizarea integrală a programului. |

## `digitalizare-imm` — Digitalizarea IMM-urilor

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `digitalizare-imm` |
| Denumire oficială | Digitalizarea IMM-urilor |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene |
| Fond / program | Planul Național de Redresare și Reziliență |
| Temei / document | Ordinul MIPE nr. 607/28.04.2026; modifică Ghidul aprobat prin Ordinul nr. 3185/2022 — [document oficial](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/) |
| Stadiu | CLOSED — Apel închis – depunerea nu este deschisă |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Pagina este un hub; o finanțare actuală trebuie identificată și verificată separat. |
| Documente | [Pagina MIPE pentru Ordinul nr. 607/28.04.2026](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/)<br>[Ordinul MIPE nr. 607/28.04.2026 (PDF oficial)](https://mfe.gov.ro/wp-content/uploads/2026/04/c764c30d879b42963929b965d0c50bb0.pdf) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Pagina MIPE pentru Ordinul nr. 607/28.04.2026](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/)<br>[Ordinul MIPE nr. 607/28.04.2026 (PDF oficial)](https://mfe.gov.ro/wp-content/uploads/2026/04/c764c30d879b42963929b965d0c50bb0.pdf) |
| Latest official update | 2026-07-22 — [Ordinul MIPE nr. 607/28.04.2026; modifică Ghidul aprobat prin Ordinul nr. 3185/2022](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Pagina MIPE pentru Ordinul nr. 607/28.04.2026](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul Digitalizarea IMM-urilor, modificat prin Ordinul nr. 607/2026](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/) (`guide:digitalizare`, verificat 2026-11-03) |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | [Ordinul MIPE nr. 607/28.04.2026 (PDF oficial)](https://mfe.gov.ro/wp-content/uploads/2026/04/c764c30d879b42963929b965d0c50bb0.pdf) (`approval:evidence:0`, verificat 2026-08-18) |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Ordinul MIPE nr. 607/28.04.2026; modifică Ghidul aprobat prin Ordinul nr. 3185/2022](https://mfe.gov.ro/pnrr-ordinul-nr-607-28-04-2026-pentru-modificarea-ghidului-solicitantului-digitalizarea-imm-urilor-grant-de-pana-la-100-000-euro-pe-intreprindere-care-sa-sprijine-imm-urile-in-adoptarea-tehnologii/) (verificat 2026-11-03) |
| Chei surse repo | `digitalizare`, `digitalizare-pnrr` |
| Notes | Apel închis. Modificarea ghidului nu constituie dovadă pentru o sesiune nouă ori redeschisă. |

## `modernizare-microintreprinderi-ne-2` — Investiții pentru modernizarea microîntreprinderilor – Apel 2

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `modernizare-microintreprinderi-ne-2` |
| Denumire oficială | Investiții pentru modernizarea microîntreprinderilor – Apel 2 |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Autoritatea de Management pentru Programul Regional Nord-Est |
| Fond / program | Programul Regional Nord-Est 2021–2027 |
| Temei / document | Ghidul final și anexele publicate la 27.08.2026; cod apel PR/NE/2026/P1/RSO1.3/2/1 — [document oficial](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) |
| Stadiu | CLOSED — Apel închis – sesiunea 28 septembrie–28 octombrie 2026 |
| Sesiune | [Anunțul oficial: depuneri 28.09.2026–28.10.2026](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) (`program`, verificat 2026-11-03) |
| Data deschiderii | 28.09.2026 |
| Deadline | 28.10.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 20.370.738,4 EUR |
| Grant minim | 100.000 EUR / proiect |
| Grant maxim | 300.000 EUR / proiect |
| Intensitate | rate: 90; scope: maximum din cheltuielile eligibile |
| Cofinanțare | Minimum 10% din cheltuielile eligibile, plus toate cheltuielile neeligibile; o contribuție eligibilă mai mare este punctată. |
| Beneficiari | Microîntreprinderi constituite ca societăți, cu investiții în Regiunea Nord-Est, care îndeplinesc condițiile ghidului final. |
| Regiune | Regiunea Nord-Est |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Investiția se realizează în județele Bacău, Botoșani, Iași, Neamț, Suceava sau Vaslui, în mediul urban ori rural.; Solicitantul respectă definiția microîntreprinderii: maximum 9 salariați și cifră de afaceri anuală netă sau active totale de maximum 2 milioane EUR, inclusiv după agregarea întreprinderilor partenere și legate.; Solicitantul a desfășurat activitate cel puțin un an fiscal integral, a fost înființat cel târziu la 03.01.2025, nu a avut activitatea suspendată în 2025 sau 2026 și a avut profit din exploatare pozitiv în 2025.; Numărul mediu de salariați în 2025 este de minimum 1, conform bazei de date ANAF.; Cel puțin un cod CAEN Rev. 3 vizat este inclus în Anexa 5, iar achiziția de mijloace fixe corporale este obligatorie.; Finanțarea nerambursabilă este de 100.000–300.000 EUR, contribuția proprie eligibilă este de minimum 10%, iar plafonul de minimis al întreprinderii unice trebuie respectat.; Cheltuielile indirecte sunt eligibile în limita unei rate forfetare de maximum 7% din costurile directe eligibile.; Grila punctează contribuția proprie până la pragul de 30% și rata profitabilității până la pragul de 6%, conform formulelor din Anexa 10.; Proiectul trebuie să obțină minimum 70 de puncte și să nu primească 0 la subcriteriile eliminatorii prevăzute de grilă. |
| Documente | [Pagina oficială ADR Nord-Est pentru Apelul 2](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Pagina oficială ADR Nord-Est pentru Apelul 2](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) |
| Latest official update | 2026-11-03 — [Ghidul final și anexele publicate la 27.08.2026; cod apel PR/NE/2026/P1/RSO1.3/2/1](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Pagina oficială ADR Nord-Est pentru Apelul 2](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul final și anexele Apelului 2, publicate la 27.08.2026](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) (`guide:por-ne-apel-2`, verificat 2026-11-03) |
| Anexe | [Anexele finale, inclusiv lista CAEN și grila de evaluare](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) (`guide:por-ne-apel-2`, verificat 2026-11-03) |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | [Anunțul oficial: depuneri 28.09.2026–28.10.2026](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) (`program`, verificat 2026-11-03) |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Ghidul final și anexele publicate la 27.08.2026; cod apel PR/NE/2026/P1/RSO1.3/2/1](https://regionordest.ro/prioritatea-1/modernizare-microintreprinderi/) (verificat 2026-11-03) |
| Chei surse repo | `por-ne-apel-2`, `por-ne` |
| Notes | Sesiunea s-a încheiat la 28 octombrie 2026. Informațiile rămân utile pentru evaluare și pregătirea documentelor; o eventuală relansare necesită anunț oficial. |

## `fondul-modernizare-autoconsum` — Fondul pentru Modernizare – energie și autoconsum

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `fondul-modernizare-autoconsum` |
| Denumire oficială | Fondul pentru Modernizare – energie și autoconsum |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | MySMIS2021: apelurile pentru capacități regenerabile destinate autoconsumului sunt marcate FINALIZAT — [document oficial](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Stadiu | COMPLETED — Apeluri finalizate în MySMIS – depunerea nu este deschisă |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Apelul, consumul, capacitatea, amplasamentul și racordarea trebuie verificate în documentația activă. |
| Documente | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Latest official update | 2026-08-18 — [MySMIS2021: apelurile pentru capacități regenerabile destinate autoconsumului sunt marcate FINALIZAT](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [MySMIS2021: apelurile pentru capacități regenerabile destinate autoconsumului sunt marcate FINALIZAT](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (verificat 2026-11-03) |
| Chei surse repo | `fondul-modernizare` |
| Notes | Apelurile înregistrate sunt marcate FINALIZAT în MySMIS; documentația fiecărei ediții nu este separată în catalogul local de surse. |

## `fondul-modernizare-regenerabile` — Fondul pentru Modernizare – energie regenerabilă

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `fondul-modernizare-regenerabile` |
| Denumire oficială | Fondul pentru Modernizare – energie regenerabilă |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | MySMIS2021: apelurile pentru noi capacități din surse regenerabile sunt marcate FINALIZAT — [document oficial](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Stadiu | COMPLETED — Apeluri finalizate în MySMIS – depunerea nu este deschisă |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Sursa regenerabilă, capacitatea, racordarea, amplasamentul și ajutorul de stat se verifică în apelul concret. |
| Documente | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Latest official update | 2026-08-18 — [MySMIS2021: apelurile pentru noi capacități din surse regenerabile sunt marcate FINALIZAT](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [MySMIS2021: apelurile pentru noi capacități din surse regenerabile sunt marcate FINALIZAT](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (verificat 2026-11-03) |
| Chei surse repo | `fondul-modernizare-regenerabile`, `fondul-modernizare` |
| Notes | Apelurile înregistrate sunt marcate FINALIZAT în MySMIS; documentația fiecărei ediții nu este separată în catalogul local de surse. |

## `afir-energie-autoconsum` — Schema de ajutor privind sprijinirea investițiilor în noi capacități de producere a energiei electrice din surse regenerabile pentru autoconsumul întreprinderilor din agricultură și industria alimentară

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `afir-energie-autoconsum` |
| Denumire oficială | Schema de ajutor privind sprijinirea investițiilor în noi capacități de producere a energiei electrice din surse regenerabile pentru autoconsumul întreprinderilor din agricultură și industria alimentară |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Agriculturii și Dezvoltării Rurale / AFIR |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Comunicarea AFIR din 09.06.2026 privind sesiunea 15.06–14.08.2026 — [document oficial](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/) |
| Stadiu | CLOSED — Apel închis – sesiunea s-a încheiat la 14 august 2026 |
| Sesiune | [Anunțul oficial AFIR pentru sesiunea 15.06.2026–14.08.2026](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/) (`registry:afir-energy-session-2026`, verificat 2026-08-23) |
| Data deschiderii | 15.06.2026 |
| Deadline | 14.08.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 265.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 20.000.000 EUR / beneficiar |
| Intensitate | rate: 100; scope: costuri eligibile în limitele costului unitar |
| Cofinanțare | Diferențele peste costurile unitare și cheltuielile neeligibile. |
| Beneficiari | Întreprinderi din agricultură; Întreprinderi din industria alimentară; OUAI și FOUAI în condițiile ghidului |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Minimum 70% autoconsum, conform Ghidului V7.; 650.000 EUR/MW până la 1 MW inclusiv și 550.000 EUR/MW peste 1 MW, conform Ghidului V7.; Prefinanțarea poate reprezenta maximum 30% din ajutorul solicitat, cu garanție de 100% din prefinanțare, conform Ghidului V7. |
| Documente | [Pagina oficială Schema de Energie](https://www.afir.ro/finantare/finantare-in-agricultura/schema-de-energie/)<br>[Ghidul solicitantului Schema Energie Autoconsum V7](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/)<br>[Anunțul oficial AFIR pentru sesiunea 15.06.2026–14.08.2026](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/)<br>[Clarificarea AFIR din 29.07.2026 privind documentele cadastrale](https://www.afir.ro/comunicate/masuri-afir-pentru-atenuarea-efectelor-provocate-de-indisponibilitatea-sistemului-ancpi-completare/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Pagina oficială Schema de Energie](https://www.afir.ro/finantare/finantare-in-agricultura/schema-de-energie/)<br>[Ghidul solicitantului Schema Energie Autoconsum V7](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/)<br>[Anunțul oficial AFIR pentru sesiunea 15.06.2026–14.08.2026](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/)<br>[Clarificarea AFIR din 29.07.2026 privind documentele cadastrale](https://www.afir.ro/comunicate/masuri-afir-pentru-atenuarea-efectelor-provocate-de-indisponibilitatea-sistemului-ancpi-completare/) |
| Latest official update | 2026-07-29 — [Clarificarea AFIR pentru sesiunea Schema de Energie 2026](https://www.afir.ro/comunicate/masuri-afir-pentru-atenuarea-efectelor-provocate-de-indisponibilitatea-sistemului-ancpi-completare/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Pagina oficială Schema de Energie](https://www.afir.ro/finantare/finantare-in-agricultura/schema-de-energie/) (`registry:afir-energy-program`, verificat 2026-08-23) |
| Ghid | [Ghidul solicitantului Schema Energie Autoconsum V7](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/) (`registry:afir-energy-guide-annexes`, verificat 2026-08-23) |
| Anexe | [Anexele Schemei de Energie pentru sesiunea 2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/) (`registry:afir-energy-guide-annexes`, verificat 2026-08-23) |
| Schemă / ordin | [Ghidul aprobat prin OMADR nr. 180/09.06.2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-schema-energie/) (`registry:afir-energy-guide-annexes`, verificat 2026-08-23) |
| Anunț sesiune | [Anunțul oficial AFIR pentru sesiunea 15.06.2026–14.08.2026](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/) (`registry:afir-energy-session-2026`, verificat 2026-08-23) |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | [Clarificarea AFIR din 29.07.2026 privind documentele cadastrale](https://www.afir.ro/comunicate/masuri-afir-pentru-atenuarea-efectelor-provocate-de-indisponibilitatea-sistemului-ancpi-completare/) (`registry:afir-energy-clarification-2026`, verificat 2026-08-22) |
| Sursă primară în registry-ul operațional | [Comunicarea AFIR din 09.06.2026 privind sesiunea 15.06–14.08.2026](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/) (verificat 2026-11-03) |
| Chei surse repo | `afir-autoconsum`, `afir-autoconsum-session-2026` |
| Notes | Fereastra de depunere este închisă; închiderea sesiunii nu este echivalată cu finalizarea întregii proceduri. Comunicarea oficială stabilă din 09.06.2026 și clarificarea din 29.07.2026 confirmă termenul de 14.08.2026; nu a fost identificată o prelungire oficială la reverificarea din 23.08.2026. |

## `autoconsum-institutii-publice` — Sprijinirea investițiilor în noi capacități de producere și stocare a energiei solare pentru autoconsum – entități publice

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `autoconsum-institutii-publice` |
| Denumire oficială | Sprijinirea investițiilor în noi capacități de producere și stocare a energiei solare pentru autoconsum – entități publice |
| Acronim | PC1 |
| Autoritate | Ministerul Energiei / AFIR |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Ghidul solicitantului și anexele publicate de AFIR la 11.09.2026 — [document oficial](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-producere-si-stocare-energie-regenerabila-beneficiari-publici/) |
| Stadiu | OPEN — Sesiune deschisă – depuneri până la 20 noiembrie 2026 |
| Sesiune | [Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-autoconsum_entitati-publice.pdf) (`registry:me-pc1-autoconsum-launch-2026`, verificat 2026-09-13)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) (`registry:afir-public-energy-active-2026`, verificat 2026-11-03) |
| Data deschiderii | 28.09.2026 |
| Deadline | 20.11.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 500.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 10.000.000 EUR / beneficiar |
| Intensitate | rate: 100; scope: maximum din cheltuielile eligibile, în limita plafoanelor pe MW instalat |
| Cofinanțare | Cheltuielile neeligibile, TVA deductibilă și orice depășire a plafoanelor din ghid rămân în sarcina beneficiarului. |
| Beneficiari | Unități administrativ-teritoriale și subdiviziunile acestora; Unități din apărare, ordine publică, siguranță națională și administrația penitenciară; Spitale și centre sociale ori de îngrijiri paliative finanțate integral din fonduri publice; Instituții publice, culte recunoscute, universități de stat, institute publice de cercetare și asociații de dezvoltare intercomunitară, în condițiile ghidului |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Proiectul include obligatoriu o capacitate nouă solară și stocare integrată; proiectele numai cu baterii sau numai cu pompe de căldură nu sunt eligibile.; Energia produsă este destinată 100% autoconsumului, iar energia stocată provine 100% din instalația solară proprie.; Sistemul de stocare asigură o durată de 2–4 ore și o putere nominală cel puțin egală cu puterea centralei fotovoltaice.; Costul eligibil este plafonat la 900.000 EUR/MW fără pompe de căldură și la 1.100.000 EUR/MW pentru proiectele care includ pompe de căldură eligibile.; Investiția trebuie finalizată și pusă în funcțiune până la 31.12.2029.; Selecție în ordinea depunerii: primul venit, primul evaluat, cu respectarea condițiilor ghidului și în limita bugetului. |
| Documente | [AFIR: pagina apelului și anexele oficiale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-producere-si-stocare-energie-regenerabila-beneficiari-publici/)<br>[Ghidul solicitantului PC1 Autoconsum entități publice — DOCX oficial AFIR](https://www.afir.ro/media/uwymsxzy/ghidul-solicitantului_autoconsum-res_fm_entitati-publice.docx)<br>[Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-autoconsum_entitati-publice.pdf)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [AFIR: pagina apelului și anexele oficiale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-producere-si-stocare-energie-regenerabila-beneficiari-publici/)<br>[Ghidul solicitantului PC1 Autoconsum entități publice — DOCX oficial AFIR](https://www.afir.ro/media/uwymsxzy/ghidul-solicitantului_autoconsum-res_fm_entitati-publice.docx)<br>[Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-autoconsum_entitati-publice.pdf)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) |
| Latest official update | 2026-09-11 — [Ghidul solicitantului și anexele publicate de AFIR la 11.09.2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-producere-si-stocare-energie-regenerabila-beneficiari-publici/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [AFIR: pagina apelului și anexele oficiale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-producere-si-stocare-energie-regenerabila-beneficiari-publici/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul solicitantului PC1 Autoconsum entități publice — DOCX oficial AFIR](https://www.afir.ro/media/uwymsxzy/ghidul-solicitantului_autoconsum-res_fm_entitati-publice.docx) (`registry:afir-autoconsum-publici-guide`, verificat 2026-09-13) |
| Anexe | [AFIR: cererea de finanțare, grila VAE, declarația DNSH și modelul de parteneriat](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-producere-si-stocare-energie-regenerabila-beneficiari-publici/) (`program`, verificat 2026-11-03) |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | [Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-autoconsum_entitati-publice.pdf) (`registry:me-pc1-autoconsum-launch-2026`, verificat 2026-09-13)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) (`registry:afir-public-energy-active-2026`, verificat 2026-11-03) |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Ghidul solicitantului și anexele publicate de AFIR la 11.09.2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-producere-si-stocare-energie-regenerabila-beneficiari-publici/) (verificat 2026-11-03) |
| Chei surse repo | `autoconsum-publici` |
| Notes | Depunere prin AFIR până la 20 noiembrie 2026, ora 23:59, sau până la epuizarea bugetului. Verifică disponibilul în platformă înainte de transmitere. |

## `fondul-modernizare-pc1-stocare-entitati-publice` — Sprijinirea investițiilor în noi capacități de stocare a energiei regenerabile – entități publice

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `fondul-modernizare-pc1-stocare-entitati-publice` |
| Denumire oficială | Sprijinirea investițiilor în noi capacități de stocare a energiei regenerabile – entități publice |
| Acronim | PC1 |
| Autoritate | Ministerul Energiei / AFIR |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Ghidul solicitantului și anexele publicate de AFIR la 11.09.2026 — [document oficial](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-stocare-energie-regenerabila-beneficiari-publici/) |
| Stadiu | OPEN — Sesiune deschisă – depuneri până la 20 noiembrie 2026 |
| Sesiune | [Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-stocare_entitati-publice.pdf) (`registry:me-pc1-stocare-launch-2026`, verificat 2026-09-13)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) (`registry:afir-public-energy-active-2026`, verificat 2026-11-03) |
| Data deschiderii | 28.09.2026 |
| Deadline | 20.11.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 150.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 10.000.000 EUR / beneficiar |
| Intensitate | rate: 100; scope: maximum din cheltuielile eligibile, conform ghidului |
| Cofinanțare | Cheltuielile neeligibile, TVA deductibilă și orice depășire a plafonului rămân în sarcina beneficiarului. |
| Beneficiari | Unități administrativ-teritoriale și subdiviziunile acestora; Unități din apărare, ordine publică, siguranță națională și administrația penitenciară; Spitale și centre sociale ori de îngrijiri paliative finanțate integral din fonduri publice; Instituții publice, culte recunoscute, universități de stat, institute publice de cercetare și asociații de dezvoltare intercomunitară, în condițiile ghidului |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Capacitatea nouă de stocare se amplasează în spatele contorului și se conectează direct la o instalație regenerabilă existentă.; Este eligibilă o singură cerere de finanțare per solicitant.; Durata echivalentă a stocării trebuie să fie între 2 și 4 ore, raportată la puterea instalată a centralei existente.; Ajutorul solicitat nu poate depăși 200.000 EUR/MWh instalat, fără TVA.; Investiția trebuie finalizată și pusă în funcțiune până la 31.12.2029.; Selecție în ordinea depunerii: primul venit, primul evaluat, cu respectarea condițiilor ghidului și în limita bugetului. |
| Documente | [AFIR: pagina apelului și anexele oficiale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-stocare-energie-regenerabila-beneficiari-publici/)<br>[Ghidul solicitantului PC1 Stocare entități publice — DOCX oficial AFIR](https://www.afir.ro/media/yo1h41gu/ghidul-solicitantului_stocare_res_fm_publici.docx)<br>[Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-stocare_entitati-publice.pdf)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [AFIR: pagina apelului și anexele oficiale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-stocare-energie-regenerabila-beneficiari-publici/)<br>[Ghidul solicitantului PC1 Stocare entități publice — DOCX oficial AFIR](https://www.afir.ro/media/yo1h41gu/ghidul-solicitantului_stocare_res_fm_publici.docx)<br>[Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-stocare_entitati-publice.pdf)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) |
| Latest official update | 2026-09-11 — [Ghidul solicitantului și anexele publicate de AFIR la 11.09.2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-stocare-energie-regenerabila-beneficiari-publici/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [AFIR: pagina apelului și anexele oficiale](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-stocare-energie-regenerabila-beneficiari-publici/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul solicitantului PC1 Stocare entități publice — DOCX oficial AFIR](https://www.afir.ro/media/yo1h41gu/ghidul-solicitantului_stocare_res_fm_publici.docx) (`registry:afir-fm-pc1-stocare-publici-guide`, verificat 2026-09-13) |
| Anexe | [AFIR: cererea de finanțare, grila VAE, declarația DNSH și modelul de parteneriat](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-stocare-energie-regenerabila-beneficiari-publici/) (`program`, verificat 2026-11-03) |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | [Anunț oficial: calendarul complet 28.09–20.11.2026](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-stocare_entitati-publice.pdf) (`registry:me-pc1-stocare-launch-2026`, verificat 2026-09-13)<br>[AFIR: depunerea proiectelor de energie pentru beneficiari publici este în curs](https://www.afir.ro/comunicate/depunere-in-curs-a-proiectelor-in-energie-a-entitatilor-publice/) (`registry:afir-public-energy-active-2026`, verificat 2026-11-03) |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Ghidul solicitantului și anexele publicate de AFIR la 11.09.2026](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-stocare-energie-regenerabila-beneficiari-publici/) (verificat 2026-11-03) |
| Chei surse repo | `fm-pc1-stocare-publici` |
| Notes | Depunere prin AFIR până la 20 noiembrie 2026, ora 23:59, sau până la epuizarea bugetului. Verifică disponibilul în platformă înainte de transmitere. |

## `pro-infra` — Schema de ajutor de stat PRO INFRA

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `pro-infra` |
| Denumire oficială | Schema de ajutor de stat PRO INFRA |
| Acronim | PRO INFRA |
| Autoritate | Ministerul Transporturilor și Infrastructurii |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Schema PRO INFRA consolidată, art. 5, 13 și 16, cu modificările Ordinului nr. 101/12.02.2026 — [document oficial](https://legislatie.just.ro/Public/DetaliiDocument/306916) |
| Stadiu | APPROVED_SCHEME — Schemă aprobată și modificată – depunerea nu este deschisă |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 100.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 15.000.000 EUR / beneficiar |
| Intensitate | rate: 100; scope: maximum din cheltuielile eligibile, prin ofertare concurențială |
| Cofinanțare | Diferența neacoperită de oferta de ajutor, costurile neeligibile și eventualele depășiri de buget. |
| Beneficiari | Întreprinderi din categoriile eligibile ale schemei care produc pentru infrastructura de transport și înlocuiesc instalații, utilaje sau echipamente cu alternative eficiente energetic în România. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Bugetul schemei este 100 milioane EUR; plafonul ajutorului este 15 milioane EUR/beneficiar.; Maximum 100% din cheltuielile eligibile prin procedură competitivă; procentul maxim nu garantează finanțarea.; EMS integrat, cu excepția justificată documentar conform art. 5 alin. (2); auditul energetic rămâne necesar. |
| Documente | [Schema PRO INFRA în Portalul Legislativ](https://legislatie.just.ro/Public/DetaliiDocument/306916) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Schema PRO INFRA în Portalul Legislativ](https://legislatie.just.ro/Public/DetaliiDocument/306916) |
| Latest official update | 2026-02-12 — [Schema PRO INFRA consolidată, art. 5, 13 și 16, cu modificările Ordinului nr. 101/12.02.2026](https://legislatie.just.ro/Public/DetaliiDocument/306916) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Schema PRO INFRA în Portalul Legislativ](https://legislatie.just.ro/Public/DetaliiDocument/306916) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | [Ordinul MTI nr. 2.292/29.12.2025 și schema PRO INFRA](https://legislatie.just.ro/Public/DetaliiDocument/306916) (`guide:pro-infra-order`, verificat 2026-11-03) |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Schema PRO INFRA consolidată, art. 5, 13 și 16, cu modificările Ordinului nr. 101/12.02.2026](https://legislatie.just.ro/Public/DetaliiDocument/306916) (verificat 2026-11-03) |
| Chei surse repo | `pro-infra`, `pro-infra-order` |
| Notes | Schema este aprobată și modificată prin Ordinul nr. 101/12.02.2026; nu este înregistrat un interval efectiv de depunere. Reverificarea nu a identificat în sursa legislativă dovada afirmației anterioare «în revizuire». |

## `apeluri-gal` — Apeluri locale LEADER prin Grupuri de Acțiune Locală

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `apeluri-gal` |
| Denumire oficială | Apeluri locale LEADER prin Grupuri de Acțiune Locală |
| Acronim | GAL / LEADER |
| Autoritate | Platforma oficială AFIR pentru Grupurile de Acțiune Locală |
| Fond / program | Planul Strategic PAC 2023–2027 / FEADR |
| Temei / document | Platforma AFIR GAL publică apeluri locale cu termene distincte; verificat la 29.08.2026 — [document oficial](https://gal.afir.ro/) |
| Stadiu | UNCONFIRMED — Apeluri locale active – statutul și termenul se verifică pentru fiecare GAL |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Beneficiarii definiți de fișa intervenției și ghidul GAL selectat |
| Regiune | local gal |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | GAL-ul, teritoriul, fișa intervenției, criteriile și calendarul se verifică local. |
| Documente | [Platforma oficială AFIR GAL](https://gal.afir.ro/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Platforma oficială AFIR GAL](https://gal.afir.ro/) |
| Latest official update | 2026-08-18 — [Platforma AFIR GAL publică apeluri locale cu termene distincte; verificat la 29.08.2026](https://gal.afir.ro/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Platforma oficială AFIR GAL](https://gal.afir.ro/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidurile și anexele DR-36/LEADER, prin platforma AFIR GAL](https://gal.afir.ro/) (`guide:dr36-leader`, verificat 2026-11-03) |
| Anexe | [Anexele DR-36/LEADER, prin platforma AFIR GAL](https://gal.afir.ro/) (`guide:dr36-leader`, verificat 2026-11-03) |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Platforma AFIR GAL publică apeluri locale cu termene distincte; verificat la 29.08.2026](https://gal.afir.ro/) (verificat 2026-11-03) |
| Chei surse repo | `dr36-leader`, `leader-gal` |
| Notes | Fiecare GAL are sesiuni distincte. La verificarea live din 22.08.2026, pagina agregată afișa 0 anunțuri și 0 apeluri în derulare; starea paginii rămâne UNCONFIRMED, nu OPEN. |

## `gal-afir-leader` — GAL AFIR / DR-36 prin Grupuri de Acțiune Locală

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `gal-afir-leader` |
| Denumire oficială | GAL AFIR / DR-36 prin Grupuri de Acțiune Locală |
| Acronim | LEADER / DR-36 |
| Autoritate | Platforma oficială AFIR pentru Grupurile de Acțiune Locală |
| Fond / program | Planul Strategic PAC 2023–2027 / FEADR |
| Temei / document | Platforma AFIR GAL publică apeluri locale cu termene distincte; verificat la 29.08.2026 — [document oficial](https://gal.afir.ro/) |
| Stadiu | UNCONFIRMED — Apelurile și termenele se verifică separat pentru fiecare GAL |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Beneficiari publici și privați definiți de intervenția și ghidul GAL |
| Regiune | local gal |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Condițiile financiare și calendarul aparțin apelului local, nu paginii-cadru AFIR. |
| Documente | [Platforma oficială AFIR GAL](https://gal.afir.ro/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Platforma oficială AFIR GAL](https://gal.afir.ro/) |
| Latest official update | 2026-09-02 — [Platforma AFIR GAL publică apeluri locale cu termene distincte; verificat la 29.08.2026](https://gal.afir.ro/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Platforma oficială AFIR GAL](https://gal.afir.ro/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidurile și anexele DR-36/LEADER, prin platforma AFIR GAL](https://gal.afir.ro/) (`guide:dr36-leader`, verificat 2026-11-03) |
| Anexe | [Anexele DR-36/LEADER, prin platforma AFIR GAL](https://gal.afir.ro/) (`guide:dr36-leader`, verificat 2026-11-03) |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Platforma AFIR GAL publică apeluri locale cu termene distincte; verificat la 29.08.2026](https://gal.afir.ro/) (verificat 2026-11-03) |
| Chei surse repo | `leader-gal`, `dr36-leader` |
| Notes | Fiecare GAL are sesiuni distincte. La verificarea live din 22.08.2026, pagina agregată afișa 0 anunțuri și 0 apeluri în derulare; starea paginii rămâne UNCONFIRMED, nu OPEN. |

## `e-move-ro` — Programul e-MOVE RO

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `e-move-ro` |
| Denumire oficială | Programul e-MOVE RO |
| Acronim | e-MOVE RO |
| Autoritate | Ministerul Transporturilor și Infrastructurii / Portal Legislativ |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Ordinul MTI nr. 755/06.08.2026 pentru actualizarea schemei e-MOVE RO, în vigoare din 10.08.2026 — [document oficial](https://legislatie.just.ro/Public/DetaliiDocument/313320) |
| Stadiu | APPROVED_SCHEME — Schemă actualizată – depunerea nu este deschisă |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 25.000.000 EUR / beneficiar |
| Intensitate | rate: 100; scope: maximum, în condițiile schemei actualizate și ale procedurii competitive |
| Cofinanțare | Diferența față de ajutorul aplicabil și cheltuielile neeligibile. |
| Beneficiari | Solicitanții definiți de schema e-MOVE RO actualizată |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Amplasamentul, racordarea, avizele și configurația tehnică trebuie documentate. |
| Documente | [Schema e-MOVE RO în Portalul Legislativ](https://legislatie.just.ro/Public/DetaliiDocument/313320) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Schema e-MOVE RO în Portalul Legislativ](https://legislatie.just.ro/Public/DetaliiDocument/313320) |
| Latest official update | 2026-08-10 — [Ordinul MTI nr. 755/06.08.2026 pentru actualizarea schemei e-MOVE RO, în vigoare din 10.08.2026](https://legislatie.just.ro/Public/DetaliiDocument/313320) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Schema e-MOVE RO în Portalul Legislativ](https://legislatie.just.ro/Public/DetaliiDocument/313320) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul e-MOVE RO publicat spre consultare, referit de sursa oficială](https://legislatie.just.ro/Public/DetaliiDocument/313320) (`guide:emove`, verificat 2026-11-03) |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | [Ordinul MTI nr. 755/06.08.2026 pentru actualizarea schemei e-MOVE RO](https://legislatie.just.ro/Public/DetaliiDocument/313320) (`guide:emove`, verificat 2026-11-03) |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Ordinul MTI nr. 755/06.08.2026 pentru actualizarea schemei e-MOVE RO, în vigoare din 10.08.2026](https://legislatie.just.ro/Public/DetaliiDocument/313320) (verificat 2026-11-03) |
| Chei surse repo | `emove` |
| Notes | Schema actualizată și ghidul consultativ nu dovedesc deschiderea unei sesiuni. |

## `pocidif-21` — PoCIDIF – Acțiunea 2.1 Dezvoltarea de noi servicii, aplicații și produse prin inovare și adoptarea de tehnologii avansate

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `pocidif-21` |
| Denumire oficială | PoCIDIF – Acțiunea 2.1 Dezvoltarea de noi servicii, aplicații și produse prin inovare și adoptarea de tehnologii avansate |
| Acronim | PoCIDIF 2.1 |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene |
| Fond / program | Programul Creștere Inteligentă, Digitalizare și Instrumente Financiare 2021–2027 |
| Temei / document | Ghidul solicitantului PoCIDIF 2.1 aprobat prin Ordinul MIPE nr. 965/23.06.2026 — [document oficial](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) |
| Stadiu | CLOSED — Apel închis – depuneri încheiate la 30 octombrie 2026 |
| Sesiune | [Pagina MIPE: apel închis la 30.10.2026](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (`program`, verificat 2026-11-03) |
| Data deschiderii | 30.06.2026 |
| Deadline | 30.10.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | 200.000 EUR / proiect |
| Grant maxim | currency: EUR; variants: 1.500.000; 3.000.000 |
| Intensitate | rate: 75; scope: ajutor regional, în funcție de categorie și regiune; rate: 100; scope: ajutor de minimis pentru cheltuielile încadrate |
| Cofinanțare | Depinde de tipul ajutorului, dimensiunea întreprinderii, regiune și cheltuielile neeligibile. |
| Beneficiari | IMM din sectorul TIC care îndeplinesc condițiile ghidului aprobat |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Activitățile CDI, introducerea în producție și introducerea pe piață trebuie corelate cu produsul inovator.; Activitatea de bază concentrează minimum 80% din finanțarea nerambursabilă, iar activitatea tehnică realizată de personalul propriu minimum 20% din finanțarea activității de bază. |
| Documente | [Pagina oficială MIPE pentru Acțiunea PoCIDIF 2.1](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Pagina oficială MIPE pentru Acțiunea PoCIDIF 2.1](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) |
| Latest official update | 2026-11-03 — [Ghidul solicitantului PoCIDIF 2.1 aprobat prin Ordinul MIPE nr. 965/23.06.2026](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Pagina oficială MIPE pentru Acțiunea PoCIDIF 2.1](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul solicitantului aprobat prin Ordinul MIPE nr. 965/23.06.2026](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (`guide:pocidif-21-guide`, verificat 2026-11-03) |
| Anexe | [Pachetul oficial de 19 anexe](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (`guide:pocidif-21-guide`, verificat 2026-11-03) |
| Schemă / ordin | [Schema de ajutor aprobată prin Ordinul MIPE nr. 875/15.06.2026](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (`guide:pocidif-21-scheme`, verificat 2026-11-03) |
| Anunț sesiune | [Pagina MIPE: apel închis la 30.10.2026](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (`program`, verificat 2026-11-03) |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | [Clarificări oficiale publicate la 09.07.2026](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (`guide:pocidif-21-qa`, verificat 2026-11-03) |
| Sursă primară în registry-ul operațional | [Ghidul solicitantului PoCIDIF 2.1 aprobat prin Ordinul MIPE nr. 965/23.06.2026](https://mfe.gov.ro/ghiduri_pocidif/pocidif-ghidul-solicitantului-dezvoltarea-de-noi-servicii-aplicatii-produse-prin-inovare-si-adoptarea-de-tehnologii-avansate-2/) (verificat 2026-11-03) |
| Chei surse repo | `pocidif-21`, `pocidif-21-guide`, `pocidif-21-scheme`, `pocidif-21-qa` |
| Notes | Pagina oficială MIPE marchează apelul închis, cu data de închidere 30 octombrie 2026. Se consultă și modificările ghidului publicate după lansare. |

## `pnrr` — Planul Național de Redresare și Reziliență

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `pnrr` |
| Denumire oficială | Planul Național de Redresare și Reziliență |
| Acronim | PNRR |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene – tabloul de bord PNRR |
| Fond / program | Mecanismul de redresare și reziliență |
| Temei / document | Tabloul de bord oficial PNRR; program în implementare, cu situație distinctă pe componente și apeluri — [document oficial](https://mfe.gov.ro/pnrr-dashboard/) |
| Stadiu | UNCONFIRMED — Program în implementare – statutul se verifică pentru fiecare componentă și apel |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Documente | [Tabloul de bord oficial PNRR](https://mfe.gov.ro/pnrr-dashboard/) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Tabloul de bord oficial PNRR](https://mfe.gov.ro/pnrr-dashboard/) |
| Latest official update | 2026-09-10 — [Tabloul de bord oficial PNRR; program în implementare, cu situație distinctă pe componente și apeluri](https://mfe.gov.ro/pnrr-dashboard/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Tabloul de bord oficial PNRR](https://mfe.gov.ro/pnrr-dashboard/) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Tabloul de bord oficial PNRR; program în implementare, cu situație distinctă pe componente și apeluri](https://mfe.gov.ro/pnrr-dashboard/) (verificat 2026-11-03) |
| Chei surse repo | `pnrr-dashboard` |
| Notes | Pagină agregată. Implementarea PNRR nu implică o sesiune de depunere deschisă pentru toate componentele. |

## `diaspora-investeste-acasa` — Diaspora Investește Acasă

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `diaspora-investeste-acasa` |
| Denumire oficială | Diaspora Investește Acasă |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Banca de Investiții și Dezvoltare (BID) |
| Fond / program | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Temei / document | Condițiile programului și stadiul operaționalizării publicate de BID, verificate la 06.09.2026 — [document oficial](https://www.bidromania.eu/produse/garantii/diaspora-investeste-acasa) |
| Stadiu | APPROVED_SCHEME — Program aprobat – în curs de operaționalizare la BID |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 100.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 200.000 EUR / întreprindere |
| Intensitate | rate: 60; scope: maximum din creditul de investiții, în limita grantului de 200.000 EUR, conform BID |
| Cofinanțare | 10% pentru proiecte de până la 400.000 EUR; 5% dacă cel puțin un asociat majoritar eligibil are sub 35 de ani; 15% pentru proiecte de peste 400.000 EUR. |
| Beneficiari | Microîntreprinderi și IMM-uri înființate de mai puțin de trei ani, cu majoritatea capitalului deținută de cetățeni români care îndeplinesc condiția de domiciliu/reședință în străinătate. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Domiciliu sau reședință în străinătate pentru minimum 12 luni din ultimele 18 luni anterioare cererii de credit.; Minimum nouă luni de experiență, pregătire sau studii relevante, inclusiv în management, pentru asociații majoritari și/sau administratori.; Investiția și participația eligibilă se păstrează minimum trei ani, cu excepțiile prevăzute de program.; Grantul reduce soldul creditului după realizarea investiției și verificarea condițiilor; nu este un avans independent. |
| Documente | [Comunicarea oficială «Investește Acasă»](https://www.bidromania.eu/produse/garantii/diaspora-investeste-acasa) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Comunicarea oficială «Investește Acasă»](https://www.bidromania.eu/produse/garantii/diaspora-investeste-acasa) |
| Latest official update | 2026-09-06 — [Condițiile programului și stadiul operaționalizării publicate de BID, verificate la 06.09.2026](https://www.bidromania.eu/produse/garantii/diaspora-investeste-acasa) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Comunicarea oficială «Investește Acasă»](https://www.bidromania.eu/produse/garantii/diaspora-investeste-acasa) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Condițiile programului și stadiul operaționalizării publicate de BID, verificate la 06.09.2026](https://www.bidromania.eu/produse/garantii/diaspora-investeste-acasa) (verificat 2026-11-03) |
| Chei surse repo | `diaspora-investeste-acasa` |
| Notes | Program aprobat, în curs de operaționalizare la BID; lista băncilor partenere urmează să fie publicată. |

## `e-drive` — Programul e-DRIVE

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `e-drive` |
| Denumire oficială | Programul e-DRIVE |
| Acronim | e-DRIVE |
| Autoritate | Ministerul Transporturilor și Infrastructurii – DGPET |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Ghidurile solicitantului e-DRIVE Măsura 1 și Măsura 2, versiuni în consultare publică publicate la 03.11.2026; observații până la 18.11.2026 — [document oficial](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/fm-mti-demareaza-procesul-de-consultare-publica-pentru-ghidurile-solicitantului-aferente-masurilor-1-si-2-ale-schemei-e-drive) |
| Stadiu | PUBLIC_CONSULTATION — Ghiduri în consultare până la 18 noiembrie 2026 – depunerea nu este deschisă |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 56.900.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 4.000.000 EUR / beneficiar, în cadrul măsurii competitive |
| Intensitate | rate: 100; scope: Măsura 1: cost de achiziție fără TVA, în plafoane; Măsura 2: numai diferența de cost eligibilă, prin selecție concurențială |
| Cofinanțare | Diferența până la prețul total, TVA și cheltuielile neeligibile; plafonul de minimis disponibil se verifică pentru întreprinderea unică. |
| Beneficiari | Măsura 1: microîntreprinderi, întreprinderi mici și mijlocii. Măsura 2: operatori de transport rutier de pasageri, inclusiv întreprinderi mari, CAEN Rev. 3 4931, 4932 și 4933. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Ghidurile sunt în consultare publică în perioada 03.11–18.11.2026; aceasta nu reprezintă lansarea apelurilor.; Măsura 1: M1 și M2 noi exclusiv electrice; maximum 30.000 EUR/M1 și 130.000 EUR/M2, în limita a 300.000 EUR pe întreprindere unică în orice perioadă de trei ani.; Măsura 2: M1, M2 și M3 pentru transportatori de pasageri; maximum 4 milioane EUR pe întreprindere și 30.000 EUR/M1; cost eligibil egal cu diferența față de alternativa convențională comparabilă.; Casarea vehiculului înlocuit se documentează în maximum 60 de zile de la recepția vehiculului electric.; TVA, informarea, publicitatea și auditul financiar nu sunt eligibile. Leasingul și vehiculele second-hand sunt excluse.; Ghidurile prevăd implementare de maximum 30 de luni de la depunere, fără depășirea datei de 30.06.2030, și durabilitate de cinci ani.; Buget total 56,9 milioane EUR: 15 milioane EUR pentru Măsura 1 și 41,9 milioane EUR pentru Măsura 2.; Măsura 2: până la 100% din diferența de cost eligibilă; criteriul kilometrajului utilizează pragurile 40% și 70%, iar prefinanțarea propusă este de până la 40%, cu garantare.; Conversia propusă de ghiduri utilizează cursul InforEuro din iunie 2026, 5,2481 lei/EUR. |
| Documente | [Anunțul MTI de consultare a ghidurilor e-DRIVE](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/fm-mti-demareaza-procesul-de-consultare-publica-pentru-ghidurile-solicitantului-aferente-masurilor-1-si-2-ale-schemei-e-drive)<br>[Ghidurile Măsurilor 1 și 2 – versiuni consultative](https://fonduri.mt.ro/documente/GS_M1_%C8%99i_M2.zip)<br>[Ordinul MTI nr. 742/2026 – actualizarea schemei e-DRIVE](https://legislatie.just.ro/Public/DetaliiDocument/313289) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Anunțul MTI de consultare a ghidurilor e-DRIVE](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/fm-mti-demareaza-procesul-de-consultare-publica-pentru-ghidurile-solicitantului-aferente-masurilor-1-si-2-ale-schemei-e-drive)<br>[Ghidurile Măsurilor 1 și 2 – versiuni consultative](https://fonduri.mt.ro/documente/GS_M1_%C8%99i_M2.zip)<br>[Ordinul MTI nr. 742/2026 – actualizarea schemei e-DRIVE](https://legislatie.just.ro/Public/DetaliiDocument/313289) |
| Latest official update | 2026-11-03 — [Ghidurile solicitantului e-DRIVE Măsura 1 și Măsura 2, versiuni în consultare publică publicate la 03.11.2026; observații până la 18.11.2026](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/fm-mti-demareaza-procesul-de-consultare-publica-pentru-ghidurile-solicitantului-aferente-masurilor-1-si-2-ale-schemei-e-drive) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Anunțul MTI de consultare a ghidurilor e-DRIVE](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/fm-mti-demareaza-procesul-de-consultare-publica-pentru-ghidurile-solicitantului-aferente-masurilor-1-si-2-ale-schemei-e-drive) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidurile Măsurilor 1 și 2 – versiuni consultative](https://fonduri.mt.ro/documente/GS_M1_%C8%99i_M2.zip) (`registry:edrive-draft-guides-20261103`, verificat 2026-11-03) |
| Anexe | [Anexele celor două ghiduri, inclusiv grilele de selecție și modelele de contract](https://fonduri.mt.ro/documente/GS_M1_%C8%99i_M2.zip) (`registry:edrive-draft-guides-20261103`, verificat 2026-11-03) |
| Schemă / ordin | [Ordinul MTI nr. 742/2026 – actualizarea schemei e-DRIVE](https://legislatie.just.ro/Public/DetaliiDocument/313289) (`registry:edrive-scheme-742-2026`, verificat 2026-11-03) |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Ghidurile solicitantului e-DRIVE Măsura 1 și Măsura 2, versiuni în consultare publică publicate la 03.11.2026; observații până la 18.11.2026](https://fonduri.mt.ro/transparenta/consultare-publica/fondul-pentru-modernizare/fm-mti-demareaza-procesul-de-consultare-publica-pentru-ghidurile-solicitantului-aferente-masurilor-1-si-2-ale-schemei-e-drive) (verificat 2026-11-03) |
| Chei surse repo | `e-drive` |
| Notes | Consultarea ghidurilor nu este sesiune de finanțare. Anunțul MTI precizează că data depunerilor va fi comunicată ulterior aprobării. |

## `e-mobility-ro` — Programul e-Mobility RO

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `e-mobility-ro` |
| Denumire oficială | Programul e-Mobility RO |
| Acronim | e-Mobility RO |
| Autoritate | Ministerul Transporturilor și Infrastructurii – DGPET |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Anunț MTI 26.09.2026: Ghidul Submăsurii 1 aprobat prin OMTI nr. 886/2026 și calendarul apelului prin OMTI nr. 904/2026 — [document oficial](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1) |
| Stadiu | OPEN — Submăsura 1 deschisă – depuneri până la 27 noiembrie 2026 |
| Sesiune | [MTI: depuneri 28 septembrie–27 noiembrie 2026](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1) (`program`, verificat 2026-11-03) |
| Data deschiderii | 28.09.2026 |
| Deadline | 27.11.2026 |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | 49.500.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 30.000.000 EUR / beneficiar |
| Intensitate | rate: 100; scope: maximum posibil prin procedura competitivă, în condițiile schemei |
| Cofinanțare | Diferența rezultată din oferta competitivă, costurile neeligibile și eventualele depășiri ale limitelor aplicabile. |
| Beneficiari | Microîntreprinderi, întreprinderi mici, mijlocii și mari eligibile; schema exclude întreprinderile nou-înființate. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Submăsura 1: depuneri 28.09–27.11.2026; bugetul apelului este 49,5 milioane EUR, distinct de bugetul total de 299 milioane EUR al schemei.; Infrastructura trebuie amplasată pe autostrăzi, drumuri expres ori drumuri naționale sau în proximitatea admisă a unei ieșiri TEN-T.; Proiectul poate include infrastructură de reîncărcare și, în condițiile schemei, producție regenerabilă și stocare asociată.; Un beneficiar nu poate primi mai mult de 40% din bugetul total al schemei.; Plafon de 30 milioane EUR/beneficiar; limita suplimentară de 40% din buget nu înlocuiește acest plafon.; Amplasament pe drumurile eligibile ori la cel mult 3 km pe șosea de cea mai apropiată ieșire TEN-T.; Stocarea absoarbe anual cel puțin 75% din energia produsă de instalațiile regenerabile conectate direct, conform condițiilor schemei. |
| Documente | [MTI: ghidul și calendarul Submăsurii 1](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1)<br>[Ghidul aprobat al Submăsurii 1 și anexele](https://fonduri.mt.ro/documente/FIN_Ghid_e-Mobility-submasura1_%202026.zip)<br>[Schema e-Mobility RO, actualizată prin OMTI 746/2026](https://legislatie.just.ro/Public/DetaliiDocument/313291) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [MTI: ghidul și calendarul Submăsurii 1](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1)<br>[Ghidul aprobat al Submăsurii 1 și anexele](https://fonduri.mt.ro/documente/FIN_Ghid_e-Mobility-submasura1_%202026.zip)<br>[Schema e-Mobility RO, actualizată prin OMTI 746/2026](https://legislatie.just.ro/Public/DetaliiDocument/313291) |
| Latest official update | 2026-11-03 — [Anunț MTI 26.09.2026: Ghidul Submăsurii 1 aprobat prin OMTI nr. 886/2026 și calendarul apelului prin OMTI nr. 904/2026](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [MTI: ghidul și calendarul Submăsurii 1](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul aprobat al Submăsurii 1 și anexele](https://fonduri.mt.ro/documente/FIN_Ghid_e-Mobility-submasura1_%202026.zip) (`registry:emobility-sm1-guide-2026`, verificat 2026-11-03) |
| Anexe | [Anexele ghidului Submăsurii 1](https://fonduri.mt.ro/documente/FIN_Ghid_e-Mobility-submasura1_%202026.zip) (`registry:emobility-sm1-guide-2026`, verificat 2026-11-03) |
| Schemă / ordin | [Schema e-Mobility RO, actualizată prin OMTI 746/2026](https://legislatie.just.ro/Public/DetaliiDocument/313291) (`registry:emobility-scheme-2026`, verificat 2026-11-03) |
| Anunț sesiune | [MTI: depuneri 28 septembrie–27 noiembrie 2026](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1) (`program`, verificat 2026-11-03) |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Anunț MTI 26.09.2026: Ghidul Submăsurii 1 aprobat prin OMTI nr. 886/2026 și calendarul apelului prin OMTI nr. 904/2026](https://fonduri.mt.ro/transparenta/comunicate-de-presa/fondul-pentru-modernizare/publicarea-ghidului-solicitantului-si-calendarului-apelului-de-proiecte-pentru-dezvoltarea-infrastructurii-de-reincarcare-a-vehiculelor-electrice-pe-reteaua-nationala-de-autostrazi-drumuri-expres-si-drumuri-nationale-e-mobility-ro-submasura-1) (verificat 2026-11-03) |
| Chei surse repo | `e-mobility-ro` |
| Notes | Calendarul 28.09.2026, ora 12:00–27.11.2026, ora 23:59 privește Submăsura 1. Nu se extinde automat asupra altor submăsuri. Se verifică modificările MTI înainte de depunere. |

## `fondul-modernizare-pc1-stocare` — Fondul pentru Modernizare – PC1 Stocare stand-alone

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `fondul-modernizare-pc1-stocare` |
| Denumire oficială | Fondul pentru Modernizare – PC1 Stocare stand-alone |
| Acronim | PC1 |
| Autoritate | Ministerul Energiei |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Anunț de lansare 14.08.2026 și prelungire 22.10.2026: depuneri 01.09–15.11.2026; ghid aprobat prin OME nr. 915/2026 — [document oficial](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/) |
| Stadiu | OPEN — Sesiune prelungită – depuneri până la 15 noiembrie 2026 |
| Sesiune | [Anunțul oficial de lansare: 01.09–30.10.2026](https://energie.gov.ro/wp-content/uploads/2026/08/Anunt-lansare-apel-proiecte-STOCARE-STAND-ALONE_final.pdf) (`registry:pc1-storage-launch-2026`, verificat 2026-11-03) |
| Data deschiderii | 01.09.2026 |
| Deadline | 15.11.2026 |
| Prelungiri | originalEnd: 2026-10-30; extendedEnd: 2026-11-15; sourceRef: registry:pc1-storage-extension-2026; verifiedAt: 2026-11-03 |
| Buget | 150.000.000 EUR |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | 15.000.000 EUR / întreprindere |
| Intensitate | rate: 100; scope: maximum conform ghidului aprobat, în limita costului eligibil și a competiției |
| Cofinanțare | Costurile neeligibile, depășirile plafonului și diferența rezultată din regulile finale ori din procedura competitivă. |
| Beneficiari | Microîntreprinderi, IMM-uri și întreprinderi mari, inclusiv întreprinderi nou-înființate, în condițiile ghidului aprobat |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Investiția vizează capacități de stocare stand-alone racordate la rețea.; Solicitantul și activitatea trebuie să respecte domeniul energetic și condițiile formei finale a ghidului.; Ghidul aprobat prevede un plafon al ajutorului de 69.000 EUR/MWh.; Depuneri 01.09–15.11.2026; termen prelungit prin anunțul ME din 22.10.2026.; Putere minimă 1 MW și raport capacitate/putere minimum 2:1; implementare de maximum 48 de luni de la semnarea contractului.; Solicitanții au activități din diviziunea CAEN 35; firmele nou-înființate au capital social subscris și vărsat de minimum 100.000 lei. |
| Documente | [Ministerul Energiei: lansare, documentație și prelungire](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/)<br>[Anunțul oficial de lansare: 01.09–30.10.2026](https://energie.gov.ro/wp-content/uploads/2026/08/Anunt-lansare-apel-proiecte-STOCARE-STAND-ALONE_final.pdf)<br>[Prelungirea depunerii până la 15 noiembrie 2026](https://energie.gov.ro/wp-content/uploads/2026/10/Anunt-prelungire-apel-proiecte-STOCARE-STAND-ALONE.docx) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Ministerul Energiei: lansare, documentație și prelungire](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/)<br>[Anunțul oficial de lansare: 01.09–30.10.2026](https://energie.gov.ro/wp-content/uploads/2026/08/Anunt-lansare-apel-proiecte-STOCARE-STAND-ALONE_final.pdf)<br>[Prelungirea depunerii până la 15 noiembrie 2026](https://energie.gov.ro/wp-content/uploads/2026/10/Anunt-prelungire-apel-proiecte-STOCARE-STAND-ALONE.docx) |
| Latest official update | 2026-10-22 — [Anunț de lansare 14.08.2026 și prelungire 22.10.2026: depuneri 01.09–15.11.2026; ghid aprobat prin OME nr. 915/2026](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Ministerul Energiei: lansare, documentație și prelungire](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/) (`program`, verificat 2026-11-03) |
| Ghid | [Ghidul solicitantului PC1 Stocare stand-alone, publicat la 17.08.2026](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/) (`guide:fm-pc1-stocare`, verificat 2026-11-03) |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | [Ordinul Ministerului Energiei nr. 915/14.08.2026, publicat la 17.08.2026](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/) (`guide:fm-pc1-stocare`, verificat 2026-11-03) |
| Anunț sesiune | [Anunțul oficial de lansare: 01.09–30.10.2026](https://energie.gov.ro/wp-content/uploads/2026/08/Anunt-lansare-apel-proiecte-STOCARE-STAND-ALONE_final.pdf) (`registry:pc1-storage-launch-2026`, verificat 2026-11-03) |
| Corrigenda / erate | [Prelungirea depunerii până la 15 noiembrie 2026](https://energie.gov.ro/wp-content/uploads/2026/10/Anunt-prelungire-apel-proiecte-STOCARE-STAND-ALONE.docx) (`registry:pc1-storage-extension-2026`, verificat 2026-11-03) |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Anunț de lansare 14.08.2026 și prelungire 22.10.2026: depuneri 01.09–15.11.2026; ghid aprobat prin OME nr. 915/2026](https://energie.gov.ro/lansare-apel-sprijinirea-investitiilor-in-dezvoltarea-instalatiilor-autonome-stand-alone-de-stocare-in-baterii-a-energiei-electrice-cu-finantare-din-fondul-pentru-modernizare-p/) (verificat 2026-11-03) |
| Chei surse repo | `fm-pc1-stocare` |
| Notes | Depunere în MySMIS 2021 între 1 septembrie 2026, ora 12:00, și 15 noiembrie 2026, ora 23:59, conform prelungirii publicate la 22 octombrie. |

## `programul-tranzitie-justa` — Programul Tranziție Justă

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `programul-tranzitie-justa` |
| Denumire oficială | Programul Tranziție Justă |
| Acronim | PTJ |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 |
| Fond / program | Fondul pentru o Tranziție Justă |
| Temei / document | Catalogul oficial al finanțărilor 2021–2027; apelurile sunt afișate în cadrul Programului Dezvoltare Durabilă și Tranziție Justă (fost PTJ), cu statut distinct pentru fiecare apel — [document oficial](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Stadiu | UNCONFIRMED — Program în implementare – statutul se verifică pentru fiecare apel în MySMIS |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | regional |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Documente | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027)<br>[Fondul pentru o Tranziție Justă – Comisia Europeană](https://commission.europa.eu/funding-and-tenders/find-funding/eu-funding-programmes/just-transition-fund_en)<br>[Programul Național de Reformă 2023 – teritoriile eligibile](https://commission.europa.eu/system/files/2023-05/ROMANIA%20NRP%202023%20RO.pdf) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027)<br>[Fondul pentru o Tranziție Justă – Comisia Europeană](https://commission.europa.eu/funding-and-tenders/find-funding/eu-funding-programmes/just-transition-fund_en)<br>[Programul Național de Reformă 2023 – teritoriile eligibile](https://commission.europa.eu/system/files/2023-05/ROMANIA%20NRP%202023%20RO.pdf) |
| Latest official update | 2026-09-10 — [Catalogul oficial al finanțărilor 2021–2027; apelurile sunt afișate în cadrul Programului Dezvoltare Durabilă și Tranziție Justă (fost PTJ), cu statut distinct pentru fiecare apel](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (`program`, verificat 2026-11-03) |
| Ghid | [Fondul pentru o Tranziție Justă – Comisia Europeană](https://commission.europa.eu/funding-and-tenders/find-funding/eu-funding-programmes/just-transition-fund_en) (`guide:ptj-comisia-europeana`, verificat 2026-09-10)<br>[Programul Național de Reformă 2023 – teritoriile eligibile](https://commission.europa.eu/system/files/2023-05/ROMANIA%20NRP%202023%20RO.pdf) (`guide:ptj-romania-pnr-2023`, verificat 2026-09-10) |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Catalogul oficial al finanțărilor 2021–2027; apelurile sunt afișate în cadrul Programului Dezvoltare Durabilă și Tranziție Justă (fost PTJ), cu statut distinct pentru fiecare apel](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (verificat 2026-11-03) |
| Chei surse repo | `ptj-mysmis`, `ptj-comisia-europeana`, `ptj-romania-pnr-2023` |
| Notes | Pagină agregată. Starea se stabilește separat pentru fiecare apel al programului. |

## `fondul-de-modernizare` — Fondul pentru Modernizare

| Câmp | Valoare auditabilă |
|---|---|
| Stable program ID | `fondul-de-modernizare` |
| Denumire oficială | Fondul pentru Modernizare |
| Acronim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Autoritate | Ministerul Investițiilor și Proiectelor Europene – MySMIS2021 |
| Fond / program | Fondul pentru Modernizare |
| Temei / document | Catalogul oficial al finanțărilor 2021–2027; Fondul pentru Modernizare are statut distinct pentru fiecare apel — [document oficial](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Stadiu | UNCONFIRMED — Program în implementare – statutul se verifică pentru fiecare apel în MySMIS |
| Sesiune | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Data deschiderii | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Deadline | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prelungiri | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Buget | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant minim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Grant maxim | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Intensitate | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cofinanțare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Beneficiari | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Regiune | Național |
| CAEN | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Prag SO | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Investiții | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli eligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Cheltuieli neeligibile | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Condiții critice | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Documente | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Indicatori | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Selecție / punctaj | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Ajutor de stat / de minimis | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Implementare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Monitorizare | Documentația oficială publicată și verificată la 03.11.2026 nu stabilește încă această informație. |
| Surse oficiale | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| Latest official update | 2026-09-10 — [Catalogul oficial al finanțărilor 2021–2027; Fondul pentru Modernizare are statut distinct pentru fiecare apel](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) |
| verifiedAt | 2026-11-03 |
| Pagină oficială program/apel | [Catalogul oficial MySMIS2021](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (`program`, verificat 2026-11-03) |
| Ghid | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anexe | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Schemă / ordin | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Anunț sesiune | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Corrigenda / erate | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Clarificări | — Neidentificat separat în sursele oficiale înregistrate la 2026-11-03; nu se presupune inexistența documentului. |
| Sursă primară în registry-ul operațional | [Catalogul oficial al finanțărilor 2021–2027; Fondul pentru Modernizare are statut distinct pentru fiecare apel](https://resurse.mysmis2021.gov.ro/ords/repo_bo/r/mysmis-2021/finantari-programe-2021-2027) (verificat 2026-11-03) |
| Chei surse repo | `fondul-modernizare-mysmis` |
| Notes | Pagină agregată. Starea se stabilește separat pentru fiecare apel al Fondului pentru Modernizare. |

## Jurnalul schimbărilor factuale din reverificare

| Program | Câmp | Before | After | Sursă | Verificat | Motiv |
|---|---|---|---|---|---|---|
| `afir-energie-autoconsum` | sourceUrl / sourceVersion / notes | URL-ul principal returna 404; versiunea indică un anunț din 15.06.2026 și amâna migrarea. | Comunicarea AFIR stabilă din 09.06.2026 este sursa principală; sesiunea 15.06–14.08.2026 este CLOSED, fără prelungire oficială identificată. | [Comunicarea AFIR din 09.06.2026](https://www.afir.ro/comunicate/265-de-milioane-de-euro-pentru-investitii-in-producerea-energiei-electrice/) | 2026-08-23 | Înlocuirea unui URL oficial 404 și reconcilierea statusului după deadline cu comunicarea și clarificarea oficială. |
| `pro-infra` | statusRationale / statusLabel / sourceVersion / lastMeaningfulUpdate / copy | Schemă aprobată, în revizuire; era invocat un proces de revizuire din martie 2026. | Schemă aprobată prin Ordinul nr. 2.292/29.12.2025 și modificată prin Ordinul nr. 101/12.02.2026; ultima actualizare oficială înregistrată este 12.02.2026; depunerea nu este deschisă. | [Forma consolidată a schemei PRO INFRA](https://legislatie.just.ro/Public/DetaliiDocument/306915) | 2026-08-23 | Sursa legislativă confirmă modificarea din februarie, dar nu susține formularea publică anterioară «în revizuire». |
| `e-mobility-ro` | grantSummary.maximum | Necompletat. | 30.000.000 EUR / beneficiar. | [Schema e-Mobility RO actualizată prin Ordinul MTI nr. 746/05.08.2026](https://legislatie.just.ro/Public/DetaliiDocument/313291) | 2026-08-23 | Forma actualizată stabilește plafonul individual, distinct de limita de 40% din bugetul total. |
| `fondul-modernizare-pc1-stocare` | statusLabel / sourceVersion / document labels | Ordinul nr. 915/17.08.2026. | Ordinul nr. 915/14.08.2026, publicat la 17.08.2026. | [Ordinul Ministerului Energiei nr. 915/14.08.2026](https://legislatie.just.ro/Public/DetaliiDocument/313464) | 2026-08-23 | Separarea datei emiterii actului de data publicării în Monitorul Oficial. |

## Goluri cunoscute și regulă de completare

Multe pagini-umbrelă și câteva ediții istorice au în prezent doar un catalog oficial sau o pagină de stare, fără URL-uri distincte pentru toate rolurile documentare. Aceste goluri sunt vizibile în fiecare fișă. Completarea lor cere un document oficial verificat, adăugat mai întâi în `official-guides.json`, în catalogul suplimentar sau în registrul de aprobări și apoi referit din `config/seo-programs.json`; nu se folosesc agregatoare ori alte firme de consultanță drept source-of-truth.
