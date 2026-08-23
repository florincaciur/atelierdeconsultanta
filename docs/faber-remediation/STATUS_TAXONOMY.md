# Taxonomia unică de status FABER

Revizie semantică: **2026-08-23**. Definiții canonice: `config/program-status-taxonomy.json`; atribuiri per program: `config/seo-programs.json#programs[*].canonicalStatus`. Acest document este generat de `tools/generate-status-governance-docs.js` și nu este o pagină publică.

## Contractul mecanismului

Starea canonică descrie un program, apel, ediție sau sesiune la granularitatea declarată. Ea este separată de publicare/indexare: o pagină `CLOSED` sau `COMPLETED` poate rămâne indexabilă dacă are valoare evergreen, iar o pagină `UNCONFIRMED` nu capătă certitudine doar pentru că este publicată.

Reguli invariabile:

1. `acceptsApplications=true` există exclusiv pentru `OPEN`.
2. `APPROVED_SCHEME` și `FINAL_GUIDE` nu sunt sinonime cu `OPEN`.
3. `SCHEDULED` cere o fereastră oficială viitoare; data de început nu promovează automat starea la `OPEN` fără reverificarea sesiunii.
4. `OPEN` cere dovadă oficială de sesiune, interval curent și verificarea unei eventuale suspendări, închideri anticipate, prelungiri ori corrigenda.
5. După deadline, `OPEN` este interzis. Se folosește `CLOSED` când închiderea este dovedită sau `UNCONFIRMED` când nu pot fi excluse actualizări oficiale.
6. Starea unui apel punctual nu se propagă asupra unei pagini-umbrelă cu apeluri multiple.
7. O tranziție este acceptată numai cu o dovadă nouă, versionată în registrul oficial; trecerea timpului este un semnal de reverificare, nu singura dovadă.

Fluxul de evaluare este: identificarea granularității → verificarea emitentului și documentului → clasificarea tipului de dovadă → evaluarea ferestrei calendaristice → controlul corrigenda/clarificărilor → emiterea statusului și label-ului public. În caz de conflict sau lipsă, rezultatul este `UNCONFIRMED`.

## Mapare status tehnic → label public

| Status tehnic | Depunere | Label public recomandat | Definiție scurtă |
|---|---|---|---|
| `ANNOUNCED` | nu | Program anunțat — depunerea nu este deschisă | Instituția competentă a anunțat oficial intenția, programul sau viitorul apel, dar documentația operațională și fereastra de depunere nu sunt încă publicate complet. |
| `PREPARATION` | nu | În pregătire — depunerea nu este deschisă | Autoritatea a confirmat că mecanismul sau documentația este în pregătire, fără o consultare publică activă, ghid final ori sesiune deschisă dovedită. |
| `PUBLIC_CONSULTATION` | nu | În consultare publică — depunerea nu este deschisă | Autoritatea primește oficial observații asupra unui proiect de document într-o perioadă de consultare încă activă; trimiterea observațiilor nu este depunere de proiect. |
| `CONSULTATIVE_GUIDE` | nu | Ghid consultativ publicat — depunerea nu este deschisă | Există un ghid explicit consultativ sau draft; perioada de consultare poate fi activă ori închisă, însă condițiile nu sunt finale. |
| `FINAL_GUIDE` | nu | Ghid final publicat — depunerea nu este deschisă | Ghidul final a fost aprobat ori publicat oficial, dar nu există încă dovadă suficientă că o sesiune de depunere este deschisă. |
| `APPROVED_SCHEME` | nu | Schemă aprobată — depunerea nu este deschisă | Schema de ajutor, ordinul sau cadrul juridic a fost aprobat, fără ca aprobarea să constituie singură dovadă de deschidere a unei sesiuni. |
| `SCHEDULED` | nu | Apel programat — depuneri între {startDate} și {endDate} | Autoritatea a confirmat oficial o fereastră viitoare de depunere, iar data curentă este anterioară începerii; simpla trecere a timpului nu promovează automat starea la OPEN. |
| `OPEN` | da | Apel deschis — depuneri până la {endDate} | Sesiunea acceptă depuneri la data curentă, conform unei dovezi oficiale aplicabile și unei ferestre confirmate neexpirate. |
| `CLOSED` | nu | Apel închis — depunerea nu este deschisă | Fereastra de depunere s-a încheiat ori sesiunea a fost închisă; evaluarea, contractarea sau implementarea pot continua. |
| `SUSPENDED` | nu | Apel suspendat — depunerea nu este disponibilă | Autoritatea a suspendat oficial și temporar sesiunea sau procedura; depunerea nu este permisă până la o reluare expresă. |
| `CANCELLED` | nu | Apel anulat — depunerea nu este deschisă | Autoritatea a anulat oficial apelul, sesiunea sau procedura identificată; o relansare ulterioară este tratată ca proces nou. |
| `COMPLETED` | nu | Apel finalizat — depunerea nu este deschisă | Autoritatea marchează procedura ori apelul ca finalizat sau există dovadă oficială că etapele relevante s-au încheiat; această stare este mai puternică decât simpla închidere a depunerii. |
| `UNCONFIRMED` | nu | Status neconfirmat — verifică sursa oficială | Dovada este insuficientă, contradictorie, expirată sau are o granularitate diferită de pagina evaluată; platforma nu afirmă un stadiu cert până la reverificare. |

Placeholder-ele `{startDate}` și `{endDate}` se înlocuiesc numai cu date absolute confirmate; formatul recomandat public este `ZZ.LL.AAAA`. Label-ul poate adăuga identificatorul apelului, dar nu poate schimba sensul stării.

## Definiții, dovezi și tranziții

### `ANNOUNCED`

**Definiție:** Instituția competentă a anunțat oficial intenția, programul sau viitorul apel, dar documentația operațională și fereastra de depunere nu sunt încă publicate complet.

**Dovadă minimă necesară:**

- comunicat, program de lucru sau anunț publicat de autoritatea competentă
- identificarea fără echivoc a programului ori a apelului anunțat

**Depunere posibilă:** Nu.

**Label public recomandat:** „Program anunțat — depunerea nu este deschisă”

**Wording public interzis:** „apel deschis”; „finanțare disponibilă acum”; „poți depune”; „deadline confirmat”.

**Exemple de tranziții valide:** `ANNOUNCED → PREPARATION`, `ANNOUNCED → PUBLIC_CONSULTATION`, `ANNOUNCED → CONSULTATIVE_GUIDE`, `ANNOUNCED → CANCELLED`, `ANNOUNCED → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `PREPARATION`

**Definiție:** Autoritatea a confirmat că mecanismul sau documentația este în pregătire, fără o consultare publică activă, ghid final ori sesiune deschisă dovedită.

**Dovadă minimă necesară:**

- calendar, program de lucru sau comunicare oficială care indică pregătirea
- absența unei dovezi mai noi pentru consultare, programare sau deschidere

**Depunere posibilă:** Nu.

**Label public recomandat:** „În pregătire — depunerea nu este deschisă”

**Wording public interzis:** „apel deschis”; „ghid final”; „schema garantează finanțarea”; „data lansării este certă”.

**Exemple de tranziții valide:** `PREPARATION → PUBLIC_CONSULTATION`, `PREPARATION → CONSULTATIVE_GUIDE`, `PREPARATION → FINAL_GUIDE`, `PREPARATION → CANCELLED`, `PREPARATION → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `PUBLIC_CONSULTATION`

**Definiție:** Autoritatea primește oficial observații asupra unui proiect de document într-o perioadă de consultare încă activă; trimiterea observațiilor nu este depunere de proiect.

**Dovadă minimă necesară:**

- pagină oficială de consultare publică
- document supus consultării și interval de consultare care include data curentă

**Depunere posibilă:** Nu.

**Label public recomandat:** „În consultare publică — depunerea nu este deschisă”

**Wording public interzis:** „apel deschis”; „depuneri deschise”; „condiții finale”; „ghid aprobat”.

**Exemple de tranziții valide:** `PUBLIC_CONSULTATION → CONSULTATIVE_GUIDE`, `PUBLIC_CONSULTATION → FINAL_GUIDE`, `PUBLIC_CONSULTATION → PREPARATION`, `PUBLIC_CONSULTATION → CANCELLED`, `PUBLIC_CONSULTATION → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `CONSULTATIVE_GUIDE`

**Definiție:** Există un ghid explicit consultativ sau draft; perioada de consultare poate fi activă ori închisă, însă condițiile nu sunt finale.

**Dovadă minimă necesară:**

- ghid oficial marcat consultativ, draft sau publicat pentru observații
- versiunea și data documentului

**Depunere posibilă:** Nu.

**Label public recomandat:** „Ghid consultativ publicat — depunerea nu este deschisă”

**Wording public interzis:** „ghid final”; „condiții definitive”; „apel deschis”; „eligibilitate garantată”.

**Exemple de tranziții valide:** `CONSULTATIVE_GUIDE → PUBLIC_CONSULTATION`, `CONSULTATIVE_GUIDE → FINAL_GUIDE`, `CONSULTATIVE_GUIDE → PREPARATION`, `CONSULTATIVE_GUIDE → CANCELLED`, `CONSULTATIVE_GUIDE → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `FINAL_GUIDE`

**Definiție:** Ghidul final a fost aprobat ori publicat oficial, dar nu există încă dovadă suficientă că o sesiune de depunere este deschisă.

**Dovadă minimă necesară:**

- ghid final oficial și actul de aprobare, dacă există
- versiunea și data aplicabile
- verificare separată a lipsei unei sesiuni deschise

**Depunere posibilă:** Nu.

**Label public recomandat:** „Ghid final publicat — depunerea nu este deschisă”

**Wording public interzis:** „apel deschis”; „poți depune acum”; „schema este deschisă”; „depuneri active”.

**Exemple de tranziții valide:** `FINAL_GUIDE → APPROVED_SCHEME`, `FINAL_GUIDE → SCHEDULED`, `FINAL_GUIDE → OPEN`, `FINAL_GUIDE → SUSPENDED`, `FINAL_GUIDE → CANCELLED`, `FINAL_GUIDE → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `APPROVED_SCHEME`

**Definiție:** Schema de ajutor, ordinul sau cadrul juridic a fost aprobat, fără ca aprobarea să constituie singură dovadă de deschidere a unei sesiuni.

**Dovadă minimă necesară:**

- act normativ, ordin sau schemă publicată de emitent ori în Portalul Legislativ/Monitorul Oficial
- numărul, data și versiunea actului aplicabil
- verificare separată a lipsei unei sesiuni deschise

**Depunere posibilă:** Nu.

**Label public recomandat:** „Schemă aprobată — depunerea nu este deschisă”

**Wording public interzis:** „apel deschis”; „poți aplica acum”; „depuneri active”; „aprobarea schemei deschide automat apelul”.

**Exemple de tranziții valide:** `APPROVED_SCHEME → PUBLIC_CONSULTATION`, `APPROVED_SCHEME → FINAL_GUIDE`, `APPROVED_SCHEME → SCHEDULED`, `APPROVED_SCHEME → OPEN`, `APPROVED_SCHEME → SUSPENDED`, `APPROVED_SCHEME → CANCELLED`, `APPROVED_SCHEME → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `SCHEDULED`

**Definiție:** Autoritatea a confirmat oficial o fereastră viitoare de depunere, iar data curentă este anterioară începerii; simpla trecere a timpului nu promovează automat starea la OPEN.

**Dovadă minimă necesară:**

- anunț oficial de sesiune sau pagină oficială echivalentă
- dată de început viitoare și dată de sfârșit confirmate
- identificarea apelului și a autorității

**Depunere posibilă:** Nu.

**Label public recomandat:** „Apel programat — depuneri între {startDate} și {endDate}”

**Wording public interzis:** „apel deschis”; „depuneri active”; „poți depune acum”; „calendar estimativ”.

**Exemple de tranziții valide:** `SCHEDULED → OPEN`, `SCHEDULED → SUSPENDED`, `SCHEDULED → CANCELLED`, `SCHEDULED → FINAL_GUIDE`, `SCHEDULED → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `OPEN`

**Definiție:** Sesiunea acceptă depuneri la data curentă, conform unei dovezi oficiale aplicabile și unei ferestre confirmate neexpirate.

**Dovadă minimă necesară:**

- anunț oficial de lansare, platformă oficială de depunere sau pagină oficială care confirmă sesiunea
- data curentă inclusă între începutul și sfârșitul oficial
- verificarea corrigenda, prelungirilor, suspendărilor și închiderilor anticipate

**Depunere posibilă:** Da, numai în fereastra oficială curentă.

**Label public recomandat:** „Apel deschis — depuneri până la {endDate}”

**Wording public interzis:** „termen nelimitat”; „finanțare garantată”; „prelungit fără corrigendă sau comunicat oficial”.

**Exemple de tranziții valide:** `OPEN → CLOSED`, `OPEN → SUSPENDED`, `OPEN → CANCELLED`, `OPEN → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `CLOSED`

**Definiție:** Fereastra de depunere s-a încheiat ori sesiunea a fost închisă; evaluarea, contractarea sau implementarea pot continua.

**Dovadă minimă necesară:**

- termen oficial depășit fără prelungire sau comunicare oficială de închidere
- verificarea eventualelor redeschideri și prelungiri

**Depunere posibilă:** Nu.

**Label public recomandat:** „Apel închis — depunerea nu este deschisă”

**Wording public interzis:** „apel deschis”; „poți depune”; „program finalizat”; „proiecte aprobate”.

**Exemple de tranziții valide:** `CLOSED → OPEN`, `CLOSED → COMPLETED`, `CLOSED → CANCELLED`, `CLOSED → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `SUSPENDED`

**Definiție:** Autoritatea a suspendat oficial și temporar sesiunea sau procedura; depunerea nu este permisă până la o reluare expresă.

**Dovadă minimă necesară:**

- comunicat, decizie sau mesaj al platformei oficiale care declară suspendarea
- data efectului și sfera suspendării

**Depunere posibilă:** Nu.

**Label public recomandat:** „Apel suspendat — depunerea nu este disponibilă”

**Wording public interzis:** „apel deschis”; „pauză tehnică neconfirmată”; „se va relua la {date} fără dovadă oficială”; „poți depune”.

**Exemple de tranziții valide:** `SUSPENDED → OPEN`, `SUSPENDED → CLOSED`, `SUSPENDED → CANCELLED`, `SUSPENDED → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `CANCELLED`

**Definiție:** Autoritatea a anulat oficial apelul, sesiunea sau procedura identificată; o relansare ulterioară este tratată ca proces nou.

**Dovadă minimă necesară:**

- act, decizie sau comunicat oficial de anulare
- identificarea exactă a apelului afectat și data anulării

**Depunere posibilă:** Nu.

**Label public recomandat:** „Apel anulat — depunerea nu este deschisă”

**Wording public interzis:** „apel închis”; „apel deschis”; „suspendat temporar”; „relansare sigură”.

**Exemple de tranziții valide:** `CANCELLED → ANNOUNCED`, `CANCELLED → PREPARATION`, `CANCELLED → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `COMPLETED`

**Definiție:** Autoritatea marchează procedura ori apelul ca finalizat sau există dovadă oficială că etapele relevante s-au încheiat; această stare este mai puternică decât simpla închidere a depunerii.

**Dovadă minimă necesară:**

- status oficial FINALIZAT/COMPLETED sau document oficial de finalizare
- identificarea exactă a apelului ori ediției finalizate

**Depunere posibilă:** Nu.

**Label public recomandat:** „Apel finalizat — depunerea nu este deschisă”

**Wording public interzis:** „apel deschis”; „poți depune”; „program desființat”; „o nouă ediție este sigură”.

**Exemple de tranziții valide:** `COMPLETED → ANNOUNCED`, `COMPLETED → PREPARATION`, `COMPLETED → SCHEDULED`, `COMPLETED → UNCONFIRMED`. Fiecare cere dovada specifică stării-destinație.

### `UNCONFIRMED`

**Definiție:** Dovada este insuficientă, contradictorie, expirată sau are o granularitate diferită de pagina evaluată; platforma nu afirmă un stadiu cert până la reverificare.

**Dovadă minimă necesară:**

- consemnarea surselor verificate și a informației lipsă ori contradictorii
- o nouă verificare în sursa primară înainte de atribuirea oricărei stări certe

**Depunere posibilă:** Nu.

**Label public recomandat:** „Status neconfirmat — verifică sursa oficială”

**Wording public interzis:** „apel deschis”; „apel închis cu certitudine”; „deadline confirmat”; „eligibilitate confirmată”.

**Exemple de tranziții valide:** `UNCONFIRMED → ANNOUNCED`, `UNCONFIRMED → PREPARATION`, `UNCONFIRMED → PUBLIC_CONSULTATION`, `UNCONFIRMED → CONSULTATIVE_GUIDE`, `UNCONFIRMED → FINAL_GUIDE`, `UNCONFIRMED → APPROVED_SCHEME`, `UNCONFIRMED → SCHEDULED`, `UNCONFIRMED → OPEN`, `UNCONFIRMED → CLOSED`, `UNCONFIRMED → SUSPENDED`, `UNCONFIRMED → CANCELLED`, `UNCONFIRMED → COMPLETED`. Fiecare cere dovada specifică stării-destinație.

## Compatibilitatea cu taxonomia legacy

Valorile de mai jos sunt citite încă de suprafețele publice existente. Ele nu sunt stări canonice și nu au mapare optimistă implicită. Normalizarea folosește atribuirea explicită din fiecare înregistrare de program până la migrarea controlată a consumatorilor.

| Status legacy | Stări canonice posibile | Regulă de normalizare |
|---|---|---|
| `calendar_estimativ` | `ANNOUNCED`, `PREPARATION`, `SCHEDULED`, `UNCONFIRMED` | Nu are mapare implicită la OPEN; se decide după granularitatea paginii și dovada oficială. |
| `consultare_publica` | `PUBLIC_CONSULTATION`, `CONSULTATIVE_GUIDE`, `UNCONFIRMED` | PUBLIC_CONSULTATION numai cât intervalul de consultare este activ; după închidere, un draft rămas public este CONSULTATIVE_GUIDE. |
| `ghid_aprobat_nedeschis` | `FINAL_GUIDE`, `APPROVED_SCHEME`, `SCHEDULED`, `UNCONFIRMED` | Tipul documentului și existența unei ferestre viitoare confirmate decid starea; nu se promovează la OPEN. |
| `apel_deschis` | `OPEN`, `UNCONFIRMED` | OPEN numai cu dovadă oficială de sesiune și fereastră curentă; o dovadă expirată sau contradictorie devine UNCONFIRMED. |
| `apel_inchis` | `CLOSED`, `COMPLETED`, `CANCELLED`, `UNCONFIRMED` | CLOSED descrie doar depunerea încheiată; COMPLETED și CANCELLED cer dovezi oficiale distincte. |
| `arhivat` | `CLOSED`, `COMPLETED`, `CANCELLED`, `UNCONFIRMED` | Arhivarea este o decizie editorială/indexare, nu un stadiu factual; pagina se clasifică după ultima dovadă oficială. |

## Maparea snapshot-ului curent

Maparea de mai jos folosește snapshot-ul factual verificat în registry la **2026-08-23**. Ea definește semantica, fără a rescrie încă toate paginile, bannerele sau artefactele materializate.

| Stable program ID | Status legacy | Status canonic | Label public recomandat | Scope | Motiv |
|---|---|---|---|---|---|
| `program-regional-nord-est` | `calendar_estimativ` | `UNCONFIRMED` | Status neconfirmat — verifică sursa oficială | umbrella_program | Apelurile au stări și calendare distincte; pagina agregată nu poate moșteni o singură stare de apel. |
| `fonduri-regionale` | `calendar_estimativ` | `UNCONFIRMED` | Status neconfirmat — verifică sursa oficială | umbrella_program | Catalogul agregă programe și apeluri cu stări diferite. |
| `dr12-afir` | `consultare_publica` | `CONSULTATIVE_GUIDE` | Ghid consultativ publicat — depunerea nu este deschisă | program_call | Ghidul este consultativ, iar intervalul de consultare este încheiat; depunerea nu este deschisă. |
| `dr14-afir` | `ghid_aprobat_nedeschis` | `SCHEDULED` | Apel programat — depuneri între 01.09.2026 și 31.10.2026 | session | Anunțul oficial indică o fereastră viitoare 01.09.2026–31.10.2026. |
| `dr18-afir` | `ghid_aprobat_nedeschis` | `SCHEDULED` | Apel programat — depuneri între 01.09.2026 și 31.10.2026 | session | Anunțul oficial indică o fereastră viitoare 01.09.2026–31.10.2026. |
| `start-up-nation` | `apel_inchis` | `CLOSED` | Apel închis — depunerea nu este deschisă | edition | Înscrierile persoanelor juridice s-au încheiat; registry-ul nu consemnează finalizarea întregii proceduri. |
| `femeia-antreprenor` | `apel_inchis` | `CLOSED` | Apel închis — depunerea nu este deschisă | edition | Depunerea ediției 2024 este închisă, iar ordinea finală la evaluare nu dovedește finalizarea întregii proceduri. |
| `digitalizare-imm` | `apel_inchis` | `CLOSED` | Apel închis — depunerea nu este deschisă | program_call | Registry-ul confirmă depunerea închisă, fără o dovadă distinctă de finalizare. |
| `modernizare-microintreprinderi-ne-2` | `consultare_publica` | `CONSULTATIVE_GUIDE` | Ghid consultativ publicat — depunerea nu este deschisă | program_call | Consultarea s-a încheiat, iar forma înregistrată este ghidul consultativ; apelul nu este deschis. |
| `fondul-modernizare-autoconsum` | `apel_inchis` | `COMPLETED` | Apel finalizat — depunerea nu este deschisă | program_call | MySMIS marchează apelurile înregistrate drept FINALIZAT. |
| `fondul-modernizare-regenerabile` | `apel_inchis` | `COMPLETED` | Apel finalizat — depunerea nu este deschisă | program_call | MySMIS marchează apelurile înregistrate drept FINALIZAT. |
| `afir-energie-autoconsum` | `apel_inchis` | `CLOSED` | Apel închis — depunerea nu este deschisă | session | Sesiunea 15.06.2026–14.08.2026 s-a încheiat; nu există în registry o dovadă distinctă de finalizare a procedurii. |
| `autoconsum-institutii-publice` | `apel_inchis` | `COMPLETED` | Apel finalizat — depunerea nu este deschisă | program_call | MySMIS marchează apelul drept FINALIZAT. |
| `pro-infra` | `ghid_aprobat_nedeschis` | `APPROVED_SCHEME` | Schemă aprobată — depunerea nu este deschisă | scheme | Schema este aprobată prin Ordinul MTI nr. 2.292/29.12.2025 și modificată prin Ordinul nr. 101/12.02.2026, fără fereastră oficială de depunere. |
| `apeluri-gal` | `calendar_estimativ` | `UNCONFIRMED` | Status neconfirmat — verifică sursa oficială | umbrella_program | Fiecare GAL are propriul apel și termen; starea agregată nu poate fi prezentată drept OPEN. |
| `gal-afir-leader` | `calendar_estimativ` | `UNCONFIRMED` | Status neconfirmat — verifică sursa oficială | umbrella_program | Fiecare GAL are propriul apel și termen; starea agregată nu poate fi prezentată drept OPEN. |
| `e-move-ro` | `ghid_aprobat_nedeschis` | `APPROVED_SCHEME` | Schemă aprobată — depunerea nu este deschisă | scheme | Actul înregistrat actualizează schema; nu există dovadă de sesiune deschisă. |
| `pocidif-21` | `apel_deschis` | `OPEN` | Apel deschis — depuneri până la 30.09.2026 | session | Pagina oficială înregistrată confirmă sesiunea 30.06.2026–30.09.2026, iar fereastra include data verificării. |
| `pnrr` | `calendar_estimativ` | `UNCONFIRMED` | Status neconfirmat — verifică sursa oficială | umbrella_program | Componentele și apelurile PNRR au stări distincte; implementarea programului nu înseamnă depunere deschisă. |
| `diaspora-investeste-acasa` | `calendar_estimativ` | `ANNOUNCED` | Program anunțat — depunerea nu este deschisă | program | Există comunicare oficială despre program, dar mecanismul de aplicare nu este publicat. |
| `e-drive` | `ghid_aprobat_nedeschis` | `APPROVED_SCHEME` | Schemă aprobată — depunerea nu este deschisă | scheme | Actul înregistrat actualizează schema; nu există dovadă de sesiune deschisă. |
| `e-mobility-ro` | `ghid_aprobat_nedeschis` | `APPROVED_SCHEME` | Schemă aprobată — depunerea nu este deschisă | scheme | Actul înregistrat actualizează schema; nu există dovadă de sesiune deschisă. |
| `fondul-modernizare-pc1-stocare` | `ghid_aprobat_nedeschis` | `FINAL_GUIDE` | Ghid final publicat — depunerea nu este deschisă | program_call | Ghidul final este aprobat, iar perioada de depunere nu este anunțată. |
| `programul-tranzitie-justa` | `calendar_estimativ` | `UNCONFIRMED` | Status neconfirmat — verifică sursa oficială | umbrella_program | Apelurile din program au stări distincte în MySMIS. |
| `fondul-de-modernizare` | `calendar_estimativ` | `UNCONFIRMED` | Status neconfirmat — verifică sursa oficială | umbrella_program | Apelurile Fondului pentru Modernizare au stări distincte în MySMIS. |

## Păstrarea paginilor închise/finalizate

`CLOSED`, `CANCELLED` și `COMPLETED` nu produc automat `noindex`, redirect sau ștergere. Decizia SEO rămâne separată și se bazează pe valoarea evergreen, unicitatea conținutului, intenția de căutare și existența unei destinații canonice mai bune. Pagina păstrată trebuie să arate clar că depunerea nu este deschisă și să indice sursa oficială verificată.

## Limita Task 02

Contractul canonic și rolurile surselor sunt păstrate în înregistrarea unică a programului. HTML-ul, bannerele și celelalte suprafețe continuă să consume temporar codul operațional legacy `status`, dar nu îi mai păstrează atribuirea într-un config concurent.
