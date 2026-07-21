# P1.10 — QA responsive și WCAG 2.2 AA

Data auditului: 21 iulie 2026  
Mediu retestat: build local servit la `http://127.0.0.1:4173`  
Rezultat: **PASS pentru verificările automate și browser asistat; VALIDARE_UMANĂ_NECESARĂ pentru screen reader și zoom nativ 200%.**

Acest raport nu declară conformitate WCAG integrală. Un rezultat automat sau arborele de accesibilitate al browserului nu înlocuiește un test efectuat de o persoană cu un screen reader.

## Domeniu și matrice

Rute: homepage, Contact/formular, DR 12, DR 14, Calculator SO, Despre FABER și hubul AFIR.

| Viewport | Orientare reprezentată | Rute | Reflow document | Structură (`lang`, H1, `main`, skip-link) |
|---:|---|---:|---|---|
| 320×568 | portrait | 7 | PASS | PASS |
| 360×640 | portrait | 7 | PASS | PASS |
| 390×844 | portrait | 7 | PASS | PASS |
| 768×1024 | portrait | 7 | PASS | PASS |
| 1024×768 | landscape | 7 | PASS | PASS |
| 1366×768 | landscape | 7 | PASS | PASS |

Total: 42/42 combinații fără scroll orizontal la nivelul documentului. Pentru toate cele șapte rute, H1, textul din `main`, meta description și JSON-LD au rămas identice între 390 și 1366 px.

## Probleme confirmate și remediate

| ID | Problemă | Criteriu WCAG | Severitate | Fix | Dovadă / retest |
|---|---|---|---|---|---|
| P110-01 | Calculatorul producea un document de 682 px la viewporturile 320–390 px. Cauze: navigație legacy duplicată și tabel de 640 px care forța containerul. | 1.4.10 Reflow | Critică | Navigația duplicată a fost eliminată; wrapperul și secțiunile au `min-width:0`, `max-width:100%` și overflow local controlat. | 320/360/390 PASS; captură `p1-10-calculator-320-reflow.png`. |
| P110-02 | Skip-link exista numai pe homepage. | 2.4.1 Bypass Blocks, 2.4.3 Focus Order | Ridicată | Sincronizatorul global adaugă o singură țintă `main#main-content[tabindex=-1]`, skip-link vizibil la focus și mutarea programatică a focusului. | 166 pagini publice cu `<main>` validate în contract; 7/7 rute în browser. |
| P110-03 | Contraste insuficiente: etichetele `.stars`, headingurile footerului, headingul CTA din hub și portocaliul/butoanele calculatorului. | 1.4.3 Contrast (Minimum), 1.4.11 Non-text Contrast | Ridicată | Accentele au fost trecute pe `#b84716`, headingurile pe alb în suprafețe dark, iar butonul destructiv pe `#b42318`. | Rapoarte calculate după fix: 4,80:1; 19,14:1; 14,36:1; 5,32:1; 6,57:1; toate PASS AA. |
| P110-04 | Câmpurile newsletter foloseau numai placeholder și anulau focusul cu `outline:none`. | 1.3.1 Info and Relationships, 2.4.7 Focus Visible, 3.3.2 Labels or Instructions | Ridicată | Labeluri asociate, ID-uri, `autocomplete`, `aria-describedby`, regiune de eroare și eliminarea `outline:none`. | Contract static PASS; focusul global rămâne disponibil. |
| P110-05 | Tabelele și controalele generate din Calculator SO nu aveau toate nume accesibile; rezultatul nu era anunțat. | 1.3.1, 4.1.2 Name/Role/Value, 4.1.3 Status Messages | Ridicată | 8 caption-uri, `aria-labelledby`, etichete pentru select/input/ștergere și rezultat `role=status`, `aria-live=polite`. | Rând adăugat în browser: toate etichetele prezente; 8/8 tabele denumite; live region PASS. |
| P110-06 | Calculatorul expunea două navigații, cu ordine de focus și landmarkuri redundante. | 1.3.1, 2.4.3, 2.4.6 | Ridicată | Topbarul local a fost eliminat; rămâne componenta globală. | `.topbar` = 0 în DOM; meniul global unic. |
| P110-07 | Unele ținte și stări nu aveau un gate explicit pentru rutele P1.10. | 2.5.8 Target Size (Minimum), 2.4.7, 2.3.3 | Medie | Contract nou pentru matrice, target minimum 24 px, focus, reduced motion, nume accesibile și structură. | Zero controale semantice sub 24 px în cele 42 stări; meniul mobil verificat la 44 px. |

## Interacțiuni retestate

- Meniu: disclosure, `aria-expanded`, Escape și restaurarea focusului sunt acoperite de contractul de navigare la toate cele șase lățimi; stările open/close au fost reconfirmate în browser.
- Formular Contact: submit invalid afișează 5 erori, sumar `role=alert`, mută focusul pe `contact-applicant-type` și leagă eroarea prin `aria-describedby`.
- Carusel: fără auto-rotire; după „Programul următor” indicatorul devine „2 din 6”; slide-urile ascunse sunt `inert` și nu conțin focusabile active.
- Filtre hub: selectarea solicitantului actualizează URL-ul și mesajul din regiunea `aria-live=polite`.
- Accordion: `details/summary` nativ se deschide corect și păstrează întrebarea ca nume accesibil.
- Arbore de accesibilitate: navigare, `main`, H1 și skip-link sunt expuse pentru homepage, Contact, Calculator SO și hub; statusurile sunt expuse acolo unde există.
- WhatsApp: contractul modalului include `role=dialog`, `aria-modal`, close control, focus trap, Escape și restaurarea focusului. Nu există declanșator public pe rutele testate, deci fluxul public este marcat N/A, nu PASS funcțional.
- Sticky CTA: nu este randat pe rutele selectate; verificarea este N/A pentru starea publică actuală.

## Verificări automate

- `npm run test:responsive-accessibility` — PASS: 7 rute × 6 viewporturi și 166 pagini publice cu skip-link valid.
- `npm run test:main-navigation` — PASS: șase stări responsive/tastatură.
- `npm run test:design-system` — PASS: 13 perechi de contrast.
- `npm run test:homepage-hero` — PASS.
- `npm run test:homepage-programs` — PASS.
- `npm run test:long-form-layout` — PASS: 27 pagini, 419 ancore și conținut păstrat integral.
- `npm run test:breadcrumbs` — PASS: 91/91 URL-uri, HTML/JSON-LD în paritate.
- `node --check` rulat separat pentru `assets/global-header.js`, `tools/sync-global-header.js` și `tools/generate-global-header.js` — PASS.

## Validări umane rămase

| Verificare | Stare | Motiv / instrucțiune de retest |
|---|---|---|
| Screen reader | `DE_VALIDAT_UMAN` | NVDA nu este instalat. Windows Narrator există, dar mediul automat nu poate evalua ordinea și calitatea anunțurilor audio. Retest recomandat: NVDA + Firefox/Chrome, pe scriptul de mai jos. |
| Zoom nativ 200% | `DE_VALIDAT_UMAN` | Browserul in-app nu expune controlul de zoom, iar evaluarea DOM este read-only. Breakpointurile și overflow-ul au trecut; este necesar Ctrl+`+` până la 200% într-un browser desktop real. |
| Text spacing 1.4.12 | `DE_VALIDAT_UMAN` | Necesită aplicarea valorilor WCAG de line/paragraph/letter/word spacing și inspecție vizuală pentru clipping/suprapuneri. |
| Touch și orientare pe dispozitiv fizic | `DE_VALIDAT_UMAN` | Portrait/landscape sunt reprezentate prin viewporturi; rotația și gesturile reale necesită dispozitiv. |

### Script scurt pentru validarea umană

1. Pornește NVDA, navighează numai cu tastatura: skip-link → meniu → H1 → conținut → formular/carousel/filtre.
2. Confirmă numele, rolul, starea extins/închis, numărul slide-ului, erorile și mesajele live fără a consulta ecranul.
3. La 200% zoom verifică toate cele șapte rute, apoi aplică text spacing WCAG; nu trebuie să existe clipping, conținut pierdut sau scroll orizontal la nivelul documentului.
4. Repetă formularul cu email fără telefon și cu telefon fără email; verifică sumarul, succesul și retry-ul de rețea.

## Dovezi vizuale

- `reports/p1-10-calculator-320-reflow.png`
- `reports/p1-10-contact-errors-390.png`
