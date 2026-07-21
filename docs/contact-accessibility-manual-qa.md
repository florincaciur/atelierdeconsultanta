# QA manual — formular Contact, WCAG 2.2 AA

## Configurație recomandată

- desktop: Windows 11, Chrome curent, NVDA curent;
- mobil: iOS/Safari cu VoiceOver sau Android/Chrome cu TalkBack;
- pagină: `/contact`, fără date personale reale;
- zoom: 100% și 200%; viewport minim: 320 CSS px.

## Tastatură

1. Folosește numai `Tab`, `Shift+Tab`, `Space`, săgeți și `Enter`.
2. Confirmă ordinea: tip solicitant → localitate → investiție → email → telefon → date opționale → confirmarea informării → acțiunile pasului.
3. Activează „Verifică și trimite” cu toate câmpurile goale.
4. Confirmă apariția sumarului, focusul pe „Tip solicitant”, conturul vizibil și faptul că headerul nu acoperă controlul.
5. Urmează fiecare link din sumar; focusul trebuie să ajungă la câmpul corespunzător.
6. Completează numai email sau numai telefon, continuă la rezumat și revino cu „Modifică”; valorile trebuie păstrate.
7. La trimitere, confirmă mesajul de încărcare și indisponibilizarea temporară a butonului.
8. Simulează o eroare de rețea; confirmă că valorile rămân și că „Încearcă din nou” este disponibil.

Rezultat tehnic executat în browser prin evenimente reale de tastatură: **PASS**. Ordinea, focusul primei erori, conturul și păstrarea valorilor sunt acoperite și de testul automat.

## Cititor de ecran

1. Pornește NVDA și navighează în mod formular.
2. Confirmă că fiecare control anunță numele, obligativitatea și instrucțiunile relevante.
3. Trimite formularul necompletat; trebuie anunțat sumarul, apoi câmpul focalizat și eroarea sa.
4. Confirmă că perechea email/telefon este anunțată ca grup și că regula „cel puțin unul” este citită.
5. La trimitere, confirmă anunțul „Solicitarea se trimite”.
6. La succes, confirmă anunțarea regiunii `status`; la eroare, confirmă anunțarea alertei și a acțiunii de reîncercare.
7. Verifică faptul că honeypot-ul anti-spam nu apare în ordinea de citire.

Stare: **DE_VALIDAT_UMAN** pentru o sesiune efectivă NVDA/VoiceOver. Arborele de accesibilitate și regiunile live sunt verificate automat, dar acestea nu înlocuiesc testarea umană cu tehnologia asistivă.

## Reflow și target-uri

- la 320 px nu trebuie să existe scroll orizontal la nivelul paginii;
- la 200% textul și linkurile lungi trebuie să se rupă pe rânduri;
- controalele interactive au minimum 24×24 CSS px, iar acțiunile principale au minimum 44 px înălțime pe mobil.

Rezultat automat Chrome: **PASS**.
