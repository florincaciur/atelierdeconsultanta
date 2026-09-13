# Audit vizual, funcțional și de vizibilitate — 14 septembrie 2026

## Domeniu și concluzie

Au fost auditate homepage-ul și toate cele 27 de rute din inventarul paginilor de program, inclusiv huburile și articolele suport publicate în sitemap-ul de programe. Lista completă și propunerile individuale sunt în [planul editorial](plan-editorial-vizibilitate-ai-2026-09-14.md).

Au fost găsite și remediate probleme de contrast în homepage și în stările formularului, un mesaj de eroare comprimat într-o coloană prea îngustă, o contradicție de calendar DR-18, o destinație externă PNRR cu problemă de certificat și un titlu repetat în pagina Start-Up Nation. Metadatele, canonical-urile și datele structurate erau conforme la începutul auditului; au fost reverificate după modificări.

## Probleme remediate

| Problemă confirmată | Remediere |
|---|---|
| Linkurile din rezumatul erorilor formularului erau albe pe fundal roz foarte deschis, contrast aproximativ 1,13:1. | Regula pentru text alb a fost limitată la panourile închise la culoare. Mesajele și legăturile de eroare au culori închise explicite. |
| Mesajul erorii de server moștenea tot culoarea albă. | Mesajul păstrează culoarea închisă a stării de eroare. Sunt testate și reîncercarea și succesul prin răspunsuri simulate. |
| Ajutorul pentru email/telefon, nota juridică și linkul către confidențialitate deveneau albe pe alb. Unele cazuri necesitau inspecție suplimentară față de axe. | Culori explicite pentru panoul alb și textele auxiliare; verificare suplimentară a contrastului calculat în formular, inclusiv placeholder-ele. |
| Eroarea confirmării de confidențialitate ocupa coloana de 24 px a checkboxului. | Mesajul este așezat în coloana textului; dispare înălțimea artificială produsă de împărțirea pe foarte multe rânduri. |
| Textul unui CTA de contact era alb pe galben, contrast aproximativ 2,02:1. | Text închis pe galben; eticheta panoului închis rămâne albă. |
| Numerele cardurilor aveau contrast aproximativ 1,12:1; numerele taburilor active aveau aproximativ 3,05:1. | Numere lizibile pe carduri și accent deschis în taburile selectate. |
| DR-18 afișa concomitent o sesiune deschisă și afirmația că depunerea nu a început. | Eliminarea formulărilor contradictorii din rezumat, disclaimer și calendar; trimitere la verificarea disponibilului AFIR. |
| Destinația directă a tabloului PNRR producea eroare de verificare a certificatului în clientul HTTP. | Legăturile folosesc pagina oficială MIPE `https://mfe.gov.ro/pnrr-dashboard/`, verificată HTTP 200. Nu s-a dezactivat validarea certificatelor. |
| Două H2 „Următorul pas” în pagina Start-Up Nation. | Titlu final descriptiv: „Verifică scenariul Start-Up Nation”, păstrând ancora și URL-ul. |

Regula nouă de contrast este limitată la homepage. Identitatea FABER, ordinea celor 14 măsuri, simulatoarele, formularul, URL-urile și regulile de indexare sunt păstrate. S-a actualizat versiunea CSS pentru cache.

## Metodă și rezultate

- **Programe:** 27 rute × 390/1440 px = 54 combinații verificate în browser. Verificări pentru resurse lipsă, erori JavaScript, imagini, ancore, ID-uri duplicate, depășire orizontală, meniuri, animații/pauză, CTA fix și secțiuni desfășurate. Zero combinații cu probleme în auditul inițial. Au fost inspectate capturile comparative mobile și desktop.
- **Homepage:** 19 stări × 320/390/768/1440 px = 76 combinații. Sunt incluse cele cinci secțiuni, etapele metodei, toate taburile de servicii/resurse și formularul: inițial, validare, detalii, rezumat, eroare de server, succes. 45 de combinații semnalau contrast insuficient înainte de remediere. După remediere: fără încălcări axe, fără depășiri și fără contrast insuficient detectat de verificarea suplimentară a panoului alb.
- **Formular:** datele fictive sunt interceptate în browser, inclusiv în verificarea live. Testele nu creează solicitări în sistemul de producție. Fluxul existent validează lipsurile, păstrează datele, permite întoarcerea între pași și reîncercarea după eroare.
- **Carusel și selecție:** testele păstrează exact 14 programe, ordinea solicitată, linkurile către paginile corecte, navigarea cu tastatura, pauza animației și funcționarea fără JavaScript.
- **SEO tehnic:** 105 rute verificate pentru title, description, H1, heading-uri, canonical, robots, Open Graph și Twitter. Fără abateri.
- **Date structurate:** 105 pagini indexabile fără probleme; paritate între conținutul vizibil și schema pentru 448 de întrebări FAQ, pe 106 rute/113 surse HTML.
- **Legături:** 17.132 legături locale și 874 fragmente verificate. Cele 50 de destinații externe distincte extrase din conținutul paginilor de program răspund HTTP 200 după remedierea destinației PNRR. Răspunsul HTTP nu substituie verificarea fiecărei condiții din document.
- **Acces pentru motoare:** verificări trecute pentru sitemap, canonical-uri, redirecționări, conținut HTML accesibil și politica de acces a crawlerelor. Nicio relaxare a protecției rutelor private.

Pentru a preveni reapariția problemelor, testul `test:homepage-all-states` verifică stările formularului și contrastul la fiecare publicare în workflow-ul de verificare live. Auditul factual include acum un test care respinge formulările de tip „depunerea nu a început” în rezumatele programelor cu statut OPEN.

## Performanță

Au fost măsurate 28 de navigări: homepage și cele 27 de rute, în Chromium la 390 px, cu context nou pentru fiecare pagină și rețeaua reală disponibilă. În această măsurare, LCP a fost între 352 și 944 ms; homepage 872 ms. Deplasarea observată a conținutului a fost zero pentru majoritatea paginilor, iar maximul CLS observat a fost aproximativ 0,00025.

Acestea sunt valori diagnostice de laborator, într-o singură rulare fără limitare artificială a rețelei, observată 1,2 secunde după încărcare. Nu reprezintă percentila 75 din CrUX și nu includ un INP valid de teren. Nu s-au schimbat speculative încărcarea scripturilor, analytics sau simulatoarele pe baza acestei singure măsurări. Datele reale Core Web Vitals trebuie urmărite în Search Console. [Google: experiența paginii](https://developers.google.com/search/docs/appearance/page-experience)

## Verificarea editorială și limite

Calendarul DR-18 a fost confruntat cu [anunțul AFIR pentru DR-14 și DR-18](https://www.afir.ro/comunicate/afir-lanseaza-sesiuni-pentru-ferme-mici-si-floricultura-plante-medicinale-si-aromatice/), care indică perioada 1 septembrie–31 octombrie 2026 și posibilitatea închiderii anticipate. Paginile PC1 păstrează calendarul și documentele oficiale verificate în auditul precedent; acestea nu au fost înlocuite cu estimări.

Auditul de vizibilitate inventariază toate paginile și propune aprofundări specifice. Nu reprezintă recertificarea juridică integrală, în această dată, a tuturor ghidurilor și anexelor tuturor programelor. Datele „verificat la” nu au fost actualizate în masă doar pentru că s-au schimbat stilurile.

Nu există o verificare tehnică ce poate garanta citarea de către un motor AI sau o anumită poziție în Google. Planul editorial urmărește informații distincte, documentate și ușor de verificat, cu măsurarea impactului ulterior.

## Dovezi

Rezultatele agregate sunt în `audit-vizual-seo-programe-2026-09-14.json`. Capturile de lucru sunt păstrate local în `.codex/homepage-states-local/` și `reports/program-experience-full-programs-2026-09-14/`; nu sunt introduse în fișierele publicate pe site. Verificarea publicării compară manifestul release și conținutul HTML/CSS/JS servit cu commitul local, apoi rulează testele browser pe domeniul public.
