# Audit și implementare: homepage cu 14 programe și PC1 public

Data verificării: 13 septembrie 2026.

## Implementare

Caruselul și tabelul de măsuri folosesc aceeași selecție și ordine:

1. Modernizarea microîntreprinderilor – Apelul 2
2. PC1 – Autoconsum entități publice
3. E-DRIVE
4. DR-12
5. DR-14
6. Diaspora Investește Acasă
7. PC1 – Stocare stand-alone
8. PC1 – Stocare entități publice
9. PRO INFRA
10. PoCIDIF 2.1
11. DR-18
12. E-MOVE RO
13. E-MOBILITY
14. Digitalizare IMM

Fiecare banner are o ilustrație SVG distinctă în stilul vizual FABER, cu mișcare redusă și pauză pentru animații. Au fost eliminate celelalte bannere și butonul AFIR Autoconsum agroalimentar din selecția homepage. Paginile existente rămân accesibile prin catalog și adresele canonice.

Pagina `/fondul-modernizare-pc1-stocare-entitati-publice` a fost completată cu calendar, condiții financiare, documente de pregătit, delimitarea față de stocarea stand-alone și răspunsuri specifice programului. Autoconsumul public folosește același calendar oficial. S-au păstrat adresele existente și structura comună a paginilor de finanțare.

Un buton contextual lung de pe pagina Microîntreprinderi Apelul 2 producea depășire pe mobil după actualizarea textului. CSS-ul comun permite acum încadrarea textului, iar versiunea resursei CSS a fost actualizată pentru cache.

## Surse PC1

Anunțurile Ministerului Energiei, publicate la 11 septembrie 2026 și legate de știrea AFIR, au fost descărcate și citite integral. PDF-ul pentru stocare coincide binar cu documentul atașat de beneficiar; amprentele sunt în `pc1-launch-source-checks-2026-09-13.json`.

- [AFIR: lansarea apelurilor pentru beneficiari publici](https://www.afir.ro/info-la-zi/primire-proiecte-de-investitii-in-energie-regenerabila-beneficiari-publici/)
- [Ministerul Energiei: stocare entități publice](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-stocare_entitati-publice.pdf)
- [Ministerul Energiei: autoconsum entități publice](https://energie.gov.ro/wp-content/uploads/2026/09/Anunt-lansare-apel-proiecte-autoconsum_entitati-publice.pdf)

Depuneri: **28 septembrie 2026, ora 10:00 – 20 noiembrie 2026, ora 23:59**, sau până la epuizarea bugetului. Selecție în ordinea depunerii, cu îndeplinirea condițiilor ghidului. Evaluare: 23 noiembrie 2026 – 2 martie 2027; contractare începând cu 8 februarie 2027; punere în funcțiune până la 31 decembrie 2029.

Stocare publică: buget 150 milioane EUR, maximum 10 milioane EUR/beneficiar cumulat cu parteneriatele, plafon 200.000 EUR/MWh fără TVA. Autoconsum public: buget 500 milioane EUR. Metadatele, rezumatele, calendarele, întrebările frecvente și registrele de surse au fost corelate.

## Validare locală

- 27 pagini de program × 9 dimensiuni de ecran: 243 verificări pentru încadrare, text, contrast și SVG; toate trecute.
- Audit browser separat: 27 pagini × mobil/desktop; raportul `program-experience-homepage14-local-2026-09-13/audit.json` nu indică probleme care cer revizuire.
- Cele 14 bannere și 14 butoane: ordine, destinații, tastatură, revenire circulară, absența suprapunerilor și axe WCAG la 320, 390, 768 și 1440 px; toate trecute. Capturile au fost inspectate vizual.
- Homepage: animație mobilă, pauză, preferință persistentă pentru mișcare redusă, fallback fără JavaScript și CTA vizibil; toate trecute.
- 105 rute: titluri, descrieri, H1, ierarhie de titluri, canonical, robots, OG și Twitter; fără abateri.
- Date structurate: 105 pagini indexabile, fără probleme; 448 întrebări FAQ cu paritate exactă între textul vizibil și schema.
- Integritate internă: 17.132 legături locale și 874 fragmente validate. Cele 96 URL-uri externe sunt inventariate în testul offline; verificarea documentelor PC1 a fost realizată separat online.

## Reper Search Console

Au fost citite cele patru exporturi furnizate. Exportul pe 28 de zile indică 413 clicuri și 13.681 afișări. PoCIDIF 2.1 are 990 afișări și 2 clicuri; stocarea publică are 113 afișări și 2 clicuri. Aceste date sunt reperul anterior publicării, nu rezultate produse de modificări. Impactul asupra pozițiilor și citării în răspunsuri AI poate fi evaluat ulterior pe date noi.

Publicarea este verificată separat prin manifestul release, conținutul HTML/CSS/JS servit, sitemap și testele browser rulate pe domeniul public.
