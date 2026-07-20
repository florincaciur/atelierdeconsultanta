# Audit editorial al limbajului generativ

Generat: 2026-07-13T10:13:14.931Z
Pagini indexabile analizate: 102
Pagini cu observații: 15
Observații totale: 16

Instrumentul raportează formulările și tiparele; nu modifică HTML-ul. Fragmentele sunt păstrate integral în CSV și în secțiunile de mai jos.

## Distribuție după severitate

| Severitate | Număr |
| --- | ---: |
| medie | 10 |
| scăzută | 6 |

## Distribuție după categorie

| Categorie | Număr |
| --- | ---: |
| concluzie_repetitivă | 5 |
| propoziții_simetrice | 4 |
| început_repetat_de_paragraf | 2 |
| liniuțe_lungi_excesive | 2 |
| enumerare_abstractă | 2 |
| promisiune_exhaustivă | 1 |

## /apeluri-gal

### 1. început_repetat_de_paragraf — severitate medie

- Fișier: `apeluri-gal/index.html`
- Fragment exact:

> Verificare pentru Apeluri GAL / LEADER Verificare pentru Apeluri GAL / LEADER Verificare pentru Apeluri GAL / LEADER

- Motiv: Trei paragrafe succesive încep cu aceeași structură, semn al unei redactări mecanice.
- Recomandare: Reordonează paragrafele după criteriu, dovadă și consecință; variază începutul numai când logica o cere.

### 2. promisiune_exhaustivă — severitate medie

- Fișier: `apeluri-gal/index.html`
- Fragment exact:

> Ghid complet GAL-AFIR

- Motiv: Promite exhaustivitate fără să poată acoperi toate versiunile și clarificările oficiale. Expresie detectată: „Ghid complet”.
- Recomandare: Precizează versiunea documentului și subiectele efectiv acoperite.

## /blog

### 1. liniuțe_lungi_excesive — severitate scăzută

- Fișier: `blog/index.html`
- Fragment exact:

> Programele destinate antreprenorilor — Start-Up Nation 2026, Femeia Antreprenor 2026 și PNRR Digitalizare IMM — se adresează unor categorii distincte de beneficiari și au reguli proprii de eligibilitate. Articolele publicate pe acest blog îți explică cum să alegi ideea de afacere potrivită, cum să pregătești planul de afaceri, ce cod CAEN trebuie să ai și ce documente sunt cerute frecvent.

- Motiv: Paragraful folosește 2 liniuțe lungi și comprimă explicații care ar trebui delimitate procedural.
- Recomandare: Împarte ideea în propoziții directe sau într-o listă de criterii, fără a schimba ierarhia vizuală.

## Remediere editorială manuală

După audit au fost rescrise manual numai paginile prioritare de mai jos. Instrumentul a fost rulat din nou după remediere; niciuna dintre aceste rute nu mai are observații, iar scanarea completă are zero constatări cu severitate ridicată.

| Rută | Intervenție editorială principală |
| --- | --- |
| `/` | Introducere bazată pe verificarea solicitantului, CAEN, amplasament, buget și documente; servicii și FAQ delimitate concret. |
| `/verificare-eligibilitate-fonduri-europene` | Criterii, documente, necorelări și consecințele actelor lipsă; eliminate exemplele financiare universale. |
| `/calculator-soc` | Rolul coeficienților și al documentelor agricole; scenarii marcate drept metodă, nu rezultate ale clienților. |
| `/consultanta-fonduri-europene` | Etape contractuale, limite, riscuri și surse; eliminate pragurile și procentele generice. |
| `/dr12-afir` | Ghid consultativ separat de condițiile finale; beneficiari, SO, acte, riscuri și sursă AFIR. |
| `/dr14` | Statut consultativ, praguri SO pe componente, proporționalitatea investiției și documentele fermei. |
| `/por-adr-nord-est` | Hub regional separat de apelurile concrete; localizare, CAEN, matrice și documente, fără termen de răspuns inventat. |
| `/afir-autoconsum-agroalimentar` | Apel deschis și Ghid V7, consum, amplasament, soluție tehnică și consecințele necorelării. |
| `/femeia-antreprenor-2026` | Program național, fără clasificare europeană; condițiile ediției 2026 marcate ca neconfirmate până la procedura finală. |
| `/e-move` | Ghid consultativ, racordare, drept asupra amplasamentului, operare și condiții care așteaptă forma finală. |
| `/despre-faber` | Metodă, limite și date publice verificabile; eliminate afirmațiile despre rezultate și proiecte anonimizate. |
| `/metodologie-verificare-eligibilitate` | Matrice criteriu–dovadă–statut–risc, exemple de necorelare și efectul documentelor lipsă. |

Excepțiile sunt acceptate numai în `config/generative-language-exceptions.json`, pentru `official_name` sau `verbatim_quote`, cu rută, categorie, fragment exact, motiv și sursă.

## /cheltuieli-eligibile-pocidif-21

### 1. enumerare_abstractă — severitate medie

- Fișier: `cheltuieli-eligibile-pocidif-21/index.html`
- Fragment exact:

> Apelul cere o succesiune completă: cercetare industrială și/sau dezvoltare experimentală, introducere în producție, introducere obligatorie pe piață, informare și publicitate și audit tehnic. Un proiect format exclusiv din active corporale și necorporale ori exclusiv din cercetare fără inovare și piață nu este finanțabil.

- Motiv: Paragraful acumulează concepte abstracte, dar nu indică un criteriu, un document, o limită sau un exemplu verificabil.
- Recomandare: Păstrează numai ideile necesare și leagă fiecare afirmație de un criteriu, document sau exemplu de necorelare.

## /dr12-vs-dr14

### 1. propoziții_simetrice — severitate scăzută

- Fișier: `dr12-vs-dr14.html`
- Fragment exact:

> Dacă rezultatul comparatiei este DR12, urmatorul pas este verificarea rolului solicitantului, a exploatației și a planului de dezvoltare. Dacă rezultatul este DR14, urmatorul pas este verificarea fermei mici, a investiției proportionale și a capacitatii de implementare. Dacă rezultatul este "inca nu", atunci proiectul are nevoie de documente sau de asteptarea ghidului activ.

- Motiv: Trei propoziții din același paragraf pornesc cu aceeași structură și creează un ritm mecanic.
- Recomandare: Grupează informația după decizia practică, nu după o structură sintactică repetată.

## /fonduri-europene-caen/4321-instalatii-electrice

### 1. concluzie_repetitivă — severitate medie

- Fișier: `fonduri-europene-caen/4321-instalatii-electrice/index.html`
- Fragment exact:

> programe regionale pentru IMM; Fondul pentru Modernizare, dacă solicitantul și proiectul se incadreaza; Digitalizare IMM

- Motiv: Concluzia reia vocabularul introducerii (100% suprapunere) fără o decizie sau un pas nou.
- Recomandare: Încheie cu documentul care trebuie verificat, o limită factuală sau următorul pas procedural.

## /fonduri-europene-caen/5610-restaurante

### 1. concluzie_repetitivă — severitate medie

- Fișier: `fonduri-europene-caen/5610-restaurante/index.html`
- Fragment exact:

> programe regionale pentru IMM; Start-Up Nation; eficiență energetica și digitalizare, dacă apelul permite

- Motiv: Concluzia reia vocabularul introducerii (100% suprapunere) fără o decizie sau un pas nou.
- Recomandare: Încheie cu documentul care trebuie verificat, o limită factuală sau următorul pas procedural.

## /fonduri-europene-nord-est

### 1. propoziții_simetrice — severitate scăzută

- Fișier: `fonduri-europene-nord-est/index.html`
- Fragment exact:

> Un proiect din Iași, Suceava, Bacău, Botosani, Neamt sau Vaslui nu intra automat intr-un program regional. Dacă investiția este agricolă sau rurala, AFIR poate fi ruta principala. Dacă investiția este digitalizare, energie sau antreprenoriat, poate fi mai potrivit un program national. Dacă investiția este productiva pentru o microintreprindere sau IMM local, merita verificat Programul Regional Nord-Est și apelurile active.

- Motiv: Trei propoziții din același paragraf pornesc cu aceeași structură și creează un ritm mecanic.
- Recomandare: Grupează informația după decizia practică, nu după o structură sintactică repetată.

## /gal-afir

### 1. început_repetat_de_paragraf — severitate medie

- Fișier: `gal-afir/index.html`
- Fragment exact:

> Verificare pentru GAL-AFIR / LEADER Verificare pentru GAL-AFIR / LEADER Verificare pentru GAL-AFIR / LEADER

- Motiv: Trei paragrafe succesive încep cu aceeași structură, semn al unei redactări mecanice.
- Recomandare: Reordonează paragrafele după criteriu, dovadă și consecință; variază începutul numai când logica o cere.

## /ghiduri

### 1. propoziții_simetrice — severitate scăzută

- Fișier: `ghiduri/index.html`
- Fragment exact:

> Un fermier are nevoie de documente diferite față de un IMM din servicii sau față de un start-up. De aceea, resursele trebuie citite prin filtrul beneficiarului, nu doar prin titlul programului. O pagina despre agricultura trebuie să ajungă la SO/SOC, acte de folosință și investiții agricole. O pagina despre digitalizare trebuie să ajungă la procese, hardware, software, securitate și indicatori. O pagina despre programe regionale trebuie să verifice regiunea, codul CAEN, punctul de lucru și cheltuielile productive.

- Motiv: Trei propoziții din același paragraf pornesc cu aceeași structură și creează un ritm mecanic.
- Recomandare: Grupează informația după decizia practică, nu după o structură sintactică repetată.

## /intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm

### 1. concluzie_repetitivă — severitate medie

- Fișier: `intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html`
- Fragment exact:

> Pot fi eligibile software, echipamente IT, servicii cloud, securitate cibernetica, implementare și instruire, dacă sunt permise de apel și justificate prin proiect.

- Motiv: Concluzia reia vocabularul introducerii (100% suprapunere) fără o decizie sau un pas nou.
- Recomandare: Încheie cu documentul care trebuie verificat, o limită factuală sau următorul pas procedural.

## /intrebari/ce-documente-sunt-necesare-pentru-dr12

### 1. concluzie_repetitivă — severitate medie

- Fișier: `intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html`
- Fragment exact:

> Pentru DR12 sunt importante documentele solicitantului, exploatației, calculul SO, actele privind terenurile sau animalele, ofertele, bugetul și declaratiile cerute de apel.

- Motiv: Concluzia reia vocabularul introducerii (100% suprapunere) fără o decizie sau un pas nou.
- Recomandare: Încheie cu documentul care trebuie verificat, o limită factuală sau următorul pas procedural.

## /intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene

### 1. concluzie_repetitivă — severitate medie

- Fișier: `intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html`
- Fragment exact:

> Cofinantarea se calculeaza pornind de la valoarea eligibila, procentul nerambursabil și cheltuielile neeligibile, care trebuie acoperite separat de beneficiar.

- Motiv: Concluzia reia vocabularul introducerii (100% suprapunere) fără o decizie sau un pas nou.
- Recomandare: Încheie cu documentul care trebuie verificat, o limită factuală sau următorul pas procedural.

## /pnrr-digitalizare-imm-cheltuieli-eligibile

### 1. propoziții_simetrice — severitate scăzută

- Fișier: `pnrr-digitalizare-imm-cheltuieli-eligibile.html`
- Fragment exact:

> Fără această analiză, proiectul devine superficial. Poți cumpăra un CRM, dar dacă nu ai proces de vânzare, nu îl vei folosi. Poți cumpăra un ERP, dar dacă nu ai fluxuri clare, implementarea va fi grea. Poți cumpăra echipamente IT, dar dacă nu există politici de securitate, riscul operațional rămâne.

- Motiv: Trei propoziții din același paragraf pornesc cu aceeași structură și creează un ritm mecanic.
- Recomandare: Grupează informația după decizia practică, nu după o structură sintactică repetată.

## /pocidif-21

### 1. enumerare_abstractă — severitate medie

- Fișier: `pocidif-21/index.html`
- Fragment exact:

> Apelul finanțează proiecte ale IMM-urilor TIC care dezvoltă prin cercetare, dezvoltare și inovare servicii, aplicații sau produse noi ori semnificativ îmbunătățite, folosesc tehnologii avansate și includ introducerea rezultatului pe piață.

- Motiv: Paragraful acumulează concepte abstracte, dar nu indică un criteriu, un document, o limită sau un exemplu verificabil.
- Recomandare: Păstrează numai ideile necesare și leagă fiecare afirmație de un criteriu, document sau exemplu de necorelare.

## /pro-infra

### 1. liniuțe_lungi_excesive — severitate scăzută

- Fișier: `pro-infra/index.html`
- Fragment exact:

> PRO INFRA sprijină investițiile care cresc eficiența energetică a capacităților industriale folosite pentru producerea materiilor prime, materialelor și produselor necesare proiectelor de infrastructură de transport. Schema face parte din programul-cheie 9 al Fondului pentru Modernizare — eficiență energetică în transporturi — și urmărește reducerea consumului de energie și a emisiilor de gaze cu efect de seră în procesele de producție.

- Motiv: Paragraful folosește 2 liniuțe lungi și comprimă explicații care ar trebui delimitate procedural.
- Recomandare: Împarte ideea în propoziții directe sau într-o listă de criterii, fără a schimba ierarhia vizuală.
