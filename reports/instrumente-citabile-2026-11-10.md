# Instrumente și exemple · 10 noiembrie 2026

| Pagină | Exemplu reproductibil | Sursa intrărilor |
| --- | --- | --- |
| `/resurse#buget-digitalizare-excel` | C2–C5 cu 18.000, 4.000, 3.000 și 5.000 EUR. `=SUM(C2:C5)` în C6 afișează 30.000 EUR fără TVA. | Foaia Buget din XLSX, rubricile de ofertare și ghidul apelului pentru încadrare. |
| `/resurse#calendar-pregatire-excel` | 26 noiembrie − 12 noiembrie 2026. `=C5-C2` în C6 afișează 14 zile calendaristice. | Foaia Calendar din XLSX, cu termene interne stabilite după calendarul autorității. |
| `/cum-se-calculeaza-cofinantarea-fonduri-europene#calculator-cofinantare` | Bază de 70.000 EUR × 85% = 59.500 EUR. Plafonul reduce grantul la 50.000 EUR. Costul propriu după recuperarea TVA este 25.000 EUR. | Intensitate și plafon din DR-14. Costurile și tratamentul TVA sunt ipoteze ale exemplului. |
| `/calculator-soc#exemple-calcul-so` | 150 pui ÷ 100 = 1,50 unități. 1,50 × 499,79 EUR/unitate = 749,685 EUR SO. Afișaj rotunjit 750 EUR SO. | Codul A5140 din lista SOC 2020 AFIR, noiembrie 2024. |

Cele două XLSX sunt șabloanele existente, cu rubricile de intrare necompletate. Formulele din previzualizare se introduc în celulele indicate. Verificarea descarcă ambele fișiere și compară octeții cu versiunea din Git, apoi deschide foile și controlează coloanele, rândurile și rezultatele manuale.

Calculatorul de cofinanțare lucrează local, în EUR. Utilizatorul introduce plafonul efectiv, intensitatea și sumele de TVA deja încadrate pe baza actelor. Costul propriu după grant și recuperarea TVA este separat de plățile intermediare. Pagina citează ghidul aplicabil și, pentru fondurile reglementate de acestea, [Regulamentul (UE) 2021/1060, art. 64](https://eur-lex.europa.eu/eli/reg/2021/1060/oj?locale=ro) și [HG 873/2022, art. 9](https://www.adrmuntenia.ro/index.php/download_file/article/794/HG-873-2022-07-06-MO-680.pdf).

Tabelul SO cuprinde toate cele 46 de categorii selectate în calculator, cu cod și unitate. Documentul AFIR descărcat la 10 noiembrie are SHA-256 `4DBCA7CE226BFCD3E54BED11238664C81E443D54BC889E98F7C2602C2206DA06`, identic cu versiunea din registru. [Lista oficială SOC 2020](https://www.afir.ro/info-la-zi/lista-detaliata-coeficienti-standard-output-soc-2020/)

Legăturile către exemple apar în DR-12, DR-14 și Digitalizare IMM Regiunea Centru · Apel 2. Contractul `node tests/citable-instruments-contract.mjs` verifică aceste legături, formulele și navigarea cu tastatura. Testează valori zero, intensitate 100%, plafon zero, plafon activ, TVA împărțită între categorii, precizie sub un cent, limitele tehnice și cantitățile invalide. Previzualizările, formulele și exemplele sunt verificate la 390 și 1.440 px cu JavaScript dezactivat.
