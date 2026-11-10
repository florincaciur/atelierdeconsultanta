# DR 12 · termene pe componente

Verificare la 10 noiembrie 2026 și reverificare după miezul nopții din 11 noiembrie. Fișa de depunere folosește înregistrarea DR-12 din registrul comun și afișează starea constatată la momentul consultării contorului AFIR.

| Componentă | Deschidere | Închidere afișată în contor | Fus orar |
| --- | --- | --- | --- |
| Alte sectoare | 6 octombrie 2026, 09:00 | 11 noiembrie 2026, 00:00 | Europe/Bucharest |
| Sector zootehnic | 6 octombrie 2026, 09:00 | 2 decembrie 2026, 15:59:59 | Europe/Bucharest |

La reverificarea din 11 noiembrie, ora 00:00:29, contorul păstra același termen pentru Alte sectoare. Fișa indică „Termen afișat expirat” pentru această componentă. Sector zootehnic era prezent în lista sesiunilor active, cu termen la 2 decembrie, ora 15:59:59. Publicarea nu deduce o prelungire din simpla prezență a unui rând în platformă.

Ora 00:00 se află la începutul zilei de 11 noiembrie, la miezul nopții dintre 10 și 11 noiembrie. Comunicatul de lansare descrie intervalul general al sesiunii. Pentru termenul fiecărei componente se folosește rândul ei din contor. Sumele disponibile și numărul de proiecte se modifică în platformă și se verifică înainte de transmitere. [Contor AFIR](https://depunerepspac.afir.ro/Sesiune/Lista) · [Anunțul sesiunii](https://www.afir.ro/info-la-zi/sesiune-depunere-de-proiecte-dr-12/)

Catalogul AFIR consultat afișează ghidul publicat la 18 septembrie 2026 și fișa de evaluare din 21 septembrie. Sunt listate și clarificări, inclusiv nota din 6 noiembrie despre istoricul șefului exploatației. Acea notă tratează verificarea criteriului de selecție 6.2. În catalogul consultat nu a fost identificat un ghid ulterior care să înlocuiască documentul folosit aici. Evidența verificării păstrează URL-urile, orele consultării și amprentele răspunsurilor. [Documente AFIR DR-12](https://www.afir.ro/domenii-de-interventie/detalii-si-anexe-dr-12/) · [Evidența surselor](surse.json)

Fișa HTML include componenta, deschiderea, închiderea și starea la verificare. Calendarul afișează aceeași stare și același moment al verificării, iar hero și meniul preiau eticheta din registru. Ancora nouă este `#dr12-afir-termene`. Ancorele existente `#este-deschis-apelul-dr12`, `#dr12-lansare`, `#cheltuieli-neeligibile-dr12` și `#dr12-neeligibile` sunt păstrate.

Au fost eliminate răspunsurile FAQ care repetau calendarul. Secțiunea de pregătire trimite către fișa de depunere și rămâne distinctă de regulile cheltuielilor. Metadatele rezumă rolul paginii și folosesc aceeași sursă cu datele structurate. DR-12, calendarul și comparația DR-12/DR-14 au data modificării 11 noiembrie, când starea de după termen a fost reverificată și explicată.

La verificările de publicare au fost corectate și trei date vechi din textele registrului intern de aprobări, în acord cu `verifiedAt` deja înregistrat. Două verificări din testul paginii despre FABER au fost aliniate cu formularea publicată la începutul acestei intervenții. În testul sursei factuale, legătura către ghid este verificată explicit, alături de legătura nouă către contor.

Testul formularului a identificat derularea la primul câmp invalid înainte de încheierea unei animații. Focalizarea folosește acum derulare imediată, astfel încât câmpul să fie vizibil sub antet. Auditul de finanțare folosește data calendaristică Europe/Bucharest, verificată prin test la limita orei 00:00. Generatorul DR-12 folosește normalizarea FAQ existentă și păstrează exclusiv sursa canonică în director.

Ordinea asseturilor pentru hero și fluxul homepage a fost stabilizată între generatoare. Pipeline-ul sincronizează blocurile de întrebări și după metoda calculatorului SO. Politica linkurilor externe include domeniile oficiale ONRC și ADR Sud-Muntenia, necesare pentru sursele deja citate în paginile CAEN și de cofinanțare.

Pachetul final a fost verificat la 320, 390 și 1440 px, cu JavaScript dezactivat. Tabelul se derulează în propria regiune pe mobil, iar pagina păstrează lățimea viewportului. Verificarea cu JavaScript a confirmat paritatea dintre calendar și hero și transmiterea sursei `/dr12-afir` în formular, cu API interceptat. Au fost transmise zero contacte de test către producție. [Rezultatele locale](teste-locale.json)
