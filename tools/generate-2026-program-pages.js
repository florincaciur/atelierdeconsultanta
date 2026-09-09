#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { synchronizedHtml } = require("./sync-breadcrumbs");
const { synchronizeFaqHtml } = require("./faq-governance");
const { synchronize: synchronizeCanonicalContact } = require("./sync-canonical-contact");
const { loadLegalIdentity } = require("./legal-identity-governance");
const { renderFooterContact } = require("./canonical-contact");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const HEADER = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8").trim();
const REGISTRY = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "seo-programs.json"), "utf8")).programs;
const FOOTER_CONTACT = renderFooterContact(loadLegalIdentity());

const PAGE_CONTENT = {
  "autoconsum-institutii-publice": {
    "h1": "PC1 Autoconsum 2026 pentru entități publice – producție solară și stocare integrată",
    "eyebrow": "Fondul pentru Modernizare · Program-cheie 1",
    "lead": "Finanțare pentru capacități fotovoltaice noi cu baterii integrate, destinate integral autoconsumului instituțiilor și entităților publice eligibile.",
    "metrics": [
      [
        "500 mil. €",
        "buget total al apelului"
      ],
      [
        "max. 10 mil. €",
        "ajutor per beneficiar"
      ],
      [
        "până la 100%",
        "din cheltuielile eligibile"
      ],
      [
        "11.09–06.11.2026",
        "calendarul anunțat al depunerii"
      ]
    ],
    "answer": "PC1 Autoconsum finanțează capacități noi de producere a energiei solare cu stocare integrată pentru entități publice. Bugetul este de 500 milioane euro, iar ajutorul poate ajunge la 10 milioane euro pe beneficiar și la 100% din cheltuielile eligibile, în limitele tehnice și valorice ale ghidului. Bateriile sunt obligatorii și trebuie dimensionate pentru 2–4 ore. La 9 septembrie 2026, depunerea era programată pentru 11 septembrie–6 noiembrie 2026, nu încă deschisă.",
    "fit": [
      "Solicitantul se încadrează într-o categorie publică eligibilă și poate adopta actele interne necesare proiectului.",
      "Există un amplasament cu drepturi clare, consum documentat și condiții realiste pentru racordare, montaj și autorizare.",
      "Proiectul propune o capacitate solară nouă, stocare integrată și un consum propriu care susține dimensionarea tehnică."
    ],
    "caution": [
      "Proiectele numai cu baterii, numai cu pompe de căldură, de înlocuire sau de extindere necontorizată separat nu sunt eligibile pe această linie.",
      "Energia produsă trebuie utilizată 100% pentru autoconsum, iar energia stocată trebuie să provină 100% din instalația solară proprie.",
      "La data verificării, pagina operațională AFIR pentru sesiune nu era încă publicată; calendarul și eventualele clarificări se reconfirmă înainte de transmitere."
    ],
    "investments": [
      [
        "Capacitate fotovoltaică nouă",
        "Panouri, invertoare, protecții, măsurare și componentele necesare unei instalații noi, contorizate și monitorizate separat."
      ],
      [
        "Stocare integrată obligatorie",
        "Baterii noi dimensionate pentru o durată echivalentă de minimum două și maximum patru ore."
      ],
      [
        "Pompe de căldură, opțional",
        "Echipamentele și lucrările de instalare pot fi eligibile în condițiile ghidului; forajele asociate rămân neeligibile."
      ],
      [
        "Montaj și punere în funcțiune",
        "Lucrările și serviciile indispensabile instalării, conectării, monitorizării și punerii în funcțiune a investiției."
      ]
    ],
    "documents": [
      [
        "Eligibilitatea entității",
        "Actul de înființare, statutul juridic, reprezentarea legală, hotărârile de aprobare și documentele fiscale cerute de ghid."
      ],
      [
        "Consumul și dimensionarea",
        "Ultimele 12 facturi, profilul consumului, auditul electroenergetic când există consumatori viitori și calculele AC.1–AC.4 din studiul de fezabilitate."
      ],
      [
        "Amplasamentul",
        "Extras de carte funciară și dreptul de proprietate, administrare, concesiune ori superficie, împreună cu verificarea sarcinilor și litigiilor."
      ],
      [
        "Studiul de fezabilitate",
        "Documentație conform HG nr. 907/2016, nu mai veche de doi ani, elaborată cu participarea personalului autorizat ANRE în instalații electrice."
      ],
      [
        "Buget, avize și mediu",
        "Deviz, buget indicativ, sursele pentru cheltuielile neeligibile, documentele de mediu și demersurile pentru avizul tehnic de racordare."
      ]
    ],
    "steps": [
      "Confirmă categoria solicitantului, actele de aprobare și dreptul asupra amplasamentului.",
      "Corelează consumul cu puterea fotovoltaică și cu bateria de 2–4 ore în studiul de fezabilitate.",
      "Construiește bugetul în limitele de 900.000 EUR/MW sau 1.100.000 EUR/MW când proiectul include pompe de căldură.",
      "Reverifică anunțul sesiunii AFIR, ghidul, anexele și clarificările înainte de depunere."
    ],
    "extraSources": [
      [
        "Ministerul Energiei — pachetul actualizat al ghidului și anexelor",
        "https://energie.gov.ro/wp-content/uploads/2026/06/Ghidul-solicitantului-Autoconsum-EP_23.06.rar"
      ],
      [
        "Portalul Legislativ — forma consolidată a ghidului PC1 pentru autoconsum public",
        "https://legislatie.just.ro/Public/DetaliiDocument/276306"
      ],
      [
        "AFIR — lista oficială a sesiunilor",
        "https://depunerepspac.afir.ro/Sesiune/Lista"
      ]
    ],
    "faqs": [
      [
        "Cine poate aplica la PC1 Autoconsum pentru entități publice?",
        "Pot aplica UAT-uri și subdiviziunile lor, unități din apărare și administrația penitenciară, spitale publice, instituții publice, culte recunoscute, universități de stat, institute publice de cercetare, asociații de dezvoltare intercomunitară și centre sociale ori paliative finanțate integral din fonduri publice, în condițiile ghidului."
      ],
      [
        "Cât este finanțarea?",
        "Ajutorul poate acoperi până la 100% din cheltuielile eligibile, fără a depăși 10 milioane euro pe beneficiar și plafoanele de 900.000 EUR/MW fără pompe de căldură, respectiv 1.100.000 EUR/MW cu pompe de căldură."
      ],
      [
        "Este obligatorie bateria?",
        "Da. Proiectul trebuie să includă stocare integrată, cu putere nominală cel puțin egală cu puterea centralei fotovoltaice și cu o durată echivalentă de 2–4 ore."
      ],
      [
        "Sunt eligibile pompele de căldură?",
        "Da, ca parte a proiectului de producție solară și stocare, în condițiile ghidului. Un proiect numai cu pompe de căldură nu este eligibil, iar forajele asociate nu sunt cheltuieli eligibile."
      ],
      [
        "Poate fi folosită energia și pentru livrare în rețea?",
        "Ghidul cere ca proiectul să fie destinat 100% autoconsumului. Dimensionarea se justifică prin consumul de referință și, dacă este cazul, prin consumatori viitori documentați."
      ],
      [
        "Când se depun proiectele?",
        "Calendarul anunțat este 11 septembrie–6 noiembrie 2026, cu depunere prin AFIR și în limita bugetului. Înainte de transmitere trebuie verificat anunțul operațional al sesiunii."
      ],
      [
        "Ce vechime poate avea studiul de fezabilitate?",
        "Studiul de fezabilitate trebuie să fie conform HG nr. 907/2016 și să nu fie mai vechi de doi ani, iar echipa trebuie să includă personal autorizat ANRE în domeniul instalațiilor electrice."
      ],
      [
        "Până când trebuie finalizată investiția?",
        "Instalarea, conectarea la rețea și punerea în funcțiune trebuie finalizate cel târziu la 31 decembrie 2029."
      ]
    ],
    "comparison": {
      "title": "Ce este obligatoriu și ce rămâne opțional?",
      "headers": [
        "Componentă",
        "Regula ghidului",
        "Observație"
      ],
      "rows": [
        [
          "Producție solară nouă",
          "Obligatorie",
          "Trebuie contorizată și monitorizată separat."
        ],
        [
          "Stocare integrată",
          "Obligatorie",
          "Putere cel puțin egală cu PV și durată de 2–4 ore."
        ],
        [
          "Pompe de căldură",
          "Opționale",
          "Sunt eligibile în proiect; forajele nu sunt eligibile."
        ]
      ]
    }
  },
  "fondul-modernizare-pc1-stocare-entitati-publice": {
    "h1": "PC1 Stocare 2026 pentru entități publice – baterii în spatele contorului",
    "eyebrow": "Fondul pentru Modernizare · Program-cheie 1",
    "lead": "Finanțare pentru capacități noi de stocare conectate direct la instalații regenerabile existente, astfel încât energia produsă local să fie folosită mai eficient pentru consumul propriu.",
    "metrics": [
      [
        "150 mil. €",
        "buget total al apelului"
      ],
      [
        "max. 10 mil. €",
        "ajutor per beneficiar"
      ],
      [
        "100%",
        "din cheltuielile eligibile"
      ],
      [
        "11.09–06.11.2026",
        "calendarul anunțat al depunerii"
      ]
    ],
    "answer": "PC1 Stocare finanțează sisteme noi de baterii în spatele contorului, conectate direct la instalații regenerabile existente ale entităților publice. Bugetul este de 150 milioane euro, iar finanțarea este de 100% din cheltuielile eligibile, în limita a 10 milioane euro pe beneficiar. Durata echivalentă a stocării trebuie să fie de 2–4 ore. La 9 septembrie 2026, depunerea era programată pentru 11 septembrie–6 noiembrie 2026, nu încă deschisă.",
    "fit": [
      "Entitatea publică se află într-o categorie eligibilă și deține o instalație de producere a energiei din surse regenerabile deja existentă.",
      "Bateria poate fi conectată în spatele aceluiași contor, în cadrul instalației de utilizare a locului de producere sau de producere și consum.",
      "Puterea centralei existente, consumul și profilul de producție susțin o baterie dimensionată pentru 2–4 ore."
    ],
    "caution": [
      "Această linie nu finanțează o baterie stand-alone destinată pieței și nici construirea unei centrale regenerabile noi.",
      "Nu sunt eligibile înlocuirea integrală a unei stocări existente, echipamentele fără marcaj CE sau tehnologiile pe bază de plumb, NiCd ori NiMH.",
      "Este permis un singur proiect per solicitant, iar instalația existentă și punctul de conexiune trebuie documentate fără ambiguități."
    ],
    "investments": [
      [
        "Baterii noi în spatele contorului",
        "Echipamente noi de stocare conectate direct la instalația regenerabilă existentă și la locul de producere sau de producere și consum."
      ],
      [
        "Conversie, protecție și control",
        "Invertoare, sisteme de management al bateriei, protecții, măsurare și monitorizare necesare funcționării sigure."
      ],
      [
        "Montaj și punere în funcțiune",
        "Lucrările și serviciile indispensabile instalării, testării, conectării și punerii în funcțiune."
      ],
      [
        "Consultanță și management",
        "Cheltuielile pot fi eligibile în condițiile și proporțiile prevăzute de ghid, cu trasabilitate față de tranșele proiectului."
      ]
    ],
    "documents": [
      [
        "Solicitantul și aprobările",
        "Actul de înființare, reprezentarea, hotărârea de aprobare, situația fiscală și documentele specifice categoriei publice."
      ],
      [
        "Instalația regenerabilă existentă",
        "Documentele tehnice și juridice ale centralei, puterea instalată, punctul de racordare, producția și legătura directă cu bateria propusă."
      ],
      [
        "Studiul de fezabilitate",
        "Documentație conform HG nr. 907/2016, nu mai veche de doi ani, cu personal autorizat ANRE și calculele pentru energia utilă și durata de 2–4 ore."
      ],
      [
        "Amplasamentul",
        "Extras de carte funciară și dreptul de proprietate, administrare, concesiune ori superficie, fără sarcini sau litigii care împiedică investiția."
      ],
      [
        "Racordare, mediu și buget",
        "ATR ori dovada demersurilor la etapa cerută, documentele de mediu, devizul general, bugetul indicativ și sursele pentru costurile neeligibile."
      ]
    ],
    "steps": [
      "Confirmă eligibilitatea entității și documentele instalației regenerabile existente.",
      "Dimensionează bateria la 2–4 ore pe baza puterii centralei, a producției și a consumului propriu.",
      "Verifică amplasamentul, soluția de conectare, bugetul și calendarul până la punerea în funcțiune.",
      "Reverifică anunțul sesiunii AFIR, ghidul, anexele și clarificările înainte de depunere."
    ],
    "extraSources": [
      [
        "Ministerul Energiei — pachetul actualizat al ghidului și anexelor",
        "https://energie.gov.ro/wp-content/uploads/2026/06/Ghidul-solicitantului-Stocare-EP.zip"
      ],
      [
        "AFIR — lista oficială a sesiunilor",
        "https://depunerepspac.afir.ro/Sesiune/Lista"
      ],
      [
        "Portalul Legislativ — cadrul Fondului pentru Modernizare",
        "https://legislatie.just.ro/Public/DetaliiDocument/309282"
      ]
    ],
    "faqs": [
      [
        "Cine poate aplica la PC1 Stocare pentru entități publice?",
        "Pot aplica UAT-uri și subdiviziunile lor, unități din apărare și administrația penitenciară, spitale publice, instituții publice, culte recunoscute, universități de stat, institute publice de cercetare, asociații de dezvoltare intercomunitară și centre sociale ori paliative finanțate integral din fonduri publice, în condițiile ghidului."
      ],
      [
        "Cât este finanțarea?",
        "Finanțarea este de 100% din cheltuielile eligibile, fără a depăși 10 milioane euro pe beneficiar. Bugetul total estimat al apelului este de 150 milioane euro."
      ],
      [
        "Este necesară o instalație regenerabilă existentă?",
        "Da. Sistemul nou de stocare trebuie conectat direct la o instalație existentă de producere a energiei din surse regenerabile."
      ],
      [
        "Ce înseamnă stocare în spatele contorului?",
        "Bateria este conectată în instalația de utilizare a aceluiași loc de producere sau de producere și consum, pentru optimizarea consumului local, nu ca activ stand-alone racordat separat la rețea."
      ],
      [
        "Ce capacitate trebuie să aibă bateria?",
        "Energia utilă a bateriei trebuie să asigure o durată echivalentă de minimum două și maximum patru ore, raportată la puterea instalată eligibilă a centralei existente."
      ],
      [
        "Câte proiecte poate depune o instituție?",
        "Ghidul permite un singur proiect per solicitant. Entitatea trebuie să aleagă și să dimensioneze coerent investiția înainte de depunere."
      ],
      [
        "Când se depun proiectele?",
        "Calendarul anunțat este 11 septembrie–6 noiembrie 2026, cu depunere prin AFIR și în limita bugetului. Înainte de transmitere trebuie verificat anunțul operațional al sesiunii."
      ],
      [
        "Până când trebuie finalizată investiția?",
        "Instalarea, conectarea și punerea în funcțiune trebuie finalizate cel târziu la 31 decembrie 2029. Contractul include apoi o perioadă de monitorizare de cinci ani de la ultima plată."
      ]
    ],
    "comparison": {
      "title": "PC1 Stocare sau PC1 Autoconsum?",
      "headers": [
        "Situația instituției",
        "Linia potrivită",
        "Investiția centrală"
      ],
      "rows": [
        [
          "Are deja instalație regenerabilă eligibilă",
          "PC1 Stocare",
          "Baterie nouă în spatele contorului"
        ],
        [
          "Nu are capacitatea solară necesară",
          "PC1 Autoconsum",
          "Producție solară nouă cu stocare integrată"
        ],
        [
          "Urmărește baterie stand-alone pentru piață",
          "Niciuna dintre liniile publice",
          "Se analizează separat schema pentru întreprinderi"
        ]
      ]
    }
  },
  "diaspora-investeste-acasa": {
    "eyebrow": "Antreprenoriat · investiții în România",
    "lead": "Programul aprobat combină un credit pentru investiții, garanția BID și un grant. Verifică vechimea firmei, legătura cu diaspora și contribuția înainte de discuția cu banca.",
    "metrics": [
      [
        "100 mil. €",
        "buget 2026–2029"
      ],
      [
        "max. 200.000 €",
        "grant per beneficiar"
      ],
      [
        "max. 60%",
        "din creditul de investiții"
      ],
      [
        "5 / 10 / 15%",
        "contribuție după profil și buget"
      ]
    ],
    "answer": "Diaspora Investește Acasă este un program aprobat, în curs de operaționalizare prin BID și băncile partenere. Sprijinul combină un credit de investiții cu un grant de maximum 60% din credit, fără a depăși 200.000 EUR. Firma trebuie să aibă mai puțin de trei ani la depunere și să îndeplinească cerințele privind asociații din diaspora. Contribuția proprie este 10% pentru proiecte de până la 400.000 EUR, respectiv 5% în cazul special pentru tineri, și 15% peste 400.000 EUR. Lista băncilor partenere este încă în pregătire.",
    "fit": [
      "Firma are mai puțin de trei ani la data cererii și investește în România.",
      "Asociații eligibili dețin majoritatea capitalului și dovedesc cel puțin 12 luni de domiciliu/reședință în străinătate din ultimele 18 luni.",
      "Asociații majoritari și/sau administratorii au minimum nouă luni de experiență sau pregătire relevantă, inclusiv în management."
    ],
    "caution": [
      "BID indică operaționalizarea în curs; lista băncilor partenere urmează să fie publicată.",
      "Grantul se folosește pentru reducerea soldului creditului după investiție și verificarea condițiilor.",
      "Acordarea creditului depinde de analiza băncii; eligibilitatea programului nu garantează creditarea."
    ],
    "investments": [
      [
        "Echipamente și tehnologie",
        "Utilaje, tehnologii, software și licențe necesare investiției."
      ],
      [
        "Spații pentru activitate",
        "Construcție, achiziție, extindere, modernizare sau renovare, conform condițiilor și excluderilor programului."
      ],
      [
        "Plan financiar sustenabil",
        "Corelează investiția cu creditul, contribuția proprie și fluxul de numerar până la acordarea grantului."
      ]
    ],
    "documents": [
      [
        "Identitate și legătura cu diaspora",
        "Acte de identitate, documente privind domiciliul sau reședința în străinătate și structura viitoarei societăți."
      ],
      [
        "Planul de investiții",
        "Buget pe categorii, oferte comparabile, calendar, amplasament și justificarea tehnică a achizițiilor."
      ],
      [
        "Dosarul financiar",
        "Contribuția proprie, ipotezele de venituri și cheltuieli, necesarul de credit și scenarii de rambursare."
      ],
      [
        "Dreptul asupra amplasamentului",
        "Acte de proprietate, închiriere sau concesiune și verificarea autorizărilor necesare activității."
      ]
    ],
    "steps": [
      "Documentează vechimea firmei, asociații din diaspora și experiența profesională.",
      "Construiește bugetul și verifică pragul contribuției proprii.",
      "Verifică publicarea listei băncilor partenere pe pagina BID.",
      "Depune cererea de credit la banca parteneră după operaționalizarea programului."
    ],
    "extraSources": [
      [
        "BID — criteriile aprobate și mecanismul programului",
        "https://www.bidromania.eu/centru-media/comunicate-de-presa/investitiile-romanilor-din-diaspora-intra-linie-dreapta-guvernul"
      ]
    ],
    "faqs": [
      [
        "Este deschisă depunerea?",
        "La verificarea din 6 septembrie 2026, BID indică programul în curs de operaționalizare. Cererile de credit vor fi primite de băncile partenere după publicarea listei și a documentelor operaționale."
      ],
      [
        "Grantul poate ajunge la 200.000 euro?",
        "Da, în limita a 60% din creditul de investiții și a plafonului de 200.000 euro. Grantul și garanția fac parte din mecanismul de minimis aplicabil."
      ],
      [
        "Trebuie să locuiesc încă în străinătate?",
        "Condiția BID acoperă domiciliul sau reședința actuală ori anterioară în străinătate: minimum 12 luni din ultimele 18 luni înaintea cererii de credit."
      ],
      [
        "Pot avea deja o firmă?",
        "Da, dacă firma are mai puțin de trei ani la data depunerii și îndeplinește cumulativ celelalte condiții."
      ],
      [
        "Este necesar un credit?",
        "Da. Finanțarea se acordă prin băncile partenere, iar grantul reduce ulterior soldul creditului."
      ],
      [
        "Cât timp păstrez investiția?",
        "Minimum trei ani de la finalizare. Se aplică și cerințe privind menținerea participației eligibile a asociaților din diaspora."
      ]
    ],
    "comparison": {
      "title": "Contribuția proprie: ce procent se aplică?",
      "headers": [
        "Valoarea proiectului",
        "Profil",
        "Minimum propriu"
      ],
      "rows": [
        [
          "Până la 400.000 EUR inclusiv",
          "Cel puțin un asociat majoritar eligibil sub 35 de ani",
          "5%"
        ],
        [
          "Până la 400.000 EUR inclusiv",
          "Celelalte situații eligibile",
          "10%"
        ],
        [
          "Peste 400.000 EUR",
          "Orice categorie eligibilă",
          "15%"
        ]
      ]
    }
  },
  "e-drive": {
    "h1": "e-DRIVE 2026 – finanțare pentru vehicule electrice M1, M2 și M3",
    "eyebrow": "Transport rutier · vehicule cu emisii zero",
    "lead": "Schema e-DRIVE explicată pe cele două măsuri: înlocuirea flotelor IMM-urilor și a vehiculelor operatorilor de transport rutier de persoane, cu plafoane și criterii diferite.",
    "metrics": [
      [
        "max. 30.000 €",
        "ajutor per vehicul M1 · măsura 1"
      ],
      [
        "max. 300.000 €",
        "plafon de minimis · întreprindere unică"
      ],
      [
        "max. 4 mil. €",
        "per beneficiar · măsura 2"
      ],
      [
        "56,9 mil. €",
        "buget total al schemei"
      ]
    ],
    "answer": "e-DRIVE este schema aprobată pentru înlocuirea vehiculelor poluante cu vehicule electrice noi. Măsura 1 se adresează microîntreprinderilor și IMM-urilor pentru vehicule M1 și M2, iar măsura 2 operatorilor de transport rutier de persoane pentru M1, M2 și M3. Bugetul total este de 56,9 milioane euro. Aprobarea schemei nu echivalează cu deschiderea depunerii.",
    "fit": [
      "Pentru măsura 1, ești microîntreprindere sau IMM și respecți sectoarele excluse de schema de minimis.",
      "Pentru măsura 2, desfășori transport rutier de persoane prin activitățile CAEN Rev. 3 prevăzute de schemă.",
      "Vehiculele propuse sunt noi și exclusiv electrice, iar vehiculele poluante înlocuite pot fi casate în termen."
    ],
    "caution": [
      "Vehiculele hibride și cele hibride reîncărcabile nu sunt vehicule cu emisii zero în sensul schemei.",
      "Vehiculul poluant înlocuit trebuie casat în maximum 60 de zile de la primirea vehiculului electric.",
      "TVA nu este eligibilă, iar ajutorul competitiv se raportează la diferența de cost față de alternativa convențională comparabilă."
    ],
    "investments": [
      [
        "Măsura 1 · de minimis",
        "Vehicule electrice noi M1 și M2, în limita a 300.000 euro pe întreprindere unică; pentru un vehicul M1, ajutorul este limitat la 30.000 euro."
      ],
      [
        "Măsura 2 · competitivă",
        "Vehicule electrice noi M1, M2 și M3 pentru transport rutier de persoane, cu maximum 4 milioane euro per beneficiar."
      ],
      [
        "Tranziția flotei",
        "Analiza include vehiculele scoase din uz, infrastructura de încărcare, asigurarea, mentenanța și exploatarea noii flote."
      ]
    ],
    "documents": [
      [
        "Eligibilitatea întreprinderii",
        "Certificat constatator, activitatea CAEN când măsura o cere, licențe și structura întreprinderii unice."
      ],
      [
        "Flota existentă",
        "Inventar, proprietate de minimum un an ori documentele excepției prevăzute de schemă, caracteristici tehnice și vehiculele propuse pentru casare."
      ],
      [
        "Configurația noii flote",
        "Minimum două oferte în condițiile schemei, categorie de omologare, autonomie, capacitate, garanții și calendar de livrare."
      ],
      [
        "Planul financiar",
        "Cost comparabil, ajutor solicitat, surse proprii, TVA neeligibilă și costurile operaționale neeligibile."
      ]
    ],
    "steps": [
      "Alege măsura după categoria beneficiarului, activitate și vehicule.",
      "Verifică încadrarea ca întreprindere unică și ajutoarele de minimis relevante.",
      "Corelează fiecare vehicul nou cu obligația de casare în 60 de zile și cu infrastructura de încărcare.",
      "Depune numai după publicarea calendarului și a procedurii operaționale."
    ],
    "extraSources": [
      [
        "Ordinul de modificare nr. 100/12.02.2026",
        "https://legislatie.just.ro/Public/DetaliiDocument/307361"
      ]
    ],
    "faqs": [
      [
        "Programul e-DRIVE este deschis?",
        "Schema este aprobată și actualizată, dar sursele verificate la 6 septembrie 2026 nu confirmă o fereastră activă de depunere. Aprobarea schemei nu echivalează cu lansarea sesiunii."
      ],
      [
        "Cine poate aplica la măsura 1?",
        "Microîntreprinderile și IMM-urile, indiferent de codul CAEN, cu respectarea sectoarelor excluse de schema de minimis și a tuturor condițiilor aplicabile."
      ],
      [
        "Sunt eligibile vehiculele hibride?",
        "Nu. Schema vizează vehicule noi exclusiv electrice; o ofertă hibridă nu este echivalentă."
      ],
      [
        "Care este plafonul de minimis?",
        "Măsura 1 folosește plafonul de 300.000 euro pe întreprindere unică; ajutorul pentru un vehicul M1 este limitat la 30.000 euro."
      ],
      [
        "Ce înseamnă măsura competitivă?",
        "În măsura 2, ajutorul se raportează la costul suplimentar față de un vehicul convențional comparabil și nu poate depăși 4 milioane euro pe beneficiar."
      ],
      [
        "Casarea este obligatorie?",
        "Da. Vehiculul poluant înlocuit trebuie casat în maximum 60 de zile de la primirea vehiculului cu emisii zero."
      ],
      [
        "Cât trebuie păstrată investiția?",
        "Vehiculele finanțate trebuie menținute în investiție timp de cinci ani, conform schemei."
      ],
      [
        "Se finanțează o mașină electrică pe firmă?",
        "Măsura 1 include vehicule M1 noi și exclusiv electrice pentru IMM-uri eligibile, cu maximum 30.000 EUR/vehicul, în limitele de minimis și cu obligația de înlocuire și casare. Nu orice achiziție auto este eligibilă."
      ],
      [
        "e-DRIVE finanțează și stații de încărcare?",
        "Schema e-DRIVE vizează vehiculele. Pentru infrastructura publică de reîncărcare verifică separat e-Mobility RO și condițiile sale de amplasare și racordare."
      ]
    ],
    "comparison": {
      "title": "e-DRIVE: măsura 1 sau măsura 2?",
      "headers": [
        "Criteriu",
        "Măsura 1 — de minimis",
        "Măsura 2 — competitivă"
      ],
      "rows": [
        [
          "Beneficiar",
          "Microîntreprinderi și IMM-uri, cu excluderile schemei",
          "Operatori eligibili de transport rutier de persoane"
        ],
        [
          "Vehicule",
          "M1 și M2, noi și exclusiv electrice",
          "M1, M2 și M3, noi și exclusiv electrice"
        ],
        [
          "Plafon",
          "30.000 EUR pentru M1; 300.000 EUR pe întreprindere unică",
          "4 milioane EUR/beneficiar"
        ],
        [
          "Baza de bugetare",
          "Ajutoarele de minimis cumulate și plafonul aplicabil vehiculului",
          "Diferența de cost față de alternativa convențională comparabilă"
        ],
        [
          "Casare",
          "În maximum 60 de zile de la primirea vehiculului electric",
          "În maximum 60 de zile de la primirea vehiculului electric"
        ]
      ]
    }
  },
  "e-mobility-ro": {
    "h1": "e-Mobility RO 2026 – finanțare pentru stații de reîncărcare",
    "eyebrow": "Infrastructură rutieră · reîncărcare electrică",
    "lead": "e-Mobility RO este prezentat ca proiect de infrastructură, nu ca simplă achiziție de stații: amplasamentul, racordarea, accesul public și configurația tehnică decid fezabilitatea.",
    "metrics": [
      [
        "299 mil. €",
        "bugetul schemei"
      ],
      [
        "max. 30 mil. €",
        "ajutor per beneficiar"
      ],
      [
        "max. 3 km",
        "pe șosea de o ieșire TEN-T"
      ],
      [
        "competitiv",
        "ajutorul se stabilește prin ofertare"
      ]
    ],
    "answer": "Schema e-Mobility RO susține infrastructură de reîncărcare de-a lungul autostrăzilor, drumurilor expres și drumurilor naționale ori în proximitatea admisă a ieșirilor rețelei TEN-T. Pot fi analizate și producția regenerabilă și stocarea asociate, dacă respectă limitele și legătura funcțională prevăzute de schemă.",
    "fit": [
      "Întreprinderea este eligibilă conform schemei și nu se află în situațiile de excludere.",
      "Ai un amplasament eligibil, cu drepturi clare și acces rutier demonstrabil.",
      "Poți documenta racordarea, puterea disponibilă, accesul public și funcționarea pe termen lung."
    ],
    "caution": [
      "O distanță mică față de un drum nu dovedește singură eligibilitatea amplasamentului.",
      "Întreprinderile nou-înființate sunt excluse de schema aprobată.",
      "Procentul de ajutor este rezultat al procedurii competitive și nu trebuie bugetat automat la maximum."
    ],
    "investments": [
      [
        "Stații și puncte de reîncărcare",
        "Echipamente, montaj, sisteme de plată, comunicații, semnalizare și lucrările strict legate de infrastructură."
      ],
      [
        "Racordare și lucrări",
        "Branșament, transformare, proiectare și lucrări necesare punerii în funcțiune, încadrate după regulile apelului."
      ],
      [
        "Regenerabile și stocare asociată",
        "Componentele asociate pot fi analizate doar în limitele tehnice și funcționale stabilite de schemă."
      ]
    ],
    "documents": [
      [
        "Amplasament și traseu",
        "Coordonate, extras de carte funciară, drept de folosință, acces din rețeaua rutieră și dovada distanței admise."
      ],
      [
        "Racordare",
        "Aviz sau studiu de soluție, putere disponibilă, lucrări, termene și riscuri de implementare."
      ],
      [
        "Soluția tehnică",
        "Număr de puncte, puteri, standarde, interoperabilitate, plată, operare și mentenanță."
      ],
      [
        "Modelul economic",
        "Trafic estimat, tarife, costuri, venituri, ofertă competitivă și sustenabilitatea după finalizare."
      ]
    ],
    "steps": [
      "Elimină amplasamentele care nu satisfac coridorul și accesul eligibil.",
      "Cere date de racordare înainte de a fixa bugetul și calendarul.",
      "Dimensionează stațiile după trafic și obligațiile tehnice, nu doar după plafon.",
      "Pregătește oferta competitivă după publicarea documentelor de depunere."
    ],
    "extraSources": [
      [
        "Schema e-Mobility RO – Portal Legislativ",
        "https://legislatie.just.ro/Public/DetaliiDocument/301593"
      ]
    ],
    "faqs": [
      [
        "e-Mobility RO este deschis pentru depuneri?",
        "Nu este prezentat ca apel deschis. Schema este aprobată, iar un calendar activ trebuie confirmat separat."
      ],
      [
        "Pot aplica firmele nou-înființate?",
        "Schema aprobată exclude întreprinderile nou-înființate; istoricul și situațiile financiare trebuie analizate."
      ],
      [
        "Unde poate fi amplasată stația?",
        "Pe drumurile eligibile din schemă sau la cel mult 3 km pe șosea de cea mai apropiată ieșire TEN-T. Distanța în linie dreaptă nu înlocuiește măsurarea pe șosea."
      ],
      [
        "Este eligibilă o baterie?",
        "Stocarea poate fi asociată infrastructurii în condițiile schemei; nu este tratată ca proiect stand-alone în această pagină."
      ],
      [
        "Ajutorul este 100%?",
        "Schema permite un maximum în procedura competitivă, însă solicitantul trebuie să își asume procentul rezultat și costurile neeligibile."
      ],
      [
        "Care este prima verificare tehnică?",
        "Amplasamentul și racordarea. Fără drept de folosință, acces eligibil și putere disponibilă, bugetul echipamentelor nu este suficient."
      ]
    ],
    "comparison": {
      "title": "e-Mobility RO: verificări tehnice înainte de buget",
      "headers": [
        "Cerință",
        "Regulă din schema actualizată"
      ],
      "rows": [
        [
          "Amplasament",
          "Drum eligibil sau cel mult 3 km pe șosea de cea mai apropiată ieșire TEN-T"
        ],
        [
          "Vehicule grele, rețea centrală TEN-T",
          "Minimum 3.600 kW total; cel puțin două puncte de minimum 350 kW fiecare"
        ],
        [
          "Vehicule grele, rețea globală TEN-T",
          "Minimum 1.500 kW total; cel puțin două puncte de minimum 350 kW fiecare"
        ],
        [
          "Excepții tehnice",
          "Art. 5 prevede și situații distincte; configurația exactă se verifică pentru fiecare amplasament"
        ],
        [
          "Stocare asociată",
          "Componenta de stocare absoarbe anual cel puțin 75% din energia produsă de instalația regenerabilă conectată direct"
        ],
        [
          "Plafon beneficiar",
          "30 milioane EUR; plafonul suplimentar de 40% din buget nu îl înlocuiește"
        ]
      ]
    }
  },
  "fondul-modernizare-pc1-stocare": {
    "eyebrow": "Fondul pentru Modernizare · Program-cheie 1",
    "lead": "Un cadru de pregătire pentru capacități noi de stocare stand-alone racordate la rețea, construit pe ghidul aprobat prin Ordinul Ministerului Energiei nr. 915/14.08.2026.",
    "metrics": [
      [
        "150 mil. €",
        "bugetul ghidului aprobat"
      ],
      [
        "max. 15 mil. €",
        "per întreprindere"
      ],
      [
        "69.000 €/MWh",
        "plafon al ajutorului"
      ],
      [
        "stand-alone",
        "stocare racordată la rețea"
      ]
    ],
    "answer": "Ghidul aprobat vizează investiții noi în capacități de stocare stand-alone conectate la rețea. Bugetul este de 150 milioane euro, ajutorul poate ajunge la 15 milioane euro pe întreprindere și este plafonat la 69.000 euro/MWh. Perioada și mecanismul operațional de depunere nu sunt încă anunțate.",
    "fit": [
      "Activitatea și structura solicitantului se încadrează în condițiile domeniului energetic.",
      "Proiectul este o capacitate de stocare stand-alone și are o soluție credibilă de racordare.",
      "Poți demonstra capacitatea financiară, drepturile asupra terenului și implementarea individuală a proiectului."
    ],
    "caution": [
      "Pagina nu descrie un apel deschis: ghidul este aprobat, dar calendarul depunerii nu este publicat.",
      "Plafonul pe MWh este o limită a ajutorului, nu o promisiune de finanțare la valoarea maximă.",
      "Racordarea, licențierea și veniturile din piața de energie necesită analiză separată."
    ],
    "investments": [
      [
        "Sisteme de baterii",
        "Echipamente noi de stocare, conversie, control, protecție și monitorizare, în condițiile ghidului aprobat."
      ],
      [
        "Lucrări și racordare",
        "Construcții, instalații și componente de racordare direct legate de punerea în funcțiune a capacității."
      ],
      [
        "Proiectare și integrare",
        "Studii și servicii tehnice eligibile numai dacă sunt prevăzute și încadrate corect în ghidul aprobat."
      ]
    ],
    "documents": [
      [
        "Societatea și activitatea",
        "Certificat constatator, CAEN, situații financiare ori capital social pentru solicitantul nou-înființat și declarații de eligibilitate."
      ],
      [
        "Teren și urbanism",
        "Drept real sau de folosință, certificat de urbanism, restricții, acces și calendarul autorizării."
      ],
      [
        "Racordare și capacitate",
        "Studiu de soluție, ATR sau stadiul acestuia, putere, capacitate MWh, cicluri și punctul de conexiune."
      ],
      [
        "Model financiar",
        "Cost pe MWh, oferte, surse proprii, scenarii de venit, sensibilități și costurile neeligibile."
      ]
    ],
    "steps": [
      "Fixează puterea și capacitatea numai după o analiză de racordare și piață.",
      "Verifică solicitantul, CAEN-ul și situația financiară în ghidul aprobat.",
      "Construiește un buget trasabil pe MWh și un calendar realist de autorizare.",
      "Revalidează eventualele corrigenda și calendarul înaintea unei decizii de investiție."
    ],
    "extraSources": [
      [
        "Cadrul Fondului pentru Modernizare – OUG nr. 60/2022",
        "https://legislatie.just.ro/Public/DetaliiDocument/294449"
      ]
    ],
    "faqs": [
      [
        "Apelul PC1 stocare este deschis?",
        "Nu. Ghidul final a fost publicat la 17 august 2026, dar la 29 august 2026 perioada și mecanismul operațional de depunere nu erau anunțate."
      ],
      [
        "Ce înseamnă stand-alone?",
        "Capacitatea de stocare este proiectată ca activ distinct conectat la rețea, nu doar ca anexă a unei centrale de producție pentru autoconsum."
      ],
      [
        "Pot aplica firme nou-înființate?",
        "Da, dacă îndeplinesc condițiile aplicabile din ghidul aprobat, inclusiv cerințele juridice și financiare prevăzute pentru această categorie."
      ],
      [
        "Finanțarea ajunge la 15 milioane euro?",
        "Da. Ghidul aprobat stabilește un plafon de maximum 15.000.000 euro pe întreprindere, în limita costului eligibil, a bugetului și a procedurii competitive."
      ],
      [
        "Este finanțarea 100%?",
        "Poate ajunge la maximum 100% conform ghidului aprobat, în limita costului eligibil și a competiției; costurile neeligibile și depășirile rămân în sarcina beneficiarului."
      ],
      [
        "Ce poate bloca proiectul?",
        "Lipsa unei soluții de racordare, drepturile insuficiente asupra terenului, calendarul de autorizare și un model economic neverificat sunt riscuri majore."
      ]
    ]
  }
};

function e(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderList(items) { return `<ul>${items.map((item) => `<li>${e(item)}</li>`).join("")}</ul>`; }
function renderCards(items) { return items.map(([title, text], index) => `<article class="program-card reveal" style="--delay:${index * 70}ms"><span class="program-card__number" aria-hidden="true">0${index + 1}</span><h3>${e(title)}</h3><p>${e(text)}</p></article>`).join(""); }
function renderDetails(items) { return items.map(([title, text]) => `<details class="program-detail"><summary>${e(title)}<span aria-hidden="true"></span></summary><div><p>${e(text)}</p></div></details>`).join(""); }

function renderSvg(slug) {
  const vehicle = slug === "e-drive" || slug === "e-mobility-ro";
  const diaspora = slug === "diaspora-investeste-acasa";
  return `<svg class="program-orbit" viewBox="0 0 520 360" role="img" aria-labelledby="${slug}-svg-title ${slug}-svg-desc">
    <title id="${slug}-svg-title">${diaspora ? "Traseul investiției din diaspora spre România" : vehicle ? "Ecosistem de mobilitate electrică" : "Sistem de stocare conectat la rețea"}</title>
    <desc id="${slug}-svg-desc">Ilustrație animată decorativă care rezumă traseul proiectului.</desc>
    <defs><linearGradient id="g-${slug}" x1="0" x2="1"><stop stop-color="#f5a623"/><stop offset="1" stop-color="#b84716"/></linearGradient></defs>
    <path class="orbit-path" d="M56 256 C120 70 390 48 468 190 C515 275 382 324 253 306 C145 292 98 234 126 158" fill="none" stroke="rgba(255,255,255,.24)" stroke-width="2" stroke-dasharray="8 12"/>
    <circle class="orbit-dot" cx="56" cy="256" r="9" fill="#f5a623"/><circle class="orbit-dot orbit-dot--two" cx="468" cy="190" r="9" fill="#f5a623"/>
    <rect x="153" y="111" width="216" height="146" rx="28" fill="rgba(255,255,255,.1)" stroke="rgba(255,255,255,.36)"/>
    <path d="M198 225h126M198 195h90M198 165h126" stroke="url(#g-${slug})" stroke-width="12" stroke-linecap="round"/>
    <path d="M343 145v78M323 184h40" stroke="#fff" stroke-width="9" stroke-linecap="round" opacity=".9"/>
  </svg>`;
}


function renderComparison(comparison, program) {
  if (!comparison) return '';
  return '<section class="program-section program-comparison" aria-label="' + e(comparison.title) + '"><div class="section-heading"><h2>' + e(comparison.title) + '</h2><p>Reguli verificate la ' + e(program.verifiedAt) + '. <a href="' + e(program.sourceUrl) + '" target="_blank" rel="noopener noreferrer">Consultă sursa oficială</a>.</p></div><div class="program-comparison-scroll" role="region" tabindex="0" aria-label="' + e(comparison.title) + '"><table><caption>' + e(comparison.title) + '</caption><thead><tr>' + comparison.headers.map(h=>'<th scope="col">'+e(h)+'</th>').join('') + '</tr></thead><tbody>' + comparison.rows.map(row=>'<tr>'+row.map((cell,i)=>i===0?'<th scope="row">'+e(cell)+'</th>':'<td>'+e(cell)+'</td>').join('')+'</tr>').join('') + '</tbody></table></div></section>';
}

function renderPage(program, content) {
  const canonical = `${SITE}${program.pageUrl}`;
  const faqSchema = content.faqs.map(([name, text]) => ({ "@type": "Question", name, acceptedAnswer: { "@type": "Answer", text } }));
  const schema = { "@context": "https://schema.org", "@graph": [
    { "@type": "WebPage", "@id": `${canonical}#webpage`, url: canonical, name: program.metaTitle, description: program.metaDescription, inLanguage: "ro-RO", dateModified: program.lastMeaningfulUpdate, isPartOf: { "@id": `${SITE}/#website` } },
    { "@type": "BreadcrumbList", itemListElement: [{ "@type": "ListItem", position: 1, name: "Acasă", item: `${SITE}/` }, { "@type": "ListItem", position: 2, name: "Fonduri europene", item: `${SITE}/fonduri-europene` }, { "@type": "ListItem", position: 3, name: program.shortName, item: canonical }] },
    { "@type": "FAQPage", mainEntity: faqSchema }
  ] };
  return `<!doctype html><html lang="ro"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${e(program.metaTitle)}</title><meta name="description" content="${e(program.metaDescription)}">
  <meta name="robots" content="index, follow"><meta name="seo-depth" content="true"><meta name="seo-min-words" content="700"><meta name="seo-min-faq" content="6">
  <link rel="canonical" href="${canonical}"><link rel="icon" href="/favicon.png">
  <meta property="og:type" content="website"><meta property="og:locale" content="ro_RO"><meta property="og:title" content="${e(program.metaTitle)}"><meta property="og:description" content="${e(program.metaDescription)}"><meta property="og:url" content="${canonical}"><meta property="og:image" content="${SITE}/og-image.jpg"><meta property="og:image:alt" content="${e(`${program.shortName} — FABER`)}">
  <meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="${e(program.metaTitle)}"><meta name="twitter:description" content="${e(program.metaDescription)}"><meta name="twitter:image" content="${SITE}/og-image.jpg"><meta name="twitter:image:alt" content="${e(`${program.shortName} — FABER`)}">
  <link rel="stylesheet" href="/assets/seo-hub.css"><link rel="stylesheet" href="/assets/program-showcase-2026.css?v=20260906-1">
  <script type="application/ld+json">${JSON.stringify(schema).replace(/</g, "\\u003c")}</script>
</head><body class="program-showcase-page page-family-program" data-page-type="program" data-program-id="${e(program.id)}">
${HEADER}
<main>
  <section class="program-hero" aria-labelledby="program-title">
    <div class="program-hero__content">
      <nav class="program-breadcrumbs" aria-label="Breadcrumb"><a href="/">Acasă</a><span>/</span><a href="/fonduri-europene">Programe</a><span>/</span><span aria-current="page">${e(program.shortName)}</span></nav>
      <p class="program-eyebrow">${e(content.eyebrow)}</p><h1 id="program-title">${e(content.h1 || program.name)}</h1><p class="program-lead">${e(content.lead)}</p>
      <div class="program-status" data-program-status="${e(program.status)}"><span aria-hidden="true"></span>${e(program.statusLabel)}</div>
      <div class="program-hero__actions"><a class="program-button program-button--primary" href="/contact#program_slug=${e(program.slug)}">Verifică proiectul</a><a class="program-button" href="#raspuns-rapid">Vezi condițiile</a></div>
    </div><div class="program-hero__visual">${renderSvg(program.slug)}</div>
  </section>
  <section class="program-metrics" aria-label="Repere de finanțare">${content.metrics.map(([value, label]) => `<div><strong>${e(value)}</strong><span>${e(label)}</span></div>`).join("")}</section>
  <section class="program-section program-section--answer" id="raspuns-rapid"><div><p class="section-kicker">Răspuns rapid</p><h2>Ce finanțează și în ce stadiu este?</h2></div><div class="answer-card"><p>${e(content.answer)}</p><small>Statut verificat la <time datetime="${program.verifiedAt}">${program.verifiedAt}</time>. ${e(program.editorialDisclaimer)}</small></div></section>
  ${renderComparison(content.comparison, program)}
  <section class="program-section program-section--fit"><div class="section-heading"><p class="section-kicker">Filtru inițial</p><h2>Merită continuată analiza?</h2><p>Compară profilul proiectului cu aceste criterii înainte de a investi în documentație. Concluzia finală se bazează pe actele solicitantului și pe forma oficială aplicabilă.</p></div><div class="program-fit-grid"><article class="fit-card fit-card--yes"><h3>Profil care merită verificat</h3>${renderList(content.fit)}</article><article class="fit-card fit-card--caution"><h3>Condiții care cer clarificare</h3>${renderList(content.caution)}</article></div></section>
  <section class="program-section program-section--soft"><div class="section-heading"><p class="section-kicker">Arhitectura proiectului</p><h2>Ce intră în analiza investiției</h2></div><div class="program-card-grid">${renderCards(content.investments)}</div></section>
  <section class="program-section program-section--documents"><div class="section-heading"><p class="section-kicker">Dosar de lucru</p><h2>Documente de pregătit</h2><p>Deschide fiecare grup și construiește o versiune trasabilă, cu dată, sursă și responsabil.</p></div><div class="program-details">${renderDetails(content.documents)}</div></section>
  <section class="program-section program-section--journey" data-program-journey-section><div class="section-heading"><p class="section-kicker">Parcurs recomandat</p><h2>De la idee la decizia de depunere</h2><p>Explorează etapele și verifică progresiv deciziile care susțin o depunere bine fundamentată.</p></div><div class="program-journey" data-program-journey style="--journey-progress:0"><svg class="program-journey__rail" data-journey-svg viewBox="0 0 100 100" preserveAspectRatio="xMinYMin meet" aria-hidden="true" focusable="false"><path class="program-journey__track" data-journey-track d="M 10 14 L 10 82" pathLength="1"></path><path class="program-journey__progress" data-journey-progress d="M 10 14 L 10 82" pathLength="1"></path></svg><ol class="program-steps">${content.steps.map((step, index) => `<li><button class="program-step" type="button" data-journey-step${index === 0 ? ` aria-current="step"` : ""} style="--step-index:${index}"><span class="program-step__number" aria-hidden="true">${index + 1}</span><span class="program-step__copy">${e(step)}</span></button></li>`).join("")}</ol><p class="program-journey__hint">Selectează un pas sau folosește tastele săgeată pentru a urmări traseul.</p></div></section>
  <section class="program-section program-section--source" id="surse-oficiale"><div><p class="section-kicker">Trasabilitate</p><h2>Surse oficiale și limitări</h2><p>Pagina consolidează actele disponibile, în limbaj propriu, și păstrează distinct statutul schemei de existența unei sesiuni de depunere.</p></div><div class="source-card"><a href="${e(program.sourceUrl)}" target="_blank" rel="noopener noreferrer"><strong>${e(program.sourceName)}</strong><span>${e(program.sourceVersion)}</span></a>${content.extraSources.map(([label, url]) => `<a href="${e(url)}" target="_blank" rel="noopener noreferrer"><strong>${e(label)}</strong><span>Deschide sursa instituțională</span></a>`).join("")}<p>Ultima verificare editorială: <time datetime="${program.verifiedAt}">${program.verifiedAt}</time>.</p></div></section>
  <section class="program-section program-section--faq"><div class="section-heading"><p class="section-kicker">Întrebări frecvente</p><h2>Clarificări înainte de pregătire</h2></div><div class="program-details">${renderDetails(content.faqs)}</div></section>
  <section class="program-final-cta"><div><p class="section-kicker">Următorul pas</p><h2>Verifică proiectul pe documente, nu doar pe promisiunea programului.</h2><p>Trimite profilul solicitantului, investiția, amplasamentul și bugetul. Primești o concluzie orientativă și lista neclarităților care trebuie rezolvate.</p></div><a class="program-button program-button--primary" href="/contact#program_slug=${e(program.slug)}&source_page=${encodeURIComponent(program.pageUrl)}">Începe verificarea</a></section>
</main>
<footer class="program-footer">© 2026 FABER – Atelier de Consultanță · <a href="/fonduri-europene">Toate programele</a> · <a href="/contact">Contact</a> · <a href="/politica-de-confidentialitate">Confidențialitate</a></footer>
<script src="/assets/program-showcase-2026.js?v=20260829-2" defer></script>
</body></html>`;
}

function renderSynchronizedPage(program, content) {
  const governed = synchronizeFaqHtml(synchronizedHtml(`${renderPage(program, content)}\n`, program.pageUrl)).html;
  return synchronizeCanonicalContact(governed, FOOTER_CONTACT);
}

function run({ check = false } = {}) {
  const bySlug = new Map(REGISTRY.map((program) => [program.slug, program]));
  const stale = [];
  for (const [slug, content] of Object.entries(PAGE_CONTENT)) {
    const program = bySlug.get(slug);
    if (!program || program.publicationState !== "public") throw new Error(`${slug}: program public lipsă din registru.`);
    const output = path.join(ROOT, program.pageUrl.slice(1), "index.html");
    const html = renderSynchronizedPage(program, content);
    if (check) {
      if (!fs.existsSync(output) || fs.readFileSync(output, "utf8") !== html) stale.push(path.relative(ROOT, output));
    } else {
      fs.mkdirSync(path.dirname(output), { recursive: true });
      fs.writeFileSync(output, html, "utf8");
    }
  }
  if (stale.length) throw new Error(`Pagini de program nesincronizate: ${stale.join(", ")}`);
  console.log(`${check ? "PASS" : "GENERATED"}: ${Object.keys(PAGE_CONTENT).length} pagini de program 2026 consolidate.`);
}

if (require.main === module) {
  try { run({ check: process.argv.includes("--check") }); }
  catch (error) { console.error(`FAIL: ${error.message}`); process.exitCode = 1; }
}

module.exports = { PAGE_CONTENT, renderPage, renderSynchronizedPage, run };
