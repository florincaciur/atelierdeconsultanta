#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const GLOBAL_HEADER = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8").trim();
const UPDATED = "2026-07-10";
const {
  SITE,
  breadcrumbItemsForPath,
  breadcrumbSchema,
  faqPageSchema,
  jsonLdGraph,
  organizationSchema,
  serviceSchema,
  webPageSchema,
  websiteSchema
} = require("./schema-helpers");

const pages = [
  {
    slug: "proiectare-fonduri-europene",
    title: "Proiectare fonduri europene: SF, DALI și planuri | FABER",
    description: "Servicii de proiectare pentru investiții finanțate din fonduri europene: studii de fezabilitate, DALI, memorii, bugete și coordonarea documentației.",
    h1: "Proiectare pentru investiții finanțate din fonduri europene",
    serviceType: "Proiectare și coordonare documentații tehnice pentru fonduri europene",
    minimumWords: 1200,
    quick: "Proiectarea pentru fonduri europene transformă ideea de investiție într-o soluție tehnică justificată, autorizabilă și corelată cu bugetul cererii de finanțare. FABER coordonează informațiile dintre beneficiar, consultant și proiectant, astfel încât studiul de fezabilitate, DALI-ul, memoriul, devizul și anexele să descrie aceeași investiție. Tipul documentației se stabilește în funcție de natura investiției, legislația aplicabilă și cerințele ghidului solicitantului.",
    checks: [
      "natura investiției și categoria de lucrări sau dotări",
      "dreptul asupra terenului, clădirii ori spațiului de implementare",
      "cerințele ghidului și anexele tehnice aplicabile",
      "maturitatea soluției, avizele și studiile disponibile",
      "corelarea devizului cu bugetul eligibil și neeligibil",
      "termenele reale pentru proiectare, autorizare și depunere"
    ],
    sections: [
      ["Ce înseamnă proiectarea pentru fonduri europene", [
        "Proiectarea pentru o investiție finanțată nu înseamnă doar realizarea unor planșe. Documentația trebuie să explice situația existentă, nevoia, soluția propusă, capacitățile, fluxurile, lucrările, dotările, indicatorii și costurile. În același timp, fiecare element trebuie să poată fi urmărit în cererea de finanțare. Dacă proiectantul descrie o soluție, iar consultantul bugetează alta, evaluatorul poate cere clarificări sau poate considera anumite cheltuieli insuficient justificate.",
        "Procesul începe printr-o temă de proiectare clară și prin verificarea documentelor beneficiarului. Se stabilesc amplasamentul, obiectivele, constrângerile, funcțiunile și rezultatele urmărite. Apoi se alege nivelul documentației cerut de legislație și de apel. Unele investiții au nevoie de studiu de fezabilitate, altele de DALI, memoriu justificativ, proiect tehnic ori documentații pentru avize. Nu toate programele solicită aceleași livrabile, iar condițiile finale se verifică în ghidul apelului activ."
      ]],
      ["Când este necesar studiul de fezabilitate", [
        "Studiul de fezabilitate este folosit, de regulă, pentru investiții noi sau pentru intervenții a căror soluție trebuie analizată înainte de proiectarea detaliată. El compară opțiuni, justifică varianta recomandată și prezintă caracteristicile tehnice, indicatorii, estimarea costurilor, etapele și riscurile. Rolul său este să arate că investiția poate fi realizată și exploatată în condițiile descrise, nu să promită aprobarea finanțării.",
        "Necesitatea unui SF se confirmă după verificarea naturii investiției, a regimului juridic al amplasamentului, a legislației tehnice și a cerințelor programului. Pentru o clădire nouă, o capacitate de producție, o rețea, o infrastructură publică sau o instalație energetică pot exista studii, avize și scenarii specifice. Consultantul verifică dacă informațiile din SF susțin obiectivele și indicatorii proiectului, iar proiectantul confirmă ipotezele tehnice și costurile. Orice diferență se corectează înainte de depunere."
      ]],
      ["Când este necesar DALI", [
        "Documentația de avizare a lucrărilor de intervenții este asociată intervențiilor asupra unor construcții existente, în situațiile prevăzute de cadrul aplicabil. DALI pornește de la starea construcției, expertizele sau studiile necesare și soluția de intervenție. El trebuie să descrie lucrările, etapele și costurile fără să ascundă degradări, restricții ori intervenții care pot schimba bugetul după depunere.",
        "Alegerea DALI nu se face doar pentru că proiectul include o clădire. Trebuie verificat dacă investiția este o intervenție asupra unui obiectiv existent, dacă sunt necesare expertize și dacă ghidul solicită un anumit nivel de maturitate. Devizul general, indicatorii și descrierea lucrărilor trebuie corelate cu cererea. Dacă apar lucrări obligatorii care nu au fost incluse, proiectul poate avea nevoie de actualizarea bugetului, de surse proprii suplimentare sau de reconsiderarea soluției."
      ]],
      ["Când este suficient un memoriu justificativ", [
        "Un memoriu justificativ poate fi adecvat pentru investiții cu o componentă tehnică mai redusă, pentru dotări sau pentru situațiile în care ghidul nu cere SF ori DALI. Memoriul trebuie totuși să explice problema, activitatea, capacitatea actuală, investiția propusă, modul de utilizare, amplasarea, rezultatele și necesitatea fiecărei cheltuieli. Un document scurt nu înseamnă un document vag.",
        "Înainte de a decide că un memoriu este suficient, se verifică lista de anexe, legislația aplicabilă și eventualele lucrări de instalare sau autorizare. Echipamentele pot impune alimentări, fundații, racorduri, ventilație, securitate, protecție la incendiu ori alte măsuri care trebuie bugetate. Dacă proiectul ascunde aceste dependențe, costurile pot apărea târziu și pot deveni neeligibile. Informațiile pot fi modificate de autoritatea finanțatoare, de aceea forma finală se confirmă în apelul activ."
      ]],
      ["Corelarea soluției tehnice cu cererea de finanțare", [
        "Cererea de finanțare și documentația tehnică trebuie să folosească aceeași logică. Obiectivele, activitățile, capacitățile, indicatorii și calendarul trebuie să poată fi urmărite din descriere până în planșe și devize. Dacă cererea promite creșterea unei capacități, soluția trebuie să arate cum este obținută și cu ce resurse. Dacă se solicită eficiență energetică, baza de calcul și echipamentele trebuie explicate.",
        "Corelarea se face printr-o matrice de verificare: obiectiv, activitate, element tehnic, document suport, cost și indicator. Consultantul semnalează condițiile de eligibilitate și punctaj, proiectantul confirmă fezabilitatea, iar beneficiarul validează nevoia și utilizarea reală. Această verificare reduce contradicțiile și ajută la pregătirea răspunsurilor la clarificări. Ea nu înlocuiește avizele și nu transformă o ipoteză tehnică într-o cheltuială eligibilă fără suportul ghidului."
      ]],
      ["Corelarea devizului cu bugetul proiectului", [
        "Devizul tehnic și bugetul cererii trebuie reconciliate la nivel de capitol, subcapitol și categorie de cheltuială. Valorile pot avea tratamente diferite în funcție de eligibilitate, TVA, limite, costuri indirecte sau contribuția beneficiarului. O poziție tehnic necesară poate fi neeligibilă; ea nu trebuie omisă, ci separată și asigurată dintr-o sursă realistă.",
        "Verificarea urmărește cantitățile, unitățile, ofertele, ipotezele de preț, lucrările conexe și rezervele. Bugetul nu se construiește prin rotunjiri menite să se încadreze într-un plafon, ci prin costuri explicabile. Dacă devizul se actualizează, se revizuiesc simultan cererea, indicatorii, graficul și sursele de finanțare. Condițiile finale se verifică în ghidul apelului activ, iar orice valoare comunicată înainte de acesta rămâne o estimare de lucru."
      ]],
      ["Documente tehnice pregătite înainte de depunere", [
        "Setul tehnic poate include tema de proiectare, ridicări, studii de teren, expertize, certificat de urbanism, avize, acorduri, planuri, memorii, SF, DALI, devize și documente privind dreptul de utilizare. Lista exactă depinde de investiție. Pentru echipamente sunt utile specificațiile funcționale, fluxul tehnologic, amplasarea și cerințele de instalare, fără a restrânge nejustificat concurența prin mărci sau modele.",
        "Documentele trebuie verificate și ca valabilitate, titular, adresă și coerență. Un act emis pentru alt beneficiar, o adresă diferită sau un drept insuficient poate bloca evaluarea ori contractarea. Este prudent ca beneficiarul să păstreze un registru al documentelor cu emitent, dată, termen și responsabil. Consultantul nu înlocuiește proiectantul sau autoritatea emitentă, dar poate organiza controlul de consistență al anexelor înainte de încărcare."
      ]],
      ["Coordonarea dintre consultant, proiectant și beneficiar", [
        "Beneficiarul definește nevoia și furnizează date reale despre activitate, amplasament și resurse. Proiectantul răspunde pentru soluția tehnică și documentația din competența sa. Consultantul traduce cerințele apelului într-o listă de verificări și urmărește coerența cu cererea. Colaborarea funcționează când deciziile și versiunile sunt documentate, iar schimbările sunt comunicate tuturor.",
        "Un calendar comun trebuie să includă studiile, avizele, bugetul, aprobările interne, reviziile și depunerea. Versiunea finală se blochează numai după o verificare încrucișată. Beneficiarul aprobă soluția pe care o poate implementa și cofinanța; proiectantul confirmă maturitatea; consultantul confirmă concordanța cu apelul disponibil. Niciun participant nu poate garanta evaluarea autorității, dar fiecare poate reduce riscurile din propria zonă."
      ]],
      ["Riscuri care pot genera neeligibilitatea cheltuielilor", [
        "Riscurile frecvente sunt începerea lucrărilor înainte de momentul permis, documentația incompletă, drepturi insuficiente asupra amplasamentului, costuri fără justificare, capacități supradimensionate, lucrări omise și neconcordanțe între deviz și cerere. Mai apar specificații restrictive, avize neobținute, indicatori imposibil de urmărit și termene care nu țin cont de autorizare sau achiziții.",
        "Controlul preventiv folosește întrebări simple: este elementul necesar, este permis, este documentat, este bugetat corect și poate fi implementat în termen? Un răspuns neclar nu se acoperă prin formulări generale. Se cere documentul, se ajustează soluția sau se separă costul neeligibil. Analiza inițială nu garantează finanțarea; scopul ei este să identifice problemele înainte ca ele să devină costuri sau obligații contractuale."
      ]],
      ["Etapele colaborării", [
        "Colaborarea începe cu datele beneficiarului și tema investiției. Urmează verificarea apelului, stabilirea documentației, colectarea actelor, studiile, soluția preliminară, estimarea costurilor și alegerea variantei. După această etapă se redactează și se corelează documentele, se face controlul intern, se aprobă versiunea finală și se pregătesc răspunsurile la eventualele clarificări.",
        "După depunere, orice schimbare trebuie evaluată înainte de a fi introdusă. O optimizare tehnică poate afecta indicatorii, bugetul sau eligibilitatea. După contractare se urmăresc condițiile contractului, proiectarea detaliată, achizițiile și actualizările aprobate. Pentru fiecare etapă se stabilesc responsabil, termen, document de intrare și livrabil. Această disciplină ajută proiectul să rămână implementabil, nu doar convingător în dosar."
      ]]
    ],
    faqs: [
      ["Toate programele cer studiu de fezabilitate?", "Nu. Documentația depinde de investiție, legislație și ghid. Unele proiecte cer SF, DALI sau alte documentații, iar altele pot folosi un memoriu și anexe tehnice."],
      ["Poate fi făcut bugetul înaintea proiectării?", "Se poate face o estimare, dar bugetul final trebuie corelat cu soluția, cantitățile, devizul și cerințele de instalare. Altfel pot lipsi costuri necesare."],
      ["Cine răspunde pentru soluția tehnică?", "Proiectantul răspunde pentru documentele și soluțiile din competența sa. Consultantul verifică raportarea lor la cererea de finanțare și la ghid."],
      ["Se pot modifica documentele după depunere?", "Clarificările și modificările sunt posibile numai în limitele procedurii aplicabile. O schimbare importantă poate afecta evaluarea, indicatorii sau eligibilitatea."],
      ["Ce trimit pentru o discuție inițială?", "Sunt utile descrierea investiției, amplasamentul, actele disponibile, bugetul estimat, programul urmărit, calendarul și datele despre solicitant."]
    ],
    links: ["/consultanta-fonduri-europene", "/studiu-fezabilitate-fonduri-europene", "/plan-de-afaceri-fonduri-europene", "/management-proiecte-fonduri-europene", "/programul-tranzitie-justa", "/contact"]
  },
  {
    slug: "studiu-fezabilitate-fonduri-europene",
    title: "Studiu de fezabilitate pentru fonduri europene | FABER",
    description: "Rolul studiului de fezabilitate în proiectele cu fonduri europene: soluții, deviz, indicatori, riscuri și corelarea cu cererea de finanțare.",
    h1: "Studiu de fezabilitate pentru proiecte cu fonduri europene",
    serviceType: "Studiu de fezabilitate și coordonare documentație de finanțare",
    minimumWords: 1000,
    quick: "Studiul de fezabilitate justifică o investiție, compară variantele și descrie soluția, costurile, indicatorii și condițiile de realizare. Pentru o cerere de finanțare, SF-ul trebuie corelat cu obiectivele, calendarul, bugetul și anexele beneficiarului. El nu este obligatoriu în orice apel și nu garantează eligibilitatea; necesitatea și conținutul se verifică în legislația aplicabilă și în ghidul programului activ.",
    checks: ["tipul investiției și nivelul de maturitate cerut", "actele amplasamentului și restricțiile existente", "studiile, expertizele și avizele necesare", "alternativele tehnice și criteriile de alegere", "devizul și sursele de finanțare", "indicatorii asumați prin proiect"],
    sections: [
      ["Rolul studiului de fezabilitate", ["Un studiu de fezabilitate răspunde la întrebarea dacă investiția poate fi realizată în condițiile tehnice, juridice, operaționale și financiare descrise. Documentul prezintă situația existentă, obiectivele, opțiunile analizate, soluția recomandată, costurile, calendarul și riscurile. Într-un proiect finanțat, rolul său este și mai precis: trebuie să ofere suport verificabil pentru afirmațiile din cererea de finanțare.", "SF-ul nu trebuie tratat ca o anexă scrisă separat. Consultantul și proiectantul compară indicatorii, capacitățile, activitățile și devizul cu formularul de finanțare. Dacă apar diferențe, se revizuiește documentația înainte de depunere. Condițiile finale se verifică în ghidul apelului activ, deoarece autoritatea poate cere modele, anexe sau niveluri de detaliu specifice."]],
      ["Datele de intrare și tema de proiectare", ["Calitatea studiului depinde de datele de intrare. Beneficiarul trebuie să clarifice amplasamentul, drepturile deținute, utilizarea actuală, nevoia, capacitatea dorită, fluxurile, utilitățile și limitele de buget. Tema de proiectare transformă aceste informații într-un set controlabil de cerințe și evită schimbările târzii.", "Se verifică documentele cadastrale, urbanistice, tehnice și organizaționale disponibile. Pentru investiții productive contează fluxul și relația dintre echipamente și lucrări; pentru infrastructură contează aria deservită și condițiile terenului; pentru energie contează consumul, racordarea și dimensionarea. Ipotezele neconfirmate se marchează, nu se prezintă ca fapte."]],
      ["Analiza variantelor", ["SF-ul trebuie să arate de ce a fost aleasă o soluție. Alternativele pot privi amplasarea, capacitatea, tehnologia, traseul, materialele, etapele sau modul de exploatare. Compararea nu este formală: criteriile trebuie să fie relevante pentru cost, durată, autorizare, consum, întreținere, impact și obiectivele programului.", "Varianta cu costul inițial cel mai mic nu este automat cea recomandată. O soluție ieftină poate genera costuri mari de operare, termene nerealiste sau riscuri de autorizare. Alegerea trebuie explicată astfel încât beneficiarul să o poată implementa și susține după finanțare. Dacă ghidul impune indicatori, ei se introduc în comparație fără a inventa valori."]],
      ["Devizul și bugetul cererii", ["Devizul traduce soluția în costuri. Fiecare capitol trebuie urmărit în buget, separat în eligibil și neeligibil conform regulilor apelului. TVA, lucrările conexe, organizarea, studiile, avizele și costurile neacoperite trebuie tratate explicit. O cheltuială tehnic necesară nu dispare dacă programul nu o finanțează.", "Controlul bugetar verifică unități, cantități, baze de preț și concordanța cu planurile. Modificarea unei capacități poate schimba echipamentele, lucrările, indicatorii și cash-flow-ul. De aceea, versiunea finală a devizului se reconciliază cu cererea înainte de depunere și din nou înainte de contractare, dacă procedura solicită actualizări."]],
      ["Indicatori și rezultate", ["Indicatorii trebuie să rezulte din soluția tehnică și să poată fi măsurați. Capacitatea, suprafața, consumul, numărul de echipamente, nivelul serviciului sau alte rezultate nu se aleg doar pentru punctaj. Ele trebuie susținute prin calcule, planuri și documente, apoi preluate identic în cerere și în anexele relevante.", "Un indicator prea optimist poate deveni obligație contractuală. Beneficiarul trebuie să înțeleagă cum va fi urmărit și ce resurse sunt necesare. Consultantul verifică legătura cu obiectivele apelului, iar proiectantul confirmă baza tehnică. Dacă metodologia autorității se schimbă, informațiile se actualizează conform documentelor oficiale."]],
      ["Avize, acorduri și maturitate", ["Studiul poate depinde de certificat de urbanism, avize, acorduri, studii de teren, expertize ori documente de mediu. Lista variază după investiție și amplasament. Unele documente sunt cerute la depunere, altele la contractare sau autorizare; calendarul proiectului trebuie să reflecte momentul real în care pot fi obținute.", "Maturitatea nu se măsoară doar prin numărul anexelor. Contează dacă soluția este stabilă, dacă restricțiile sunt cunoscute și dacă bugetul include consecințele lor. Un aviz cu condiții poate schimba traseul sau costurile. Registrul documentelor, cu responsabil și termen, reduce riscul ca o anexă expirată sau emisă pe alt titular să blocheze dosarul."]],
      ["Riscuri și sustenabilitate", ["SF-ul trebuie să descrie riscurile tehnice, juridice, de calendar, cost și operare. Ele pot include teren insuficient clarificat, utilități indisponibile, capacități supradimensionate, creșteri de preț, avize întârziate sau lipsa resurselor pentru exploatare. Măsurile propuse trebuie să fie realiste și bugetate când generează costuri.", "Sustenabilitatea privește funcționarea după finalizare: personal, mentenanță, consumuri, autorizări, venituri sau bugete publice. O investiție eligibilă pe hârtie poate fi dificil de operat. Analiza prudentă verifică dacă beneficiarul poate menține rezultatele și obligațiile, fără a promite finanțarea sau performanțe care nu sunt documentate."]],
      ["Corelarea cu cererea și controlul final", ["Înainte de depunere se face o verificare încrucișată între SF, cerere, buget, calendar, indicatori și anexele juridice. Se urmăresc denumirile, adresele, capacitățile, valorile și etapele. O matrice de coerență ajută la identificarea rapidă a contradicțiilor și la atribuirea corecțiilor.", "Versiunea finală trebuie aprobată de beneficiar și de specialiștii responsabili. Consultantul nu modifică soluția tehnică fără proiectant, iar proiectantul nu presupune eligibilitatea unei cheltuieli fără verificarea programului. Analiza inițială nu garantează finanțarea; ea reduce erorile care pot fi controlate înainte de evaluare."]]
    ],
    faqs: [["Este SF obligatoriu pentru orice proiect?", "Nu. Necesitatea depinde de investiție, legislație și ghidul apelului."], ["Cine întocmește studiul?", "Documentația este realizată de specialiștii competenți, iar consultantul urmărește corelarea cu cererea."], ["Devizul din SF este bugetul final?", "Este baza tehnică, dar categoriile eligibile și tratamentul lor se verifică separat în ghid."], ["Pot fi schimbate soluțiile după depunere?", "Numai în limitele procedurii și după evaluarea efectelor asupra indicatorilor, costurilor și aprobărilor."], ["Ce documente sunt necesare la început?", "Tema, actele amplasamentului, datele solicitantului, studiile existente, programul vizat și bugetul estimat."]],
    links: ["/proiectare-fonduri-europene", "/consultanta-fonduri-europene", "/plan-de-afaceri-fonduri-europene", "/management-proiecte-fonduri-europene", "/surse-oficiale-fonduri-europene"]
  },
  {
    slug: "plan-de-afaceri-fonduri-europene",
    title: "Plan de afaceri pentru fonduri europene | FABER",
    description: "Plan de afaceri pentru proiecte finanțate: model economic, piață, investiție, buget, indicatori, riscuri și corelarea cu ghidul apelului.",
    h1: "Plan de afaceri pentru proiecte finanțate",
    serviceType: "Elaborare și verificare plan de afaceri pentru fonduri europene",
    minimumWords: 1000,
    quick: "Planul de afaceri explică de ce este necesară investiția, cum va funcționa activitatea, ce resurse folosește și cum pot fi susținute ipotezele comerciale și financiare. Pentru fonduri europene, documentul trebuie corelat cu solicitantul, codul CAEN, bugetul, calendarul, ofertele și indicatorii apelului. Nu este o promisiune de venit și nu garantează finanțarea; scenariile trebuie documentate și testate prudent.",
    checks: ["activitatea și codul CAEN eligibil", "piața și clienții descriși prin surse", "capacitatea tehnică și resursele umane", "veniturile, costurile și ipotezele", "cofinanțarea și cash-flow-ul", "indicatorii și obligațiile programului"],
    sections: [
      ["Rolul planului de afaceri", ["Planul de afaceri leagă investiția de activitatea reală a solicitantului. El descrie problema, oportunitatea, clienții, concurența, procesele, echipa, resursele, costurile și rezultatele urmărite. Într-un proiect finanțat, fiecare ipoteză importantă trebuie să poată fi explicată prin date sau documente, nu prin formulări generale.", "Documentul nu este limitat la Start-Up Nation. El poate fi solicitat sau util în programe pentru IMM, agricultură, producție, servicii, digitalizare ori dezvoltare regională. Structura exactă se verifică în modelul apelului. Condițiile finale se verifică în ghidul apelului activ, iar planul se adaptează solicitantului și investiției, nu invers."]],
      ["Solicitant, activitate și obiective", ["Prima verificare privește solicitantul: forma juridică, istoricul, activitatea autorizată, locația, resursele și situația financiară. Obiectivele proiectului trebuie să pornească din nevoi reale și să fie compatibile cu activitatea. Un echipament sau un software nu este justificat doar pentru că apare într-o listă eligibilă.", "Obiectivele trebuie formulate astfel încât rezultatele să poată fi urmărite. Se evită promisiunile absolute și indicatorii fără bază. Pentru o firmă existentă se folosesc date istorice relevante; pentru o activitate nouă se explică sursele ipotezelor și etapele de lansare. Orice condiție de eligibilitate sau punctaj se verifică separat și se susține prin documentele cerute."]],
      ["Piață, clienți și concurență", ["Analiza pieței trebuie să arate cine cumpără, ce problemă rezolvă oferta, cum se ia decizia și ce alternative există. Sursele pot include statistici, rapoarte, date publice, interviuri sau experiența documentată a solicitantului. O listă de tendințe fără legătură cu localitatea, segmentul și capacitatea proiectului nu susține prognoza.", "Concurența se analizează prin ofertă, poziționare, preț, distribuție și diferențiatori verificabili. Planul nu trebuie să afirme că nu există concurenți doar pentru a părea atractiv. Dacă piața este aglomerată, se explică avantajul operațional sau comercial și resursele necesare. Datele variabile se datează și se revizuiesc înainte de depunere."]],
      ["Investiție, flux și capacitate", ["Lista de achiziții trebuie să rezulte din fluxul activității. Se explică ce face fiecare echipament, cum se integrează, ce capacitate are și ce condiții de instalare presupune. Pentru digitalizare se descriu procesele, utilizatorii, integrarea și securitatea; pentru producție se urmăresc materiile prime, etapele, controlul și depozitarea.", "Capacitatea planificată trebuie să fie compatibilă cu cererea estimată, personalul, spațiul și utilitățile. Supradimensionarea poate slăbi justificarea și crește cofinanțarea. Subdimensionarea poate face indicatorii imposibili. Consultantul corelează planul cu ofertele și documentația tehnică, iar beneficiarul confirmă că soluția poate fi exploatată după proiect."]],
      ["Buget și cofinanțare", ["Bugetul include grantul estimat, contribuția proprie, cheltuielile neeligibile, TVA unde este cazul și costurile operaționale din perioada de implementare. Planul trebuie să arate de unde provin resursele și când sunt necesare. Aprobarea nu elimină nevoia de cash-flow pentru plăți, rambursări, diferențe de preț sau costuri neacoperite.", "Valorile se construiesc pe oferte, devize și ipoteze documentate. Nu se adaptează artificial cheltuielile pentru a consuma plafonul. Dacă o achiziție nu poate fi justificată prin obiective și flux, ea trebuie reconsiderată. Intensitățile, limitele și regulile finale se verifică în ghidul apelului activ, fără a transfera automat condițiile unui program către altul."]],
      ["Prognoze financiare prudente", ["Prognoza pornește de la volum, preț, ritm de creștere, sezonalitate, capacitate și termene de încasare. Costurile includ materiile, personalul, utilitățile, mentenanța, marketingul, taxele și finanțarea. Scenariul de bază trebuie să poată fi reconstituit, iar un scenariu prudent arată efectul întârzierilor sau al vânzărilor mai mici.", "Planul nu garantează venituri. El testează dacă activitatea poate susține funcționarea și obligațiile proiectului. Pentru o firmă existentă, diferențele față de istoricul financiar se explică. Pentru un start-up, ipotezele se leagă de pași concreți de intrare pe piață. Orice procent sau valoare specifică apelului rămâne condiționată de documentele oficiale."]],
      ["Echipă și implementare", ["Planul descrie rolurile necesare, competențele existente, recrutarea și responsabilitățile. Numărul de persoane trebuie corelat cu volumul de activitate și cu indicatorii asumați. Dacă proiectul presupune autorizări, formare sau certificări, acestea se includ în calendar și în buget când sunt relevante.", "Implementarea acoperă achizițiile, livrarea, instalarea, testarea, lansarea și raportarea. Termenele trebuie să țină cont de proceduri și dependențe. Beneficiarul rămâne responsabil pentru decizii și documente, consultantul urmărește cerințele finanțării, iar furnizorii trebuie să livreze în condițiile contractate. Schimbările se evaluează înainte de aplicare."]],
      ["Riscuri, indicatori și control final", ["Riscurile pot veni din piață, costuri, întârzieri, personal, autorizare, tehnologie sau cofinanțare. Pentru fiecare risc se stabilește probabilitatea, impactul și măsura realistă. Indicatorii din plan trebuie să fie identici cu cei din cerere și să poată fi măsurați pe perioada de implementare și monitorizare.", "Controlul final verifică title-ul programului, solicitantul, CAEN-ul, adresa, valorile, ofertele, calendarul, prognozele și anexele. Se elimină contradicțiile și promisiunile fără suport. Analiza inițială nu garantează finanțarea; verificăm eligibilitatea pe baza informațiilor transmise și a ghidurilor disponibile."]]
    ],
    faqs: [["Planul de afaceri este doar pentru start-up-uri?", "Nu. Poate fi necesar sau util și pentru firme existente, ferme, investiții regionale, digitalizare și alte programe."], ["Pot folosi același plan la mai multe apeluri?", "Conținutul de bază poate ajuta, dar structura, criteriile, bugetul și indicatorii trebuie adaptate fiecărui apel."], ["Cine stabilește prognozele?", "Beneficiarul furnizează ipotezele reale, iar consultantul le structurează și verifică pentru coerență și documentare."], ["Planul garantează punctajul?", "Nu. Punctajul depinde de grila, documentele, evaluarea și bugetul programului."], ["Ce trimit pentru început?", "Datele firmei, activitatea, investiția, ofertele, piața vizată, echipa, bugetul și programul urmărit."]],
    links: ["/consultanta-fonduri-europene", "/proiectare-fonduri-europene", "/studiu-fezabilitate-fonduri-europene", "/management-proiecte-fonduri-europene", "/contact"]
  },
  {
    slug: "management-proiecte-fonduri-europene",
    title: "Management proiecte cu fonduri europene | FABER",
    description: "Management pentru proiecte cu fonduri europene: contractare, achiziții, cereri de plată, monitorizare, modificări, indicatori și obligații.",
    h1: "Managementul proiectelor finanțate din fonduri europene",
    serviceType: "Management și implementare proiecte cu fonduri europene",
    minimumWords: 1000,
    quick: "Managementul unui proiect finanțat urmărește transformarea contractului și a cererii aprobate într-o investiție implementată, documentată și raportată corect. Activitatea poate include planificare, achiziții, monitorizarea livrabilelor, cereri de plată sau rambursare, clarificări, modificări și arhivare. Beneficiarul păstrează responsabilitatea deciziilor și obligațiilor; consultantul sprijină controlul documentelor și al termenelor fără a garanta acceptarea cheltuielilor.",
    checks: ["contractul și anexele aprobate", "calendarul activităților și achizițiilor", "bugetul și sursele de cash-flow", "regulile de achiziție și conflict de interese", "documentele pentru plată și indicatori", "obligațiile de informare, monitorizare și durabilitate"],
    sections: [
      ["De la aprobare la contractare", ["Aprobarea proiectului nu este finalul procesului. Înainte de contractare se verifică forma proiectului acceptat, condițiile speciale, documentele actualizate, sursa cofinanțării și termenele. Orice diferență față de cererea depusă trebuie înțeleasă și tratată prin procedura permisă, nu presupusă ca fiind acceptată.", "Beneficiarul trebuie să cunoască obligațiile pe care le semnează: indicatori, perioadă de implementare, achiziții, raportări, publicitate, menținerea investiției și condițiile de plată. Consultantul poate organiza lista de documente și întrebări, dar decizia contractuală și exactitatea informațiilor aparțin beneficiarului. Condițiile finale se verifică în contract și în ghidul apelului activ."]],
      ["Planul de implementare", ["Planificarea transformă activitățile aprobate într-un calendar cu dependențe, responsabili și livrabile. Se includ proiectarea, avizele, achizițiile, livrările, lucrările, instalarea, testarea, recrutarea, raportarea și plățile. O întârziere într-o etapă poate afecta toate activitățile următoare, de aceea se stabilesc puncte de control și rezerve realiste.", "Planul financiar trebuie sincronizat cu planul tehnic. Beneficiarul verifică momentele în care plătește furnizorii, când poate solicita rambursarea și ce resurse proprii sunt necesare. Nu se presupune că grantul este disponibil înaintea procedurii aplicabile. Orice termen oficial poate fi modificat numai prin mecanismul prevăzut de finanțator."]],
      ["Achiziții și trasabilitate", ["Achizițiile trebuie pregătite pe baza regulilor aplicabile beneficiarului și programului. Specificațiile descriu necesitatea și performanța fără restricții nejustificate. Dosarul achiziției păstrează justificarea, invitațiile sau publicitatea, ofertele, evaluarea, declarațiile, contractul, livrarea și plata, astfel încât decizia să poată fi urmărită.", "Conflictele de interese, divizarea artificială, criteriile schimbate și documentele incomplete pot genera corecții. Consultantul poate folosi liste de control, însă beneficiarul și persoanele desemnate răspund pentru procedură. Înainte de lansare se verifică bugetul aprobat, specificațiile, calendarul și eventualele condiții de autorizare sau proiectare."]],
      ["Livrare, recepție și documente", ["Recepția nu se reduce la o factură. Se verifică obiectul contractului, cantitatea, seria, configurația, lucrările, testele, instruirea, garanția și documentele tehnice. Pentru servicii se confirmă livrabilele și acceptarea lor; pentru lucrări se folosesc documentele prevăzute de contract și de cadrul tehnic.", "Diferențele dintre oferta selectată, contract, livrare și cererea de plată trebuie clarificate înainte de raportare. O denumire schimbată poate fi banală sau poate ascunde o modificare de caracteristici; evaluarea se face pe documente. Dovezile se arhivează într-o structură stabilă, cu versiuni și responsabil, pentru control și monitorizare."]],
      ["Cereri de plată și rambursare", ["Dosarul financiar leagă contractul, factura, dovada livrării, recepția, plata și înregistrarea contabilă de linia bugetară aprobată. În funcție de mecanism pot exista cereri de plată, prefinanțare sau rambursare. Lista exactă de documente se verifică în contract, manual și instrucțiunile autorității.", "Cheltuiala nu devine eligibilă doar pentru că a fost plătită. Trebuie să fie prevăzută, necesară, realizată în perioada permisă și susținută prin procedura corectă. Consultantul verifică dosarul, iar beneficiarul confirmă realitatea operațiunii și evidența contabilă. Informațiile pot fi modificate de autoritatea finanțatoare."]],
      ["Monitorizare, indicatori și raportare", ["Indicatorii se urmăresc de la început, nu doar la raportul final. Pentru fiecare indicator se stabilește definiția, baza de calcul, sursa dovezii, responsabilul și momentul măsurării. Activitățile și rezultatele se documentează periodic, iar abaterile sunt analizate înainte să pună în pericol obligațiile contractuale.", "Raportarea trebuie să fie coerentă cu cererea aprobată și cu situația reală. Nu se raportează rezultate care nu pot fi demonstrate. Dacă un indicator devine dificil de atins, beneficiarul verifică imediat opțiunile procedurale și impactul. Consultantul poate pregăti explicația și documentele, dar autoritatea decide acceptarea."]],
      ["Modificări și clarificări", ["În implementare pot apărea schimbări de preț, furnizor, calendar, caracteristici, amplasare sau soluție. Înainte de aplicare se verifică dacă modificarea este permisă, dacă necesită notificare sau act adițional și dacă afectează obiectivele, indicatorii, concurența ori eligibilitatea. Implementarea întâi și justificarea după este un risc major.", "Registrul modificărilor păstrează motivul, documentele, analiza impactului, aprobarea internă și răspunsul autorității. Clarificările trebuie să fie factuale și să folosească aceleași versiuni ale documentelor. O explicație nu poate înlocui un act lipsă, iar o modificare tehnică nu trebuie prezentată ca simplă corecție dacă schimbă investiția."]],
      ["Informare, arhivare și durabilitate", ["Proiectele pot avea obligații privind identitatea vizuală, informarea publică, păstrarea documentelor și accesul la control. Materialele, fotografiile, anunțurile și dovezile se arhivează conform cerințelor. Datele personale și informațiile comerciale se gestionează prudent, fără a încărca în rapoarte elemente care nu sunt cerute.", "După finalizare urmează perioada de monitorizare sau durabilitate. Beneficiarul menține investiția, destinația, indicatorii și documentele conform contractului. Vânzarea, relocarea, înlocuirea sau schimbarea activității se analizează înainte. Managementul bun pregătește această perioadă încă din proiectare și bugetare."]],
      ["Control intern și responsabilități", ["O matrice de responsabilități clarifică cine aprobă, cine verifică și cine păstrează fiecare document. Beneficiarul conduce proiectul și răspunde pentru realitatea operațiunilor. Proiectantul, furnizorii, contabilul și consultantul au roluri distincte. Lipsa delimitării produce întârzieri și documente contradictorii.", "Controalele periodice verifică bugetul, termenele, achizițiile, livrările, plățile, indicatorii și riscurile. Problemele se înregistrează cu termen și responsabil. Sprijinul de management nu garantează acceptarea unei cheltuieli sau a unei modificări; el oferă un proces verificabil pentru decizii și raportare."]]
    ],
    faqs: [["Managementul începe după contractare?", "Pregătirea începe înainte, prin înțelegerea obligațiilor, planificare și verificarea resurselor."], ["Consultantul poate semna în locul beneficiarului?", "Numai dacă există un mandat legal și procedura permite; responsabilitățile beneficiarului nu dispar."], ["Orice factură aprobată intern este eligibilă?", "Nu. Eligibilitatea depinde de contract, perioadă, achiziție, livrare și documentele programului."], ["Pot schimba furnizorul sau echipamentul?", "Schimbarea se analizează înainte și se urmează procedura de notificare sau aprobare aplicabilă."], ["Ce documente trimit pentru preluarea implementării?", "Contractul, cererea și bugetul aprobate, corespondența, achizițiile, plățile, calendarul și situația indicatorilor."]],
    links: ["/consultanta-fonduri-europene", "/proiectare-fonduri-europene", "/studiu-fezabilitate-fonduri-europene", "/plan-de-afaceri-fonduri-europene", "/contact"]
  }
];

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function schemaFor(page) {
  const url = `${SITE}/${page.slug}`;
  const pageNode = webPageSchema({
    url,
    name: page.title,
    description: page.description,
    datePublished: UPDATED,
    dateModified: UPDATED
  });
  pageNode.mainEntity = { "@id": `${url}#service` };
  return jsonLdGraph([
    organizationSchema(),
    websiteSchema(),
    pageNode,
    serviceSchema({
      url,
      name: page.h1,
      description: page.description,
      serviceType: page.serviceType
    }),
    breadcrumbSchema(breadcrumbItemsForPath(`/${page.slug}`, page.h1)),
    faqPageSchema(page.faqs, { minItems: 2 })
  ]).replace(/</g, "\\u003c");
}

function renderPage(page) {
  const url = `${SITE}/${page.slug}`;
  const sections = page.sections.map(([heading, paragraphs]) => `
      <section>
        <h2>${escapeHtml(heading)}</h2>
        ${paragraphs.map((paragraph) => `<p>${escapeHtml(paragraph)}</p>`).join("\n        ")}
      </section>`).join("\n");
  const faqs = page.faqs.map(([question, answer]) => `<section class="faq-item"><h3>${escapeHtml(question)}</h3><p>${escapeHtml(answer)}</p></section>`).join("\n        ");
  const links = page.links.map((href) => `<a href="${href}">${escapeHtml(href.slice(1).replace(/-/g, " "))}</a>`).join("\n        ");
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(page.title)}</title>
  <meta name="description" content="${escapeHtml(page.description)}">
  <meta name="robots" content="index, follow">
  <meta name="seo-depth" content="true">
  <meta name="seo-min-words" content="${page.minimumWords}">
  <meta name="seo-min-faq" content="5">
  <link rel="canonical" href="${url}">
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <meta property="og:title" content="${escapeHtml(page.title)}">
  <meta property="og:description" content="${escapeHtml(page.description)}">
  <meta property="og:url" content="${url}">
  <meta property="og:type" content="website">
  <meta property="og:image" content="${SITE}/og-image.jpg">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="stylesheet" href="/assets/seo-hub.css">
  <link rel="preload" as="style" href="/assets/see-also.css" onload="this.onload=null;this.rel='stylesheet'">
  <noscript><link rel="stylesheet" href="/assets/see-also.css"></noscript>
  <link rel="stylesheet" href="/assets/design-profiles.css">
  <script type="application/ld+json">${schemaFor(page)}</script>
  <script src="/assets/analytics-events.js" defer></script>
</head>
<body class="page-family-service">
  ${GLOBAL_HEADER}
  <div class="breadcrumb"><a href="/">Acasă</a> / <a href="/consultanta-fonduri-europene">Consultanță</a> / ${escapeHtml(page.h1)}</div>
  <header class="hero hero--image hero--service" data-design-family="service" style="--hero-image:url('/assets/hero/hero-business.webp')">
    <span class="hero-icon" aria-hidden="true"><i class="ph-duotone ph-ruler"></i></span>
    <span class="eyebrow design-badge design-badge--service">Serviciu FABER | analiză | documentație</span>
    <h1>${escapeHtml(page.h1)}</h1>
    <p>${escapeHtml(page.description)}</p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="/contact">Discută cu un consultant</a>
      <a class="btn btn-secondary" href="/consultanta-fonduri-europene">Vezi consultanța</a>
    </div>
    <div class="hero-summary" aria-label="Repere pentru ${escapeHtml(page.h1)}">
      <span class="hero-summary__item"><strong>Beneficiari</strong><em>firme, fermieri, organizații și instituții publice</em></span>
      <span class="hero-summary__item"><strong>Documente</strong><em>stabilite după investiție și ghid</em></span>
      <span class="hero-summary__item"><strong>Control</strong><em>coerență între soluție, buget și cerere</em></span>
      <span class="hero-summary__item"><strong>Prudență</strong><em>fără promisiuni de aprobare</em></span>
    </div>
  </header>
  <main class="container">
    <article class="panel">
      <section aria-labelledby="raspuns-rapid">
        <h2 id="raspuns-rapid">Răspuns rapid</h2>
        <p class="intro">${escapeHtml(page.quick)}</p>
      </section>
      <section aria-labelledby="ce-trebuie-verificat">
        <h2 id="ce-trebuie-verificat">Ce trebuie verificat</h2>
        <ul>${page.checks.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
      </section>
      <section class="editorial-meta" aria-label="Metadate editoriale">
        <div class="editorial-meta__header"><p class="editorial-meta__eyebrow">Transparență editorială</p><span class="editorial-meta__status" data-status="actualizat">Actualizat</span></div>
        <dl class="editorial-meta__grid"><div><dt>Autor</dt><dd>FABER – Atelier de Consultanță</dd></div><div><dt>Ultima actualizare</dt><dd><time datetime="${UPDATED}">10 iulie 2026</time></dd></div></dl>
        <p class="editorial-meta__note">Informațiile pot fi modificate de autoritatea finanțatoare; condițiile finale se verifică în ghidul apelului activ.</p>
      </section>
      ${sections}
      <section class="faq" aria-labelledby="faq-title">
        <h2 id="faq-title">Întrebări frecvente</h2>
        ${faqs}
      </section>
      <section>
        <h2>Servicii și resurse asociate</h2>
        <p>Continuă cu serviciul sau documentația potrivită etapei proiectului. Linkurile de mai jos folosesc direct rutele canonice și oferă context despre eligibilitate, proiectare, planificare și implementare.</p>
        <div class="related-links">${links}</div>
      </section>
    </article>
    <section class="cta-box" aria-labelledby="cta-title">
      <h2 id="cta-title">Discută cu un consultant</h2>
      <p>Trimite datele proiectului, investiția, amplasamentul, bugetul estimat, documentele existente și programul urmărit. Analiza inițială nu garantează finanțarea.</p>
      <div class="cta-actions"><a class="btn btn-primary" href="/contact">Trimite detaliile proiectului</a><a class="btn btn-secondary" href="/metodologie-verificare-eligibilitate">Vezi metodologia</a></div>
    </section>
  </main>
  <footer class="footer">© 2026 FABER – Atelier de Consultanță · <a href="/fonduri-europene">Fonduri europene</a> · <a href="/contact">Contact</a></footer>
</body>
</html>\n`;
}

function wordCount(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&[a-z0-9#]+;/gi, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean).length;
}

for (const page of pages) {
  const html = renderPage(page);
  const words = wordCount(html);
  if (words < page.minimumWords) {
    throw new Error(`${page.slug}: ${words} words; minimum ${page.minimumWords}`);
  }
  const output = path.join(ROOT, page.slug, "index.html");
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, html, "utf8");
  console.log(`${page.slug}: ${words} words`);
}
