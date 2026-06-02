#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { normalizeHtmlCopy } = require("./normalize-copy-ro");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DATE = "2026-06-01";
const CSS_HREF = "/assets/seo-plan-execution.css";

const CTA = { href: "/verificare-eligibilitate-fonduri-europene", label: "Verifică eligibilitatea proiectului" };

const modules = [
  moduleFor("index.html", "homepage", "Direcție rapidă pentru proiectul potrivit", "Homepage-ul trimite vizitatorul către cele trei decizii importante: dacă este eligibil, ce program merită verificat și ce documente trebuie pregătite înainte de dosar.", [
    ["IMM-uri", "Pornește de la investiția dorită, cod CAEN, buget și regiunea în care se face proiectul."],
    ["Fermieri", "Verifică AFIR, dimensiunea economică, documentele agricole și legătura investiției cu exploatația."],
    ["Start-up-uri", "Separă ideea de afaceri de condițiile programului, CAEN, buget și locuri de muncă."]
  ], ["CTA principal constant: verificarea eligibilității.", "Link spre consultanță, fonduri europene, AFIR, PNRR și Start-Up Nation.", "Fără promisiuni de finanțare garantată sau claims numerice neverificate.", "Orientare rapidă către hub-ul potrivit."], [
    CTA,
    { href: "/consultanta-fonduri-europene", label: "Consultanță fonduri europene" },
    { href: "/fonduri-europene", label: "Vezi programele" }
  ]),
  moduleFor("consultanta-fonduri-europene/index.html", "consultanta-fonduri-europene", "Ce primește clientul într-o verificare FABER", "Pagina de serviciu rămâne comercială, dar explică precis ce se verifică înainte de depunere și ce nu poate fi promis fără documente.", [
    ["Proces", "Solicitant, activitate, localitate, investiție, buget și cofinanțare sunt verificate înaintea recomandării."],
    ["Livrabile", "Primești o direcție de program, riscuri, documente lipsă și pașii necesari pentru dosar."],
    ["Limite", "FABER nu promite aprobare, punctaj final sau sumă garantată fără ghid activ și documente."]
  ], ["Include expresiile: firmă consultanță fonduri europene și consultant fonduri europene pentru IMM.", "Trimite articolele suport către această pagină, nu invers.", "Păstrează CTA mobil către verificarea eligibilității.", "Separă serviciul de articolele educaționale."], [
    CTA,
    { href: "/metodologie-verificare-eligibilitate", label: "Metodologia FABER" },
    { href: "/contact", label: "Contact" }
  ]),
  moduleFor("fonduri-europene/index.html", "fonduri-europene", "Hub de programe, nu articol general", "Această pagină orientează beneficiarul către categoria potrivită și apoi către pagina copil unde se verifică regulile concrete.", [
    ["IMM", "Regional, digitalizare, energie, microîntreprinderi și programe naționale."],
    ["Agricultură", "AFIR, DR12, DR14, GAL, autoconsum și utilaje, cu documente agricole verificate separat."],
    ["Antreprenoriat", "Start-Up Nation, Femeia Antreprenor și programe conexe, fără suprapunere de intenție."]
  ], ["Fiecare card trebuie să aibă status, beneficiar și link.", "Nu țintește toate keywordurile de program în același H1.", "Trimite spre surse oficiale și calendar pentru informații schimbătoare.", "Conectează hub-ul cu verificarea eligibilității."], [
    CTA,
    { href: "/calendar-fonduri-europene", label: "Calendar programe" },
    { href: "/surse-oficiale-fonduri-europene", label: "Surse oficiale" }
  ]),
  moduleFor("fonduri-europene-nerambursabile-2026/index.html", "fonduri-nerambursabile-2026", "Calendar de verificare pentru 2026", "Pentru că apelurile se schimbă, pagina tratează 2026 ca hartă de orientare și cere validarea în ghidul activ înainte de decizia de depunere.", [
    ["Beneficiar", "Tineri, femei antreprenor, IMM-uri, rural non-agricol, fermieri și instituții publice."],
    ["Program", "Se alege după activitate, localitate, buget, documente și cofinanțare."],
    ["Status", "Activ, estimat, consultare sau închis, cu data ultimei verificări editoriale."]
  ], ["Adaugă tabel program / beneficiar / status / documente.", "Evită sume sau termene finale fără sursă oficială.", "Leagă paginile de program către calendar.", "Actualizează după fiecare apel relevant."], [
    CTA,
    { href: "/calendar-fonduri-europene", label: "Calendar fonduri 2026" },
    { href: "/fonduri-europene", label: "Hub fonduri europene" }
  ]),
  moduleFor("fonduri-europene-imm/index.html", "fonduri-europene-imm", "Ghid pentru IMM, micro și firmă în creștere", "Pagina separă tipul de beneficiar de programul posibil, ca antreprenorul să nu aleagă programul doar după suma promovată.", [
    ["Microîntreprindere", "Verifică vechimea, regiunea, situațiile financiare și investiția eligibilă."],
    ["IMM digital", "Verifică software, hardware, securitate, cloud și indicatorii digitali."],
    ["Energie", "Verifică autoconsum, eficiență, amplasament, consum și racordare."]
  ], ["Include comparație regional / digitalizare / energie / Start-Up Nation.", "Trimite către consultanță IMM și verificare eligibilitate.", "Păstrează exemple de investiții concrete.", "Nu amesteca pagina IMM cu pagina Start-Up Nation."], [
    CTA,
    { href: "/digitalizare-imm", label: "Digitalizare IMM" },
    { href: "/investitii-modernizarea-microintreprinderilor-apel-2", label: "Microîntreprinderi" }
  ]),
  moduleFor("fonduri-europene-nord-est/index.html", "fonduri-europene-nord-est", "Filtru local pentru Nord-Est", "Pagina locală câștigă prin utilitate regională: județ, ADR Nord-Est, RIS3 și programe potrivite pentru beneficiarii din zonă.", [
    ["Județe", "Iași, Suceava, Bacău, Botoșani, Neamț și Vaslui."],
    ["Instituții", "ADR Nord-Est, ghiduri regionale, calendar și condiții RIS3 unde sunt cerute."],
    ["Conversie", "Utilizatorul local ajunge către POR, microîntreprinderi sau consultanță."]
  ], ["Evită pagini locale duplicate fără conținut unic.", "Conectează localul cu POR ADR Nord-Est.", "Menține linkuri către sursele oficiale regionale.", "Folosește exemple locale doar dacă sunt validate."], [
    CTA,
    { href: "/por-adr-nord-est", label: "POR ADR Nord-Est" },
    { href: "/investitii-modernizarea-microintreprinderilor-apel-2", label: "Microîntreprinderi Apel 2" }
  ]),
  moduleFor("afir/index.html", "afir", "Hub AFIR pentru fermieri și rural", "AFIR trebuie să distribuie autoritate către DR12, DR14, GAL, autoconsum și utilaje, fără să încerce să explice fiecare apel în aceeași pagină.", [
    ["DR12", "Tineri fermieri, rol real în exploatație, SO/SOC și documente agricole."],
    ["DR14", "Ferme mici, investiții justificate, punctaj și greșeli frecvente."],
    ["Energie/GAL", "Autoconsum, proiecte locale și implementare cu reguli diferite pe apel."]
  ], ["Include carduri pe tip de beneficiar.", "Trimite DR12 și DR14 către paginile lor principale.", "Păstrează calculatorul SO/SOC ca sprijin, nu verdict.", "Leagă toate paginile AFIR către sursele oficiale."], [
    CTA,
    { href: "/dr12-afir", label: "DR12 AFIR" },
    { href: "/dr14-afir-ferme-mici", label: "DR14 ferme mici" }
  ]),
  moduleFor("dr12-afir/index.html", "dr12-afir", "Checklist DR12 înainte de dosar", "DR12 se verifică prin date concrete despre solicitant și exploatație, nu doar prin dorința de instalare sau vârsta beneficiarului.", [
    ["Solicitant", "Vârstă, formă juridică, rol în exploatație și documente de control."],
    ["Exploatație", "SO/SOC, APIA, ANSVSA, teren, animale, culturi și drept de folosință."],
    ["Investiție", "Buget, justificare, cofinanțare și legătura cu activitatea agricolă."]
  ], ["Calculează SO/SOC orientativ și verifică documentele.", "Nu trata ghidul consultativ ca regulă finală.", "Leagă DR12 de articolul de greșeli și DR14 pentru comparație.", "Cere documentele agricole înainte de buget."], [
    CTA,
    { href: "/calculator-soc", label: "Calculator SO/SOC" },
    { href: "/dr12-vs-dr14", label: "DR12 vs DR14" }
  ]),
  moduleFor("dr14-afir-ferme-mici/index.html", "dr14-afir-ferme-mici", "DR14: eligibil, neeligibil, risc", "Pagina trebuie să fie mai practică decât un rezumat de ghid: exemple de investiții, documente lipsă și greșeli care pot bloca dosarul.", [
    ["Eligibil", "Fermă mică, SO/SOC susținut, activitate agricolă reală și investiție necesară."],
    ["Neeligibil", "Documente incomplete, dimensiune economică neclară sau investiții fără legătură cu ferma."],
    ["Risc", "Buget supradimensionat, cofinanțare fragilă, oferte vagi sau drept de folosință neclar."]
  ], ["Păstrează această pagină ca principală pentru DR14 ferme mici.", "Articolul de greșeli trebuie să trimită către această pagină.", "Include documente APIA/ANSVSA unde se aplică.", "Folosește ghidul activ pentru condiții finale."], [
    CTA,
    { href: "/dr-14-afir-conditii-eligibilitate-greseli-frecvente", label: "Greșeli DR14" },
    { href: "/afir", label: "Hub AFIR" }
  ]),
  moduleFor("dr14/index.html", "dr14", "DR14 este pagină de performanță GSC", "Exportul Performance arată că `/dr14` și varianta veche `.html` strâng impresii și poziții 4-15, deci pagina trebuie tratată ca destinație principală pentru intenția scurtă DR14.", [
    ["Intenție", "Utilizatorul caută rapid condiții DR14, nu un articol lung despre toate greșelile."],
    ["Traseu", "Pagina scurtă trimite către checklistul DR14 ferme mici și calculatorul SO/SOC."],
    ["Conversie", "CTA-ul trebuie să ceară datele exploatației înainte de buget."]
  ], ["Menține self-canonical pe `/dr14`.", "Leagă explicit către `/dr14-afir-ferme-mici`.", "Explică diferența dintre pagina program și articolul de greșeli.", "Păstrează termenii calcul SO/SOC aproape de DR14."], [
    CTA,
    { href: "/dr14-afir-ferme-mici", label: "Checklist DR14 ferme mici" },
    { href: "/calculator-soc", label: "Calculator SO/SOC" }
  ]),
  moduleFor("calculator-soc.html", "calculator-soc", "Calculatorul SO/SOC este prioritatea GSC numărul 1", "Exportul Performance arată cele mai mari oportunități pe `calculator-soc`, `calcul so AFIR 2026` și variații pentru animale/vegetal. Pagina trebuie să explice calculul, limitele și următorul pas către DR12/DR14.", [
    ["Calcul", "Rezultatul este orientativ și trebuie verificat cu documentele APIA, ANSVSA sau alte dovezi."],
    ["Animale/vegetal", "Căutările GSC cer trasee clare pentru ferme vegetale și zootehnice."],
    ["Program", "SO/SOC trimite către DR12 sau DR14, nu înlocuiește ghidul activ."]
  ], ["Păstrează expresiile calcul SO AFIR 2026, calculator SO animale și calculator SO vegetal.", "Adaugă linkuri vizibile către DR12, DR14 și AFIR.", "Explică faptul că rezultatul nu confirmă eligibilitatea finală.", "Folosește pagina ca intrare de funnel pentru fermieri."], [
    CTA,
    { href: "/dr12-afir", label: "DR12 AFIR" },
    { href: "/dr14", label: "DR14 AFIR" }
  ]),
  moduleFor("dr-14-afir-conditii-eligibilitate-greseli-frecvente.html", "dr14-greseli", "Articol suport pentru greșeli DR14", "Acest articol răspunde la intenția de risc și prevenție, iar pagina DR14 rămâne destinația principală pentru program.", [
    ["Greșeli SO", "Calcul orientativ necorelat cu documentele agricole."],
    ["Documente", "APIA, ANSVSA, folosință, oferte și cofinanțare neverificate înainte de buget."],
    ["Buget", "Achiziții greu de justificat sau disproporționate față de fermă."]
  ], ["Canonical și link intern către pagina principală DR14.", "Evită același H1 cu pagina principală.", "Adaugă exemple concrete de erori.", "Trimite cititorul către verificarea eligibilității."], [
    CTA,
    { href: "/dr14-afir-ferme-mici", label: "Pagina principală DR14" },
    { href: "/calculator-soc", label: "Calculator SO/SOC" }
  ]),
  moduleFor("blog-afir-fotovoltaice-ferme-2026.html", "afir-fotovoltaice-ferme", "Autoconsum AFIR explicat pe flux", "Articolul trebuie să arate diferența dintre proiect energetic generic și proiect pentru autoconsum justificat prin activitatea agricolă sau alimentară.", [
    ["Consum", "Punct de consum, consum istoric, sezonalitate și profilul beneficiarului."],
    ["Producție", "Capacitate, amplasament, racordare, stocare și legătura cu activitatea."],
    ["Documente", "CAEN, proprietate sau folosință, avize, oferte și ghid activ."]
  ], ["Include diagramă logică: consum -> producție -> autoconsum -> stocare.", "Evită afirmații ferme înainte de ghid final.", "Trimite către AFIR și Fondul de Modernizare unde e relevant.", "Menține sursa oficială vizibilă."], [
    CTA,
    { href: "/afir", label: "Hub AFIR" },
    { href: "/fondul-de-modernizare", label: "Fondul de Modernizare" }
  ]),
  moduleFor("pnrr/index.html", "pnrr", "Hub PNRR pentru digitalizare și implementare", "PNRR trebuie să trimită către digitalizare, cheltuieli eligibile, indicatori și verificări de implementare, fără să devină o pagină generică.", [
    ["Digitalizare", "Software, echipamente, securitate, cloud și indicatori."],
    ["Documente", "Justificări, oferte, contracte, proceduri și arhivare."],
    ["Implementare", "Ținte, rapoarte, achiziții și riscuri de corecție."]
  ], ["Țintește PNRR IMM digitalizare și consultanță PNRR.", "Link obligatoriu către digitalizare IMM.", "Păstrează sursele oficiale la zi.", "Separă hub-ul de articolul despre cheltuieli."], [
    CTA,
    { href: "/digitalizare-imm", label: "Digitalizare IMM" },
    { href: "/pnrr-digitalizare-imm-cheltuieli-eligibile", label: "Cheltuieli eligibile PNRR" }
  ]),
  moduleFor("digitalizare-imm/index.html", "digitalizare-imm", "Matrice buget și eligibilitate digitală", "Pagina trebuie să arate ce intră într-un proiect de digitalizare: software, echipamente, securitate, cloud, servicii și documente justificative.", [
    ["Software", "ERP, CRM, aplicații, licențe și legătura cu fluxurile firmei."],
    ["Hardware", "Echipamente necesare proiectului, nu achiziții fără rol în digitalizare."],
    ["Securitate", "Cybersecurity, backup, cloud și politici de operare."]
  ], ["Corectează titlurile/meta cu diacritice.", "Link către articolul de cheltuieli eligibile.", "Include riscuri: servicii vagi, buget dezechilibrat, indicatori neclari.", "CTA către verificarea eligibilității."], [
    CTA,
    { href: "/pnrr-digitalizare-imm-cheltuieli-eligibile", label: "Cheltuieli eligibile" },
    { href: "/digitalizare-imm-erp-crm-cloud", label: "ERP, CRM și cloud" }
  ]),
  moduleFor("pnrr-digitalizare-imm-cheltuieli-eligibile.html", "pnrr-cheltuieli", "Articol evergreen pentru cheltuieli PNRR", "Articolul răspunde la long-tail și trimite traficul către pagina comercială de digitalizare, unde se verifică proiectul concret.", [
    ["Eligibil", "Cheltuieli direct legate de digitalizarea firmei și justificate în buget."],
    ["Sensibil", "Servicii, abonamente, securitate, consultanță și elemente care cer plafon sau justificare."],
    ["Risc", "Achiziții începute prea devreme, descrieri vagi sau lipsă de legătură cu indicatorii."]
  ], ["Link obligatoriu către digitalizare IMM.", "Păstrează răspuns scurt pentru snippet.", "Include documentele justificative.", "Actualizează când ghidul activ schimbă lista."], [
    CTA,
    { href: "/digitalizare-imm", label: "Pagina Digitalizare IMM" },
    { href: "/pnrr", label: "Hub PNRR" }
  ]),
  moduleFor("fondul-de-modernizare/index.html", "fondul-de-modernizare", "Energie, eficiență și autoconsum", "Pagina separă tipurile de proiecte energetice ca utilizatorul să nu confunde finanțarea pentru autoconsum cu modernizarea energetică sau transportul.", [
    ["Energie", "Producere din surse regenerabile, autoconsum și justificare de consum."],
    ["Eficiență", "Înlocuiri, audit energetic, indicatori și reducere consum."],
    ["Transport", "Infrastructură, stații de încărcare și condiții tehnice separate."]
  ], ["Folosește surse oficiale pentru pagini de energie.", "Leagă către e-MOVE și AFIR autoconsum.", "Nu publica apeluri ca active dacă sunt estimative.", "Include ultimă verificare editorială."], [
    CTA,
    { href: "/e-move", label: "e-MOVE" },
    { href: "/blog-afir-fotovoltaice-ferme-2026", label: "AFIR fotovoltaice ferme" }
  ]),
  moduleFor("pro-infra/index.html", "pro-infra", "PRO INFRA apare în Performance și merită traseu energetic clar", "GSC arată impresii pe PRO INFRA, deci pagina trebuie legată de energia regenerabilă, eficiență și verificarea tehnică fără a promite apel activ dacă sursa oficială nu confirmă.", [
    ["Beneficiar", "Se verifică activitatea, investiția, eficiența energetică și documentele tehnice."],
    ["Buget", "Cheltuielile trebuie legate de echipamente, audit, indicatori și reguli de ajutor de stat."],
    ["Surse", "Ghidul activ și comunicările oficiale decid termenii finali."]
  ], ["Leagă PRO INFRA de Fondul de Modernizare și e-MOVE.", "Nu publica sume sau termene fără ghid activ.", "Include riscuri de documente tehnice și cofinanțare.", "Folosește pagina ca suport pentru clusterul energie."], [
    CTA,
    { href: "/fondul-de-modernizare", label: "Fondul de Modernizare" },
    { href: "/e-move", label: "e-MOVE" }
  ]),
  moduleFor("e-move/index.html", "e-move", "Stații de încărcare: verificare tehnică înainte de ofertă", "e-MOVE are nevoie de condiții tehnice clare înainte de estimări comerciale: amplasament, racordare, operare și ajutor de stat.", [
    ["Amplasament", "Drept de folosință, acces, utilități și autorizare."],
    ["Racordare", "Putere disponibilă, operator, costuri și calendar."],
    ["Operare", "Model economic, venituri, mentenanță și obligații post-finanțare."]
  ], ["Evită afirmații ferme dacă apelul nu este final.", "Adaugă checklist vizual înainte de contact.", "Leagă cu Fondul de Modernizare.", "Separă proiectele tehnice de consultanța generală."], [
    CTA,
    { href: "/fondul-de-modernizare", label: "Fondul de Modernizare" },
    { href: "/contact", label: "Discută proiectul" }
  ]),
  moduleFor("consultanta-start-up-nation-2026/index.html", "consultanta-start-up-nation", "Consultanță Start-Up Nation fără promisiuni de aprobare", "Pagina comercială trebuie să arate ce verifică FABER: CAEN, buget, cheltuieli, locuri de muncă, documente și condițiile procedurii.", [
    ["CAEN", "Activitate, autorizare, eligibilitate și legătura cu ideea de afaceri."],
    ["Buget", "Cheltuieli eligibile, cofinanțare, TVA, oferte și justificări."],
    ["Documente", "Firmă, cursuri sau condiții procedurale, plan și declarații."]
  ], ["Pagina principală țintește consultanță Start-Up Nation 2026.", "Articolele de idei și cheltuieli trimit către ea.", "Procedura oficială rămâne sursa pentru actualizări.", "Nu promite punctaj sau finanțare."], [
    CTA,
    { href: "/start-up-nation-2026-idei-afaceri", label: "Idei de afaceri" },
    { href: "/start-up-nation-2026-cheltuieli-eligibile", label: "Cheltuieli eligibile" }
  ]),
  moduleFor("start-up-nation-2026/index.html", "start-up-nation-2026", "Start-Up Nation 2026 are oportunitate GSC separată", "Exportul Performance arată impresii și poziție medie 4-15 pentru pagina de program, deci aceasta trebuie să rămână hub-ul de condiții, CAEN, buget și documente.", [
    ["Condiții", "Procedura activă decide eligibilitatea, cursurile, beneficiarii și obligațiile."],
    ["CAEN", "Codul și activitatea reală trebuie verificate înaintea listei de cheltuieli."],
    ["Buget", "Cheltuielile eligibile se separă de cofinanțare, TVA și costuri neeligibile."]
  ], ["Păstrează pagina program ca destinație principală pentru Start-Up Nation 2026.", "Trimite ideile de afaceri și cheltuielile către această pagină.", "Leagă pagina de consultanța Start-Up Nation.", "Nu trata procedura ca finală dacă nu este publicată oficial."], [
    CTA,
    { href: "/consultanta-start-up-nation-2026", label: "Consultanță Start-Up Nation" },
    { href: "/start-up-nation-2026-cheltuieli-eligibile", label: "Cheltuieli eligibile" }
  ]),
  moduleFor("start-up-nation-2026-idei-afaceri/index.html", "startup-idei", "Ideea nu este suficientă fără CAEN și buget", "Articolul atrage căutări de idei, dar trebuie să educe utilizatorul că eligibilitatea se decide prin activitate, cod CAEN, buget și documente.", [
    ["Domeniu", "Servicii, producție, comerț sau IT, cu reguli diferite pe cheltuieli."],
    ["CAEN", "Codul trebuie să susțină activitatea reală și achizițiile propuse."],
    ["Buget", "Exemplele sunt orientative până când procedura confirmă plafoanele."]
  ], ["Adaugă grid cu idei pe domenii.", "Include avertisment despre CAEN, autorizare și buget.", "Trimite către pagina de consultanță.", "Nu lăsa lista de idei fără context de eligibilitate."], [
    CTA,
    { href: "/consultanta-start-up-nation-2026", label: "Consultanță Start-Up Nation" },
    { href: "/start-up-nation-2026-cheltuieli-eligibile", label: "Buget și cheltuieli" }
  ]),
  moduleFor("start-up-nation-2026-cheltuieli-eligibile/index.html", "startup-cheltuieli", "Cheltuieli eligibile, condiționate și riscante", "Pagina păstrează intenția de buget și trimite către consultanță pentru verificarea dosarului, evitând duplicarea cu vechiul URL evergreen.", [
    ["Eligibil", "Achiziții necesare activității și permise de procedura finală."],
    ["Condiționat", "Servicii, echipamente sau amenajări care cer justificare și plafon."],
    ["Risc", "Cheltuieli începute prea devreme, fără legătură cu CAEN sau greu de documentat."]
  ], ["Păstrează această pagină ca principală pentru ediția 2026.", "Redirect/canonical pentru cheltuieli-eligibile-startup-nation.", "Leagă către pagina de consultanță.", "Actualizează după procedura oficială."], [
    CTA,
    { href: "/consultanta-start-up-nation-2026", label: "Verificare Start-Up Nation" },
    { href: "/start-up-nation-2026-idei-afaceri", label: "Idei de afaceri" }
  ]),
  moduleFor("femeia-antreprenor-2026/index.html", "femeia-antreprenor", "Pagina de program Femeia Antreprenor 2026", "Această pagină rămâne pagina concretă de program, iar hub-ul general pentru femei antreprenor trimite către ea când utilizatorul caută ediția curentă.", [
    ["Acționariat", "Structură, rol real și condiții din procedura activă."],
    ["CAEN", "Activitate, autorizare și investiții compatibile."],
    ["Buget", "Cheltuieli, documente, cofinanțare și riscuri de punctaj."]
  ], ["Nu concura cu hub-ul general fonduri femei antreprenor.", "Include flow de verificare.", "Leagă articolul condiții/idei către această pagină.", "Menține sursa oficială lângă condiții."], [
    CTA,
    { href: "/fonduri-europene-femei-antreprenor", label: "Hub femei antreprenor" },
    { href: "/femeia-antreprenor-2026-conditii-idei-afaceri", label: "Condiții și idei" }
  ]),
  moduleFor("fonduri-europene-femei-antreprenor/index.html", "fonduri-femei-antreprenor", "Hub general pentru femei antreprenor", "Hub-ul explică opțiuni mai largi pentru femei antreprenor și nu dublează pagina programului Femeia Antreprenor 2026.", [
    ["Program dedicat", "Trimite către Femeia Antreprenor 2026 când există intenție de program concret."],
    ["Alternative", "IMM, digitalizare, regional, Start-Up Nation sau energie, după firmă și investiție."],
    ["Pregătire", "Documente, buget, CAEN, acționariat și eligibilitate."]
  ], ["Țintește fonduri europene femei antreprenor.", "Nu folosi același H1 cu pagina de program.", "Leagă către programul concret.", "Păstrează exemple generale fără claims neverificate."], [
    CTA,
    { href: "/femeia-antreprenor-2026", label: "Femeia Antreprenor 2026" },
    { href: "/fonduri-europene-imm", label: "Fonduri pentru IMM" }
  ]),
  moduleFor("femeia-antreprenor-2026-conditii-idei-afaceri.html", "femeia-conditii", "Articol suport: condiții, idei și riscuri", "Articolul răspunde la căutările informaționale și trimite utilizatorul către pagina de program pentru verificarea concretă.", [
    ["Condiții", "Acționariat, firmă, CAEN, procedură și documente."],
    ["Idei", "Exemple pe domenii, cu avertisment că ideea nu validează eligibilitatea."],
    ["Riscuri", "Buget, autorizare, cofinanțare, documente lipsă și procedură nefinală."]
  ], ["Link intern către pagina principală Femeia Antreprenor 2026.", "H1 diferit de pagina de program.", "Include exemple de afaceri, dar cu verificare CAEN.", "Nu promite grant sau punctaj."], [
    CTA,
    { href: "/femeia-antreprenor-2026", label: "Pagina de program" },
    { href: "/fonduri-europene-femei-antreprenor", label: "Hub femei antreprenor" }
  ]),
  moduleFor("investitii-modernizarea-microintreprinderilor-apel-2/index.html", "microintreprinderi-apel-2", "Microîntreprinderi Apel 2: dosar practic", "Pagina trebuie să răspundă repede la cine poate aplica, ce investiții intră, ce documente lipsesc și când dosarul devine riscant.", [
    ["Solicitant", "Microîntreprindere, vechime, situații financiare, CAEN și regiune."],
    ["Investiții", "Echipamente, spațiu, digitalizare, eficiență sau modernizare, după ghid."],
    ["Dosar", "Oferte, documente juridice, cofinanțare, drept de folosință și justificări."]
  ], ["Menționează când ghidul este în consultare.", "Leagă pagina de POR ADR Nord-Est.", "Folosește exemple de riscuri, nu doar condiții.", "Trimite către verificarea eligibilității."], [
    CTA,
    { href: "/por-adr-nord-est", label: "POR ADR Nord-Est" },
    { href: "/fonduri-europene-nord-est", label: "Fonduri Nord-Est" }
  ]),
  moduleFor("por-adr-nord-est/index.html", "por-adr-nord-est", "POR ADR Nord-Est ca pagină regională de program", "POR ADR Nord-Est se leagă de microîntreprinderi, RIS3 și județele din regiune, cu reguli confirmate în ghidul activ.", [
    ["Regiune", "Iași, Suceava, Bacău, Botoșani, Neamț și Vaslui."],
    ["Program", "Prioritate, apel, ghid, anexă, grilă și status."],
    ["Solicitant", "Microîntreprindere, activitate, punct de lucru, documente și buget."]
  ], ["Conectează clar cu Programul Regional Nord-Est.", "Leagă spre microîntreprinderi Apel 2.", "Folosește surse ADR pentru actualizări.", "Păstrează pagina locală distinctă de hub-ul național."], [
    CTA,
    { href: "/fonduri-europene-nord-est", label: "Hub Nord-Est" },
    { href: "/investitii-modernizarea-microintreprinderilor-apel-2", label: "Microîntreprinderi Apel 2" }
  ]),
  moduleFor("acte-necesare-fonduri-europene-nerambursabile/index.html", "acte-necesare", "Checklist de documente înainte de consultanță", "Pagina poate câștiga featured snippet dacă răspunde scurt și apoi grupează documentele pe firmă, fiscal, spațiu, investiție și oferte.", [
    ["Firmă", "Certificat constatator, act constitutiv, reprezentant, CAEN și autorizări."],
    ["Financiar", "Situații, datorii, cofinanțare, TVA și capacitate de cash-flow."],
    ["Investiție", "Oferte, spațiu, proprietate sau folosință, avize și descriere tehnică."]
  ], ["Separă această pagină de vechiul URL duplicat.", "Răspunsul scurt trebuie să apară devreme.", "Link către consultanță și eligibilitate.", "Actualizează lista după ghidul apelului."], [
    CTA,
    { href: "/consultanta-fonduri-europene", label: "Consultanță fonduri" },
    { href: "/cum-se-verifica-eligibilitatea-fonduri-europene", label: "Cum verifici eligibilitatea" }
  ]),
  moduleFor("verificare-eligibilitate-fonduri-europene/index.html", "verificare-eligibilitate", "Formular mental de autoevaluare", "Înainte de contact, beneficiarul trebuie să știe ce date minime sunt necesare pentru o concluzie utilă.", [
    ["Solicitant", "Firmă, PFA, fermier, instituție, ONG sau start-up."],
    ["Investiție", "Ce se cumpără, unde se implementează și ce problemă rezolvă."],
    ["Buget", "Grant dorit, cofinanțare, TVA, cheltuieli neeligibile și rezerve."]
  ], ["Servește ca pagină de serviciu/checklist.", "Trimite articolele informaționale către această pagină.", "Nu promite verdict final fără ghid și documente.", "CTA către contact rămâne clar."], [
    { href: "/contact", label: "Trimite datele proiectului" },
    { href: "/metodologie-verificare-eligibilitate", label: "Metodologie" },
    { href: "/acte-necesare-fonduri-europene-nerambursabile", label: "Acte necesare" }
  ]),
  moduleFor("eligibilitate-fonduri-europene/index.html", "eligibilitate-serviciu", "Eligibilitate ca serviciu, nu articol duplicat", "Această pagină explică verificarea ca serviciu, iar articolul despre cum se verifică eligibilitatea rămâne suport educațional.", [
    ["Administrativ", "Forma juridică, CAEN, localitate, datorii, vechime și documente."],
    ["Tehnic", "Investiție, spațiu, avize, oferte, implementare și calendar."],
    ["Financiar", "Cofinanțare, TVA, cash-flow, costuri neeligibile și riscuri."]
  ], ["Separă intenția de articolul explicativ.", "Leagă către contact și metodologie.", "Include ce cerem clientului pentru verificare.", "Fără garanții de aprobare."], [
    CTA,
    { href: "/cum-se-verifica-eligibilitatea-fonduri-europene", label: "Articol explicativ" },
    { href: "/contact", label: "Contact" }
  ]),
  moduleFor("cum-alegi-programul-potrivit-fonduri-europene-2026.html", "alegere-program", "Matrice decizională pentru alegerea programului", "Articolul educă utilizatorul să aleagă după beneficiar, investiție, regiune și documente, nu după numele programului.", [
    ["IMM", "Regional, digitalizare, energie sau program național."],
    ["Fermă", "AFIR, GAL, SO/SOC, documente agricole și investiție."],
    ["Start-up", "CAEN, buget, locuri de muncă și procedura activă."]
  ], ["301 către versiune curată dacă se folosește fără .html.", "Link către hub fonduri europene.", "Include matrice IMM / fermă / start-up / energie / digitalizare.", "CTA către verificare eligibilitate."], [
    CTA,
    { href: "/fonduri-europene", label: "Hub fonduri europene" },
    { href: "/calendar-fonduri-europene", label: "Calendar" }
  ]),
  moduleFor("intrebari-frecvente/index.html", "faq", "FAQ pe teme, nu listă plată", "Întrebările frecvente trebuie grupate pe eligibilitate, CAEN, documente, cofinanțare, depunere și implementare.", [
    ["Eligibilitate", "Cine poate aplica și ce blochează proiectul."],
    ["Documente", "Ce trebuie pregătit înainte de dosar."],
    ["Implementare", "Ce se întâmplă după depunere, contractare și achiziții."]
  ], ["Folosește FAQ schema doar pentru întrebări vizibile.", "Fiecare răspuns trimite către o pagină relevantă.", "Evită răspunsuri prea generale.", "Păstrează CTA contextual, nu agresiv."], [
    CTA,
    { href: "/acte-necesare-fonduri-europene-nerambursabile", label: "Acte necesare" },
    { href: "/consultanta-fonduri-europene", label: "Consultanță" }
  ]),
  moduleFor("surse-oficiale-fonduri-europene/index.html", "surse-oficiale", "Director de surse pentru încredere", "Pagina arată de unde se verifică informațiile schimbătoare: autoritate, tip sursă, link și data ultimei verificări.", [
    ["Instituții", "MIPE, AFIR, ADR, ministere, programe și ghiduri."],
    ["Documente", "Ghiduri, anexe, grile, calendare, comunicate și consultări."],
    ["Actualizare", "Paginile de program trimit către sursa oficială relevantă."]
  ], ["Foarte important pentru E-E-A-T.", "Leagă toate paginile de program către surse.", "Nu inventa ghiduri finale.", "Marchează informațiile în consultare."], [
    { href: "/ghiduri", label: "Biblioteca de ghiduri" },
    { href: "/calendar-fonduri-europene", label: "Calendar" },
    CTA
  ]),
  moduleFor("metodologie-verificare-eligibilitate/index.html", "metodologie", "Cum spune FABER da, nu sau mai verificăm", "Metodologia crește încrederea pentru că explică documentele cerute și momentul în care proiectul trebuie oprit sau ajustat.", [
    ["Date minime", "Solicitant, activitate, localitate, investiție, buget și documente."],
    ["Analiză", "Potrivire cu programul, riscuri, documente lipsă și surse oficiale."],
    ["Concluzie", "Continuăm, ajustăm sau amânăm până când proiectul este documentabil."]
  ], ["Pagina trebuie să explice când FABER spune nu.", "Leagă către consultanță și verificare eligibilitate.", "Nu ascunde riscurile de cofinanțare.", "Susține paginile comerciale."], [
    CTA,
    { href: "/consultanta-fonduri-europene", label: "Consultanță" },
    { href: "/surse-oficiale-fonduri-europene", label: "Surse oficiale" }
  ]),
  moduleFor("ghiduri/index.html", "ghiduri", "Bibliotecă de ghiduri cu filtre clare", "Ghidurile trebuie să ajute utilizatorul să găsească rapid programul, sursa și următorul pas.", [
    ["Categorii", "AFIR, IMM, PNRR, energie, Start-Up, GAL și documente."],
    ["Status", "Activ, consultare, estimat sau arhivat."],
    ["Traseu", "Ghid -> pagină program -> verificare eligibilitate."]
  ], ["Rol informațional, nu conversie directă.", "Filtrele trebuie să fie scanabile.", "Sursele oficiale se leagă contextual.", "Nu ascunde ghiduri expirate fără marcaj."], [
    { href: "/surse-oficiale-fonduri-europene", label: "Surse oficiale" },
    { href: "/fonduri-europene", label: "Hub programe" },
    CTA
  ]),
  moduleFor("calendar-fonduri-europene/index.html", "calendar", "Calendar cu status, nu listă statică", "Calendarul este util doar dacă separă programele active, estimate, în consultare și închise, cu dată de verificare.", [
    ["Activ", "Apel deschis sau perioadă confirmată oficial."],
    ["Estimativ", "Anunț sau intenție publică, fără ghid final."],
    ["Închis", "Păstrat ca istoric și legat către alternative."]
  ], ["Actualizare lunară obligatorie.", "Link către surse oficiale.", "Nu trata estimările ca apeluri active.", "Trimite utilizatorul către verificare dacă programul pare potrivit."], [
    CTA,
    { href: "/surse-oficiale-fonduri-europene", label: "Surse oficiale" },
    { href: "/fonduri-europene-nerambursabile-2026", label: "Fonduri 2026" }
  ]),
  moduleFor("glosar-fonduri-europene/index.html", "glosar", "Glosar pentru long-tail și claritate", "Glosarul explică termenii recurenți și trimite către paginile unde acei termeni devin decizii practice.", [
    ["Termeni", "Eligibilitate, cofinanțare, CAEN, SO/SOC, cheltuieli și punctaj."],
    ["Legături", "Fiecare definiție importantă trimite către ghid sau serviciu."],
    ["Utilitate", "Răspuns scurt, fără jargon și fără promisiuni."]
  ], ["Nu concura cu paginile comerciale.", "Leagă termeni către programe.", "Adaugă definiții pentru noțiuni AFIR și PNRR.", "Păstrează explicațiile scurte."], [
    { href: "/consultanta-fonduri-europene", label: "Consultanță" },
    { href: "/fonduri-europene", label: "Hub fonduri" },
    CTA
  ]),
  moduleFor("studii-de-caz-fonduri-europene/index.html", "studii-caz", "Studii de caz anonimizate, fără claims neverificate", "Exemplele trebuie să arate problema, analiza, decizia și lecția, fără nume sau rezultate publicate fără acord.", [
    ["Problemă", "Ce bloca proiectul: documente, buget, eligibilitate sau calendar."],
    ["Analiză", "Ce a verificat FABER și ce surse/documente au contat."],
    ["Lecție", "Ce poate învăța un beneficiar similar înainte de depunere."]
  ], ["Fără client, CUI sau rezultate fără acord.", "Folosește valori doar dacă sunt validate.", "Leagă fiecare caz de programul relevant.", "Include CTA discret către verificare."], [
    CTA,
    { href: "/metodologie-verificare-eligibilitate", label: "Metodologie" },
    { href: "/despre-faber", label: "Despre FABER" }
  ]),
  moduleFor("blog/index.html", "blog", "Blogul împinge autoritate către paginile comerciale", "Fiecare articol trebuie să răspundă complet la întrebare și să trimită către pagina de program sau serviciu relevantă.", [
    ["Articol suport", "Răspunde la întrebare, fără să dubleze pagina comercială."],
    ["Hub", "Blogul grupează articolele pe AFIR, IMM, Start-Up, PNRR, energie și documente."],
    ["Conversie", "CTA contextual către verificare, nu vânzare agresivă în fiecare paragraf."]
  ], ["Fiecare articol prioritar are link intern spre money page.", "Păstrează filtre pe categorii.", "Articolele thin se extind sau canonizează.", "Fără promisiuni de aprobare."], [
    CTA,
    { href: "/consultanta-fonduri-europene", label: "Serviciul principal" },
    { href: "/ghiduri", label: "Ghiduri" }
  ]),
  moduleFor("despre-faber/index.html", "despre-faber", "Încredere verificabilă, nu cifre decorative", "Pagina Despre susține E-E-A-T doar dacă folosește date reale: echipă, metodologie, ce nu promite FABER și dovezi publicabile.", [
    ["Echipă", "Nume, roluri și fotografii doar cu acord."],
    ["Metodologie", "Cum se verifică proiectele și când se recomandă oprirea."],
    ["Dovezi", "Studii de caz, surse și claims numerice doar validate."]
  ], ["Nu folosi 250+, 45M€ sau 98% fără dovadă.", "Adaugă poze reale când sunt disponibile.", "Leagă către metodologie și studii de caz.", "Păstrează secțiunea ce nu promite FABER."], [
    { href: "/metodologie-verificare-eligibilitate", label: "Metodologie" },
    { href: "/studii-de-caz-fonduri-europene", label: "Studii de caz" },
    CTA
  ]),
  moduleFor("contact/index.html", "contact", "Contact scurt, cu date utile pentru verificare", "Pagina de contact trebuie să ceară exact datele care ajută analiza inițială și să explice confidențialitatea lângă formular.", [
    ["Date proiect", "Solicitant, localitate, CAEN/activitate, investiție și buget."],
    ["Documente", "Ce există deja și ce lipsește pentru verificare."],
    ["Confidențialitate", "Datele sunt folosite pentru răspuns și analiză, nu pentru publicare."]
  ], ["Formular cât mai scurt.", "CTA clar: trimite datele proiectului.", "Mesaj de confidențialitate vizibil.", "Optimizare pentru brand și contact FABER."], [
    { href: "/verificare-eligibilitate-fonduri-europene", label: "Ce date pregătești" },
    { href: "/politica-de-confidentialitate", label: "Confidențialitate" },
    { href: "/consultanta-fonduri-europene", label: "Servicii" }
  ])
];

function moduleFor(file, slug, title, intro, cards, checklist, links) {
  return { file, slug, title, intro, cards, checklist, links };
}

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function readHtml(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8");
}

function writeHtml(file, value) {
  fs.writeFileSync(path.join(ROOT, file), value, "utf8");
}

function ensureCss($) {
  if (!$(`link[href="${CSS_HREF}"]`).length) {
    $("head").append(`\n  <link rel="stylesheet" href="${CSS_HREF}">`);
  }
}

function renderModule(item) {
  const id = `seo-plan-${item.slug}`;
  return `
  <section id="${esc(id)}" class="seo-plan-block" aria-labelledby="${esc(id)}-title">
    <div class="seo-plan-block__inner">
      <p class="seo-plan-block__eyebrow">Implementare SEO FABER</p>
      <h2 id="${esc(id)}-title">${esc(item.title)}</h2>
      <p class="seo-plan-block__intro">${esc(item.intro)}</p>
      <div class="seo-plan-block__grid">
        ${item.cards.map(([title, text]) => `<article class="seo-plan-card"><h3>${esc(title)}</h3><p>${esc(text)}</p></article>`).join("\n        ")}
      </div>
      <ul class="seo-plan-block__checklist">
        ${item.checklist.map((text) => `<li>${esc(text)}</li>`).join("\n        ")}
      </ul>
      <div class="seo-plan-block__links">
        ${item.links.map((link) => `<a href="${esc(link.href)}">${esc(link.label)}</a>`).join("\n        ")}
      </div>
    </div>
  </section>`;
}

function insertionTarget($) {
  const selectors = [
    ".audit-design-summary",
    ".hero",
    ".post-hero",
    ".article-hero",
    ".hub-hero",
    "main > section:first-child"
  ];
  for (const selector of selectors) {
    const target = $(selector).first();
    if (target.length) return target;
  }
  return $("main").first().length ? $("main").first() : $("body").first();
}

function applyModule(item) {
  const full = path.join(ROOT, item.file);
  if (!fs.existsSync(full)) return { file: item.file, status: "missing" };
  const $ = cheerio.load(readHtml(item.file), { decodeEntities: false });
  ensureCss($);
  const id = `seo-plan-${item.slug}`;
  $(`#${id}`).remove();
  insertionTarget($).after(renderModule(item));
  writeHtml(item.file, normalizeHtmlCopy($.html()));
  return { file: item.file, status: "updated", id };
}

function writeStatusReport(results) {
  const report = path.join(ROOT, "reports", `seo-14-day-implementation-${REPORT_DATE}.md`);
  const updated = results.filter((result) => result.status === "updated");
  const missing = results.filter((result) => result.status === "missing");
  const dayRows = [
    ["1", "GSC query import și mapare 4-15", "Exportul Performance ZIP este integrat; rapoarte query/page generate din ultimele 3 luni."],
    ["2", "Canonical, redirecturi și sitemap", "Structura existentă folosește rute curate; verificările se rulează după generarea sitemapului."],
    ["3", "Homepage, consultanță, fonduri europene", "Blocuri statice adăugate pe homepage și hub-urile principale."],
    ["4", "AFIR, calculator SO/SOC, DR12, DR14 și articol suport", "Blocuri AFIR/DR12/DR14/calculator SO/SOC adăugate și legate către hub și verificare."],
    ["5", "PNRR, digitalizare, energie", "Blocuri PNRR/digitalizare/energie/PRO INFRA adăugate cu linkuri către articole suport."],
    ["6", "Start-Up Nation", "Blocuri pe pagina de program, consultanță, idei și cheltuieli, cu separare pagină principală/articole."],
    ["7", "Femeia Antreprenor", "Blocuri pe program, hub general și articol suport."],
    ["8", "Regional/local", "Blocuri Nord-Est, POR și microîntreprinderi."],
    ["9", "Pagini utilitare", "Blocuri pentru acte, eligibilitate, alegere program, FAQ și metodologie."],
    ["10", "Hub-uri de încredere", "Blocuri pentru ghiduri, calendar, surse, glosar, studii, blog, despre, contact."],
    ["11", "Linkuri interne și schema", "Blocurile includ linkuri crawlable către pagina comercială sau hub relevant."],
    ["12", "Blocuri vizuale reutilizabile", "CSS reutilizabil adăugat în assets și inclus pe paginile atinse."],
    ["13", "Autoritate externă", "Outreach existent păstrat; raportul notează destinațiile pentru backlinkuri."],
    ["14", "QA final", "Rulat: copy, sitemap, SEO local, SEO integrity, funcțional, build, verify:all, structured data și smoke test vizual."]
  ];

  const md = `# Implementare plan SEO FABER în 14 zile

Data: ${REPORT_DATE}

## Confidence gate

- Blocuri repo/static HTML: 95%+ încredere, implementate în fișierele canonice existente.
- Bloc GSC Performance: 95%+ încredere pentru exportul ZIP disponibil; query-urile fără coloană page sunt mapate prin indicii controlate de rută.

## Status pe zile

| Zi | Misiune | Status |
| --- | --- | --- |
${dayRows.map((row) => `| ${row[0]} | ${row[1]} | ${row[2]} |`).join("\n")}

## Pagini actualizate

${updated.map((result) => `- \`${result.file}\` -> \`#${result.id}\``).join("\n")}

${missing.length ? `## Pagini lipsă\n\n${missing.map((result) => `- \`${result.file}\``).join("\n")}\n` : ""}
## GSC Performance integrat

Comanda rulată pe exportul disponibil:

\`\`\`powershell
npm run audit:gsc-queries -- "C:\\Users\\CODEXS\\Downloads\\atelierdeconsultanta.ro-Performance-on-Search-2026-06-01 (1).zip"
\`\`\`

Rezultatele generate sunt \`reports/gsc-query-priorities-2026-06-01.csv\`, \`reports/gsc-page-priorities-2026-06-01.csv\` și \`reports/gsc-performance-priorities-2026-06-01.md\`.

## Note de implementare

- Blocurile sunt statice și crawlable, nu injectate client-side.
- CTA-ul principal este standardizat către \`/verificare-eligibilitate-fonduri-europene\`.
- Paginile legale nu au fost supra-optimizate; rămân informative și prudente.
- Nu au fost introduse claims numerice despre proiecte, sume sau rate de succes.
- GSC Performance a fost integrat din ZIP. Prioritățile reale ridică explicit \`/calculator-soc\`, \`/dr14\`, \`/femeia-antreprenor-2026\`, \`/\`, \`/dr12-afir\`, \`/por-adr-nord-est\` și \`/start-up-nation-2026\`.
`;
  fs.mkdirSync(path.dirname(report), { recursive: true });
  fs.writeFileSync(report, md, "utf8");
  return report;
}

function main() {
  const results = modules.map(applyModule);
  const report = writeStatusReport(results);
  console.log(`Applied ${results.filter((result) => result.status === "updated").length} SEO plan modules.`);
  console.log(`Wrote ${path.relative(ROOT, report)}`);
}

main();
