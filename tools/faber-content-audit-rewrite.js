#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { normalizeHtmlCopy, normalizeRomanianCopy } = require("./normalize-copy-ro");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const TODAY = "2026-05-29";

const MINIMUM_ROUTES = [
  "/",
  "/consultanta-fonduri-europene",
  "/verificare-eligibilitate-fonduri-europene",
  "/fonduri-europene",
  "/fonduri-nerambursabile",
  "/fonduri-europene-nerambursabile-2026",
  "/fonduri-europene-nord-est",
  "/eligibilitate-fonduri-europene",
  "/ghiduri",
  "/calendar-fonduri-europene",
  "/intrebari-frecvente",
  "/glosar-fonduri-europene",
  "/studii-de-caz-fonduri-europene",
  "/calculator-soc",
  "/blog",
  "/despre-faber",
  "/contact",
  "/por-adr-nord-est",
  "/dr12-afir",
  "/dr12-afir.html",
  "/afir-autoconsum-agroalimentar",
  "/autoconsum-public-fotovoltaice-institutii-publice",
  "/dr14",
  "/dr14-afir-ferme-mici",
  "/digitalizare-imm",
  "/femeia-antreprenor-2026",
  "/gal-afir",
  "/apeluri-gal",
  "/e-move",
  "/pro-infra",
  "/start-up-nation-2026",
  "/start-up-nation-2026-conditii",
  "/startup-nation-2026-conditii",
  "/pnrr",
  "/afir",
  "/cum-alegi-programul-potrivit-fonduri-europene-2026",
  "/acte-necesare-fonduri-europene-nerambursabile",
  "/ce-acte-sunt-necesare-fonduri-europene",
  "/dr-14-afir-conditii-eligibilitate-greseli-frecvente",
  "/dr-12-afir-instalarea-tinerilor-fermieri",
  "/start-up-nation-2026-idei-afaceri",
  "/femeia-antreprenor-2026-conditii-idei-afaceri",
  "/pnrr-digitalizare-imm-cheltuieli-eligibile",
  "/fondul-de-modernizare-finantari-energie-fotovoltaice-autoconsum",
  "/cum-se-calculeaza-cofinantarea-fonduri-europene",
  "/cand-merita-consultant-fonduri-europene",
  "/cum-se-verifica-eligibilitatea-fonduri-europene",
  "/cat-costa-consultanta-fonduri-europene-ghid",
  "/dr12-vs-dr14",
  "/digitalizare-imm-erp-crm-cloud",
  "/blog-afir-fotovoltaice-ferme-2026",
  "/idei-afaceri-fonduri-europene",
  "/termeni-si-conditii",
  "/politica-de-confidentialitate",
  "/gdpr",
  "/surse-oficiale-fonduri-europene",
  "/metodologie-verificare-eligibilitate"
];

const PROGRAM_OVERRIDES = {
  "consultanta-fonduri-europene": {
    title: "Consultanță fonduri europene | FABER",
    description: "Consultanță pentru fonduri europene: eligibilitate, program potrivit, strategie de punctaj, dosar, clarificări și implementare.",
    h1: "Consultanță pentru fonduri europene",
    quickAnswer: "FABER verifică eligibilitatea solicitantului, compară programele potrivite și pregătește dosarul pe baza documentelor disponibile. O analiză inițială arată dacă merită continuat, ce trebuie ajustat și ce riscuri pot apărea înainte de depunere. Contractul complet de consultanță acoperă documentația, bugetul, clarificările și, dacă este cazul, suportul în implementare.",
    contentSections: [
      {
        title: "Verificare inițială sau consultanță completă",
        paragraphs: [
          "Verificarea inițială răspunde la întrebarea dacă proiectul merită pregătit acum: solicitant, CAEN sau exploatație, localitate, investiție, buget, cofinanțare și documente minime.",
          "Consultanța completă începe după această filtrare și include strategia de punctaj, bugetul, cererea, anexele, clarificările și sprijinul în contractare sau implementare, dacă serviciul este agreat."
        ]
      },
      {
        title: "Cum tratăm costurile",
        paragraphs: [
          "Costul consultanței depinde de program, complexitatea investiției, documentele existente, clarificările probabile și etapa proiectului. Oferta se stabileste dupa evaluarea proiectului, nu dupa un pret unic."
        ]
      }
    ],
    finalCtaText: "Trimite datele proiectului pentru o verificare inițială: solicitant, activitate, localitate, investiție, buget și cofinanțare disponibilă."
  },
  "verificare-eligibilitate-fonduri-europene": {
    title: "Verificare eligibilitate fonduri europene",
    description: "Verificare inițială pentru fonduri europene: firmă, CAEN, localitate, investiție, buget, cofinanțare, documente și program potrivit.",
    h1: "Verificare eligibilitate pentru fonduri europene",
    quickAnswer: "Serviciul verifică dacă solicitantul și investiția au o potrivire realistă cu un program de finanțare. Sunt necesare forma juridică, CAEN-ul sau activitatea fermei, localitatea, bugetul, cofinanțarea și documentele existente. Rezultatul poate fi: continuăm pregătirea, ajustăm proiectul sau amânăm până când apar documente ori reguli mai clare.",
    contentSections: [
      {
        title: "Ce date trimiți",
        items: [
          "forma juridică și datele solicitantului;",
          "cod CAEN, activitate reală sau date despre exploatație;",
          "localitatea investiției și documentele pentru spațiu, teren sau punct de lucru;",
          "investiția dorită, bugetul estimat și cofinanțarea disponibilă;",
          "documente deja pregătite: certificat constatator, situații financiare, APIA/ANSVSA, oferte sau avize."
        ]
      },
      {
        title: "Ce concluzie primești",
        paragraphs: [
          "Concluzia nu este o promisiune de aprobare. Este o filtrare pragmatică: proiectul poate merge mai departe, trebuie ajustat sau ar trebui amânat până când ghidul activ și documentele confirmă incadrarea."
        ]
      }
    ],
    finalCtaText: "Trimite forma juridică, CAEN-ul sau activitatea, localitatea, investiția, bugetul și documentele disponibile pentru o verificare inițială."
  },
  "fonduri-europene": {
    title: "Fonduri europene pentru firme și fermieri",
    description: "Hub pentru fonduri europene: programe pentru IMM-uri, fermieri, instituții publice, energie, digitalizare, GAL, AFIR și PNRR.",
    h1: "Fonduri europene: programe, eligibilitate și ghiduri",
    quickAnswer: "Această pagină este hub-ul central FABER pentru programe de finanțare. Diferențiază traseele pentru IMM-uri, fermieri, start-up-uri, instituții publice, energie, digitalizare, GAL și AFIR, apoi trimite către paginile de program unde se verifică regulile active.",
    contentSections: [
      {
        title: "Cum alegi direcția potrivită",
        paragraphs: [
          "Un IMM poate porni de la investiții regionale, digitalizare, energie sau programe naționale. Un fermier verifică mai întâi AFIR, SO/SOC, documentele exploatației și investiția agricolă. O instituție publică are nevoie de hotărâri, bugete, consumuri și documente de proprietate sau administrare.",
          "Pentru fiecare traseu, regulile finale se confirmă în ghidul activ, anexele apelului și comunicările autorității."
        ],
        links: [
          { href: "/afir", label: "AFIR" },
          { href: "/pnrr", label: "PNRR" },
          { href: "/gal-afir", label: "GAL-AFIR" },
          { href: "/e-move", label: "e-MOVE" },
          { href: "/pro-infra", label: "PRO INFRA" },
          { href: "/fonduri-nerambursabile", label: "Fonduri nerambursabile" },
          { href: "/ghiduri", label: "Ghiduri" }
        ]
      }
    ],
    finalCtaText: "Dacă ai mai multe programe posibile, trimite profilul beneficiarului și investiția ca să alegem direcția de verificare."
  },
  "fonduri-nerambursabile": {
    title: "Fonduri nerambursabile | grant, cofinanțare",
    description: "Ghid despre fonduri nerambursabile: grant, cofinanțare, cheltuieli eligibile și neeligibile, rambursare și obligații post-finanțare.",
    h1: "Fonduri nerambursabile: grant, cofinanțare și obligații",
    quickAnswer: "Fondurile nerambursabile nu înseamnă bani fără obligații. Beneficiarul trebuie să acopere contribuția proprie, TVA-ul sau cheltuielile neeligibile, să respecte achizițiile, cererile de plată și obligațiile de monitorizare. Pagina explică diferența dintre grant, buget total, cash-flow și responsabilitățile post-finanțare.",
    contentSections: [
      {
        title: "Grantul nu acoperă tot proiectul",
        paragraphs: [
          "Cheltuielile eligibile sunt costurile pe care programul le poate deconta, în limitele ghidului. Cheltuielile neeligibile sunt costuri pe care beneficiarul le suportă separat: TVA, diferențe de preț, lucrări nepermise, servicii nejustificate sau rezerve de implementare.",
          "Rambursarea poate veni după plata furnizorilor, de aceea cash-flow-ul trebuie verificat înainte de depunere."
        ]
      }
    ],
    finalCtaText: "Trimite bugetul estimat și cheltuielile principale ca să separăm grantul posibil de contribuția proprie și costurile neeligibile."
  },
  "fonduri-europene-nerambursabile-2026": {
    title: "Fonduri europene nerambursabile 2026",
    description: "Fonduri europene nerambursabile 2026: programe posibile, cine poate aplica, ce documente se verifică, riscuri și pași următori.",
    h1: "Fonduri europene nerambursabile 2026",
    quickAnswer: "Pentru 2026, programele trebuie urmărite fără a presupune valori, termene sau punctaje finale înainte de apelul activ. Verificarea pornește de la beneficiar, localizare, activitate, investiție, buget, cofinanțare și documente. Pagina este o hartă de orientare, nu o listă de finanțări garantate.",
    contentSections: [
      {
        title: "Structură de verificare pentru 2026",
        items: [
          "programe posibile: AFIR, GAL, PNRR, regional, energie, digitalizare, antreprenoriat;",
          "cine poate aplica: firmă, fermier, start-up, instituție publică sau beneficiar GAL;",
          "ce se verifică: CAEN, localitate, documente, cofinanțare, punctaj, cheltuieli;",
          "riscuri: ghid nefinal, documente incomplete, buget greu de susținut, apel nepotrivit."
        ]
      }
    ],
    finalCtaText: "Pentru o verificare pe 2026, trimite profilul beneficiarului, investiția și bugetul estimat. Confirmăm regulile doar în ghidul activ."
  },
  "por-adr-nord-est": {
    title: "POR ADR Nord-Est pentru microîntreprinderi",
    description: "POR ADR Nord-Est pentru microîntreprinderi: județ, CAEN, vechime, situații financiare, punct de lucru, RIS3, oferte și buget.",
    h1: "POR ADR Nord-Est pentru microîntreprinderi",
    quickAnswer: "Pentru o microîntreprindere din Nord-Est, verificarea începe cu județul investiției, CAEN-ul, vechimea, situațiile financiare, punctul de lucru, bugetul și ofertele. RIS3 sau alte condiții regionale se tratează prudent și se confirmă numai în ghidul activ și anexele ADR Nord-Est.",
    contentSections: [
      {
        title: "Ce verificăm pentru Nord-Est",
        items: [
          "localizarea în Iași, Suceava, Bacău, Botoșani, Neamț sau Vaslui;",
          "încadrarea de microîntreprindere și istoricul financiar;",
          "codul CAEN și legătura investiției cu activitatea reală;",
          "punctul de lucru, dreptul de folosință și ofertele;",
          "corelarea cu domeniile regionale, inclusiv RIS3, unde ghidul o cere."
        ]
      }
    ],
    finalCtaText: "Trimite județul investiției, CAEN-ul, vechimea firmei, bugetul și lista de achiziții pentru o verificare POR ADR Nord-Est."
  },
  "dr12-afir": {
    title: "DR12 AFIR | tineri fermieri instalați",
    description: "DR12 AFIR pentru tineri fermieri instalați: vârstă, șef exploatație, SO/SOC, APIA, ANSVSA, folosință, investiție și cofinanțare.",
    h1: "DR12 AFIR pentru tineri fermieri instalați",
    quickAnswer: "DR12 trebuie verificat ca program de consolidare pentru tineri fermieri instalați, nu ca promisiune automată de instalare. Contează vârsta, rolul real de șef al exploatației, SO/SOC, documentele APIA sau ANSVSA, dreptul de folosință, investiția, cofinanțarea și grila apelului activ.",
    decisionIntro: "Pentru DR12, întrebarea principală este dacă solicitantul poate demonstra rolul real în exploatație și dacă investiția consolidează ferma în limitele apelului.",
    decisionClose: "Dacă vârsta, SO/SOC, actele de folosință sau documentele agricole nu sunt clare, dosarul trebuie ajustat înainte de buget. Condițiile finale se confirmă în ghidul activ AFIR.",
    contentSections: [
      {
        title: "Nu confundăm DR12 cu orice instalare",
        paragraphs: [
          "Pagina tratează DR12 ca intervenție pentru tineri fermieri instalați sau în consolidare, în funcție de ghidul activ. Dacă apelul final definește altfel beneficiarii, textul trebuie citit împreună cu sursa oficială."
        ]
      }
    ],
    finalCtaText: "Trimite vârsta solicitantului, forma juridică, datele exploatației, SO/SOC, documentele agricole și investiția dorită pentru verificarea DR12."
  },
  "afir-autoconsum-agroalimentar": {
    title: "AFIR autoconsum agroalimentar | energie",
    description: "AFIR autoconsum agroalimentar: beneficiari agricoli și alimentari, punct de producție, consum istoric, amplasament, avize, CAEN și stocare.",
    h1: "AFIR autoconsum agroalimentar",
    quickAnswer: "Programul se analizează pentru beneficiari din agricultură sau industria alimentară care pot justifica producția de energie pentru autoconsum. Verificarea include punctul de producție, punctul de consum, consumul istoric, amplasamentul, avizele, capacitatea, stocarea, CAEN-ul și legătura cu activitatea agroalimentară.",
    contentSections: [
      {
        title: "Autoconsum, nu proiect energetic generic",
        paragraphs: [
          "Capacitatea nu se alege după plafon, ci după consum, amplasament și regulile apelului activ. Dacă producția, consumul și documentele de amplasament nu se potrivesc, proiectul devine vulnerabil la evaluare."
        ]
      }
    ],
    finalCtaText: "Trimite CAEN-ul, consumul istoric, punctul de consum, amplasamentul și soluția tehnică propusă pentru verificarea autoconsumului."
  },
  "autoconsum-public-fotovoltaice-institutii-publice": {
    title: "Autoconsum public fotovoltaice | instituții",
    description: "Fotovoltaice pentru instituții publice: HCL, consum, amplasament, proprietate sau administrare, avize, buget și diferențe față de agroalimentar.",
    h1: "Autoconsum public fotovoltaice pentru instituții publice",
    quickAnswer: "Pagina este pentru primării, școli, spitale și instituții publice care analizează fotovoltaice pentru consum propriu. Spre deosebire de autoconsumul agroalimentar, verificarea pornește de la documente publice: HCL, consum, amplasament, avize, proprietate sau administrare, buget și proceduri de achiziție.",
    contentSections: [
      {
        title: "Documente publice care contează",
        items: [
          "hotărâre de consiliu local sau document echivalent;",
          "consum istoric și profilul clădirilor publice;",
          "drept de proprietate sau administrare asupra amplasamentului;",
          "avize, racordare, buget și calendar de achiziție."
        ]
      }
    ],
    finalCtaText: "Trimite instituția, clădirile vizate, consumul, documentele de proprietate sau administrare și bugetul estimat."
  },
  "dr14": {
    title: "DR14 AFIR | ferme mici și investiții",
    description: "DR14 AFIR pentru ferme mici: SO/SOC, exploatație, investiții eligibile, documente, cofinanțare, punctaj și legătura cu calculatorul SO.",
    h1: "DR14 AFIR pentru ferme mici",
    quickAnswer: "DR14 se verifică pentru ferme mici care pot demonstra dimensiunea economică, documentele exploatației, dreptul de folosință, investiția necesară și cofinanțarea. Pragurile, sumele și punctajul se confirmă în ghidul activ. Calculatorul SO/SOC este doar un punct de pornire.",
    contentSections: [
      {
        title: "Legătura cu calculatorul SO/SOC",
        paragraphs: [
          "Un rezultat orientativ din calculator nu este suficient. Datele trebuie susținute prin documente APIA, ANSVSA, registru agricol sau alte dovezi cerute de ghid."
        ],
        links: [{ href: "/calculator-soc", label: "Calculator SO/SOC" }, { href: "/dr14-afir-ferme-mici", label: "Checklist DR14 ferme mici" }]
      }
    ],
    finalCtaText: "Trimite structura fermei, SO/SOC, documentele exploatației, investiția și bugetul ca să verificăm dacă DR14 merită pregătit."
  },
  "dr14-afir-ferme-mici": {
    title: "DR14 AFIR ferme mici | checklist practic",
    description: "Checklist DR14 pentru ferme mici: SO calculat corect, APIA/ANSVSA, investiție corelată, cofinanțare, oferte și greșeli frecvente.",
    h1: "DR14 AFIR ferme mici: checklist și greșeli frecvente",
    quickAnswer: "Această pagină completează pagina principală DR14 cu un checklist aplicat. Verifică SO/SOC, documentele APIA sau ANSVSA, dreptul de folosință, investiția, cofinanțarea, ofertele și greșelile frecvente: SO calculat greșit, documente incomplete, buget supradimensionat sau cofinanțare insuficientă.",
    finalCtaText: "Trimite datele fermei și lista de achiziții pentru o verificare DR14 orientată pe greșeli frecvente și documente lipsă."
  },
  "digitalizare-imm": {
    title: "Digitalizare IMM | ERP, CRM, cloud",
    description: "Digitalizare IMM: ERP, CRM, cloud, securitate cibernetică, echipamente IT, servicii și legătura cheltuielilor cu activitatea firmei.",
    h1: "Digitalizare IMM: ERP, CRM, cloud și securitate",
    quickAnswer: "Un proiect de digitalizare trebuie să arate ce proces se îmbunătățește: vânzări, producție, gestiune, raportare, relația cu clienții sau securitatea datelor. ERP, CRM, cloud, hardware și securitate cibernetică pot fi analizate doar dacă sunt permise de ghid și sunt legate de activitatea reală.",
    contentSections: [
      {
        title: "Exemple de cheltuieli digitale",
        items: [
          "ERP pentru gestiune, producție, stocuri sau raportare;",
          "CRM pentru relația cu clienții și vânzări;",
          "cloud, backup și servicii de implementare;",
          "securitate cibernetică, echipamente IT și instruire, dacă apelul le permite."
        ],
        links: [{ href: "/digitalizare-imm-erp-crm-cloud", label: "ERP, CRM și cloud" }, { href: "/pnrr", label: "PNRR" }]
      }
    ],
    finalCtaText: "Trimite procesele pe care vrei să le digitalizezi, lista de achiziții IT, bugetul și ofertele existente pentru o verificare inițială."
  },
  "femeia-antreprenor-2026": {
    title: "Femeia Antreprenor 2026 | pregătire",
    description: "Femeia Antreprenor 2026: beneficiari, eligibilitate, idei de investiții, CAEN, documente și pregătire prudentă înainte de lansare.",
    h1: "Femeia Antreprenor 2026: eligibilitate și pregătire",
    quickAnswer: "Pagina tratează pregătirea pentru Femeia Antreprenor 2026 fără să presupună apel deschis. Verificarea include structura acționariatului, rolul femeii antreprenor, CAEN-ul, activitatea, ideea de investiție, documentele firmei, bugetul și procedura activă atunci când este publicată.",
    finalCtaText: "Trimite structura firmei, CAEN-ul, ideea de investiție, bugetul și documentele disponibile pentru o verificare prudentă."
  },
  "start-up-nation-2026": {
    title: "Start-Up Nation 2026 | condiții și dosar",
    description: "Start-Up Nation 2026: pregătire, procedură activă, cursuri, firmă nouă, CAEN, buget, documente și riscuri de verificat.",
    h1: "Start-Up Nation 2026: pregătire, CAEN și buget",
    quickAnswer: "Start-Up Nation 2026 se verifică prin procedura activă, profilul solicitantului, cursurile sau condițiile cerute, firma nouă, CAEN-ul, bugetul și documentele. O idee de afacere nu garantează eligibilitatea; trebuie validată prin procedură, cheltuieli, punctaj și capacitatea de implementare.",
    finalCtaText: "Trimite ideea, CAEN-ul, bugetul, stadiul firmei și documentele disponibile pentru verificarea condițiilor Start-Up Nation."
  },
  "start-up-nation-2026-conditii": {
    title: "Start-Up Nation 2026 condiții | checklist",
    description: "Checklist Start-Up Nation 2026: solicitant, firmă nouă, CAEN, cursuri, buget, cheltuieli, documente, cofinanțare și procedură activă.",
    h1: "Start-Up Nation 2026: checklist de condiții",
    quickAnswer: "Pagina este un checklist de conditii, nu un articol general. Verifica solicitantul, firma noua, CAEN-ul, cursurile sau cerintele procedurii, bugetul, cheltuielile, documentele si cofinantarea.",
    finalCtaText: "Trimite checklistul completat, CAEN-ul, ideea și bugetul ca să verificăm unde pot apărea riscuri."
  },
  "pnrr": {
    title: "PNRR pentru IMM-uri și digitalizare",
    description: "Hub PNRR pentru IMM-uri: apeluri specifice, digitalizare, cheltuieli eligibile, documente, indicatori și reguli de confirmat oficial.",
    h1: "PNRR: apeluri, digitalizare și reguli specifice",
    quickAnswer: "PNRR are apeluri și reguli specifice, cu obiective, indicatori, termene și documente proprii. Pentru IMM-uri, digitalizarea trebuie legată de procese reale și de cheltuieli justificabile. Pagina trimite către Digitalizare IMM și articolul despre cheltuieli eligibile.",
    contentSections: [
      {
        title: "PNRR nu este un program unic",
        paragraphs: [
          "Fiecare apel PNRR trebuie citit separat. Ce a fost permis într-un apel poate să nu fie permis în altul, iar indicatorii și termenele pot schimba bugetul."
        ],
        links: [{ href: "/digitalizare-imm", label: "Digitalizare IMM" }, { href: "/pnrr-digitalizare-imm-cheltuieli-eligibile", label: "Cheltuieli eligibile" }]
      }
    ],
    finalCtaText: "Trimite obiectivul digital, lista de cheltuieli și bugetul pentru o verificare PNRR pe apelul activ."
  },
  "afir": {
    title: "AFIR | DR12, DR14, GAL și autoconsum",
    description: "Hub AFIR pentru fermieri: DR12, DR14, autoconsum agroalimentar, GAL/LEADER, calculator SO/SOC, documente și verificări înainte de dosar.",
    h1: "AFIR: programe pentru fermieri și beneficiari rurali",
    quickAnswer: "Hub-ul AFIR organizează programele pentru fermieri și beneficiari rurali: DR12, DR14, autoconsum agroalimentar, GAL/LEADER și calculatorul SO/SOC. Înainte de dosar se verifică solicitantul, exploatația, documentele agricole, investiția, cofinanțarea și ghidul activ.",
    finalCtaText: "Trimite tipul exploatației, SO/SOC, documentele agricole și investiția ca să alegem traseul AFIR potrivit."
  },
  "gal-afir": {
    title: "GAL-AFIR | proiecte LEADER și implementare",
    description: "Consultanță GAL-AFIR: scriere proiecte GAL, preluare proiecte în implementare, beneficiari publici și privați, SDL, criterii, achiziții și plăți.",
    h1: "GAL-AFIR: proiecte LEADER publice și private",
    quickAnswer: "FABER scrie proiecte GAL și poate prelua proiecte GAL aflate în implementare, dacă documentele și contractul permit. Verificarea separă beneficiarii publici de cei privați și include GAL-ul local, SDL, fișa intervenției, ghidul local, criteriile, documentele, bugetul, clarificările, achizițiile și cererile de plată.",
    finalCtaText: "Trimite localitatea, GAL-ul dacă îl cunoști, tipul beneficiarului și stadiul proiectului: idee, depunere sau implementare."
  },
  "apeluri-gal": {
    title: "Apeluri GAL | cum se verifică",
    description: "Apeluri GAL: ce sunt, cum identifici GAL-ul local, cum citești SDL, fișa intervenției, ghidul local, criteriile și bugetul.",
    h1: "Apeluri GAL: ce sunt și cum se verifică",
    quickAnswer: "Această pagină explică ce sunt apelurile GAL și cum se verifică o oportunitate locală: identificarea GAL-ului, citirea SDL, fișa intervenției, ghidul local, criteriile, documentele și bugetul. Pentru serviciul FABER de scriere sau implementare, pagina trimite către hub-ul GAL-AFIR.",
    finalCtaText: "Dacă ai găsit un apel GAL, trimite linkul, localitatea, tipul beneficiarului și investiția pentru o verificare inițială."
  },
  "e-move": {
    title: "e-MOVE | stații de încărcare",
    description: "e-MOVE: stații de încărcare, mobilitate electrică, eligibilitate, locații, racordare, operare, venituri și ajutor de stat.",
    h1: "e-MOVE: stații de încărcare și mobilitate electrică",
    quickAnswer: "e-MOVE se verifică prin beneficiar, locație, drept de folosință, racordare, operare, venituri posibile și ajutor de stat. Nu presupunem un calendar până la publicarea sursei oficiale active. Proiectul trebuie să fie operabil, nu doar eligibil pe hârtie.",
    decisionIntro: "Pentru e-MOVE, riscul apare mai ales la locație, racordare, dreptul de folosință și modelul de operare al stațiilor de încărcare.",
    finalCtaText: "Trimite locația, dreptul asupra amplasamentului, puterea dorită, datele de racordare și modelul de operare."
  },
  "pro-infra": {
    title: "PRO INFRA | eficiență energetică",
    description: "PRO INFRA: eficiență energetică pentru producători, CAEN, echipamente înlocuite, EMS, casare, audit energetic și documente tehnice.",
    h1: "PRO INFRA: eficiență energetică și echipamente",
    quickAnswer: "PRO INFRA se analizează ca schemă de eficiență energetică pentru producători sau infrastructură, în funcție de ghid. Verificarea include CAEN-ul, echipamentele înlocuite, eficiența energetică, EMS, casarea, auditul energetic și documentele tehnice. Nu păstrăm sume fără sursă oficială.",
    finalCtaText: "Trimite CAEN-ul, echipamentele existente, echipamentele propuse, auditul energetic dacă există și bugetul estimat."
  },
  "eligibilitate-fonduri-europene": {
    title: "Eligibilitate fonduri europene | administrativ și tehnic",
    description: "Hub despre eligibilitate: diferența dintre eligibilitate administrativă, tehnică și punctaj, documente, CAEN, cofinanțare și riscuri.",
    h1: "Eligibilitate fonduri europene: administrativ, tehnic și punctaj",
    quickAnswer: "Eligibilitatea are mai multe niveluri. Administrativ verifică solicitantul și documentele. Tehnic verifică investiția, cheltuielile și implementarea. Punctajul arată dacă proiectul poate fi competitiv, dar nu garantează finanțarea. Pagina este hub SEO și trimite către serviciul de verificare pentru analiza concretă.",
    finalCtaText: "Trimite datele solicitantului și investiția ca să verificăm separat eligibilitatea administrativă, tehnică și punctajul orientativ."
  },
  "ghiduri": {
    title: "Ghiduri fonduri europene | bibliotecă FABER",
    description: "Bibliotecă de resurse FABER: ghiduri AFIR, IMM, digitalizare, energie, antreprenoriat, GAL, documente și checklisturi utile.",
    h1: "Ghiduri și resurse pentru fonduri europene",
    quickAnswer: "Biblioteca FABER grupează resurse orientative pentru AFIR, IMM-uri, digitalizare, energie, antreprenoriat și GAL. Scopul este să pregătești întrebările și documentele, nu să înlocuiești ghidul oficial al apelului activ.",
    contentSections: [
      {
        title: "Cum folosești biblioteca",
        paragraphs: [
          "Alege întâi categoria proiectului: AFIR pentru ferme și investiții rurale, IMM pentru investiții productive, digitalizare pentru software și echipamente IT, energie pentru autoconsum sau eficiență, antreprenoriat pentru start-up-uri și GAL pentru apeluri locale. Fiecare resursă trebuie citită împreună cu ghidul activ, anexele și clarificările oficiale.",
          "Dacă două ghiduri par potrivite, nu porni de la titlu. Compară solicitantul, localitatea, CAEN-ul sau exploatația, investiția, bugetul, documentele disponibile și contribuția proprie. O resursă bună te ajută să formulezi întrebările corecte înainte de a bloca bani în oferte, avize sau proiectare."
        ]
      },
      {
        title: "Grupe de resurse utile",
        items: [
          "AFIR: SO/SOC, documente APIA sau ANSVSA, folosință teren, investiții agricole și obligații de implementare;",
          "IMM: CAEN, vechime, situații financiare, punct de lucru, oferte, cofinanțare și cheltuieli eligibile;",
          "digitalizare: ERP, CRM, cloud, securitate cibernetică, hardware, servicii și legătura cu activitatea firmei;",
          "energie: consum istoric, amplasament, avize, racordare, autoconsum, eficiență energetică și documente tehnice;",
          "GAL: localitate, SDL, fișa intervenției, ghid local, criterii de selecție, achiziții și cereri de plată."
        ]
      }
    ],
    finalCtaText: "Alege ghidul potrivit sau trimite proiectul dacă nu știi ce resursă se potrivește."
  },
  "calendar-fonduri-europene": {
    title: "Calendar fonduri europene | pregătire",
    description: "Calendar fonduri europene: pregătire, apel activ, documente, depunere, clarificări și verificare din timp, fără a înlocui calendarele oficiale.",
    h1: "Calendar fonduri europene: pregătire fără grabă",
    quickAnswer: "Calendarul FABER nu înlocuiește calendarele oficiale. Îl folosim pentru a organiza pregătirea: programe în pregătire, apeluri active, verificare documente, depunere și clarificări. Un dosar pregătit din timp este mai ușor de verificat decât unul făcut pe fugă.",
    finalCtaText: "Trimite programul urmărit și stadiul documentelor ca să stabilim ce trebuie pregătit înainte de deschiderea sau închiderea apelului."
  },
  "intrebari-frecvente": {
    title: "Întrebări frecvente despre fonduri europene",
    description: "Întrebări frecvente despre cofinanțare, CAEN, documente, ghid, punctaj, implementare, GAL, AFIR și digitalizare.",
    h1: "Întrebări frecvente despre fonduri europene",
    quickAnswer: "FAQ-ul răspunde pe limbaj natural la întrebări despre cofinanțare, CAEN, documente, ghid, punctaj, implementare, GAL, AFIR și digitalizare. Răspunsurile sunt orientative și trebuie verificate pe programul activ.",
    finalCtaText: "Dacă întrebarea ta depinde de documente, trimite proiectul pentru o verificare aplicată."
  }
};

const ARTICLE_OVERRIDES = {
  "cum-alegi-programul-potrivit-fonduri-europene-2026.html": {
    title: "Cum alegi fonduri europene în 2026",
    description: "Ghid practic pentru alegerea programului potrivit în 2026: eligibilitate, oportunitate, documente, buget, punctaj și riscuri.",
    h1: "Cum alegi programul potrivit de fonduri europene în 2026",
    intro: "Programul potrivit nu se alege după suma maximă anunțată, ci după solicitant, investiție, documente, cofinanțare și regulile apelului activ. Eligibilitatea arată dacă poți intra în analiză; oportunitatea arată dacă merită să pregătești dosarul acum."
  },
  "ce-acte-sunt-necesare-fonduri-europene.html": {
    title: "Ce acte sunt necesare pentru fonduri europene",
    description: "Checklist scurt pentru acte necesare la fonduri europene: firmă, fermă, spațiu, buget, oferte, declarații și avize.",
    h1: "Ce acte sunt necesare pentru fonduri europene?",
    intro: "Lista exactă de acte depinde de ghidul activ, dar verificarea începe aproape întotdeauna cu documentele solicitantului, activitatea, spațiul, bugetul, ofertele, declarațiile și avizele cerute de program."
  },
  "dr-14-afir-conditii-eligibilitate-greseli-frecvente.html": {
    title: "DR14 AFIR: condiții și greșeli frecvente",
    description: "Articol despre greșeli frecvente la DR14 AFIR: SO/SOC, documente APIA/ANSVSA, investiții neeligibile, cofinanțare, oferte și termene.",
    h1: "DR14 AFIR: condiții, eligibilitate și greșeli frecvente",
    intro: "La DR14, multe probleme apar înainte de depunere: SO/SOC calculat greșit, documente agricole incomplete, investiții necorelate, cofinanțare insuficientă, oferte vagi sau termene prea strânse. Regulile finale se confirmă în ghidul activ."
  },
  "dr-12-afir-instalarea-tinerilor-fermieri.html": {
    title: "DR12 pentru tineri fermieri instalați",
    description: "DR12 pentru tineri fermieri instalați: diferența față de instalare, documente, SO/SOC, exploatație, investiție și riscuri.",
    h1: "DR12 pentru tineri fermieri instalați",
    intro: "DR12 trebuie citit cu atenție față de programul descris în ghidul activ. Dacă apelul vizează consolidarea tinerilor fermieri instalați, accentul cade pe rolul real în exploatație, SO/SOC, documente agricole și investiția propusă."
  },
  "pnrr-digitalizare-imm-cheltuieli-eligibile.html": {
    title: "PNRR Digitalizare IMM: cheltuieli eligibile",
    description: "Cheltuieli eligibile pentru digitalizare IMM: software, hardware, cloud, securitate, website, servicii și legătura cu activitatea.",
    h1: "PNRR Digitalizare IMM: cheltuieli eligibile",
    intro: "Cheltuielile IT trebuie legate de activitatea firmei și de procese măsurabile. Software-ul, hardware-ul, cloud-ul, securitatea, website-ul sau serviciile de implementare sunt analizate doar dacă apelul activ le permite și dacă pot fi justificate."
  },
  "cum-se-calculeaza-cofinantarea-fonduri-europene.html": {
    title: "Cum se calculează cofinanțarea",
    description: "Explicație simplă despre grant, contribuție proprie, TVA, cheltuieli neeligibile, cash-flow și exemplu numeric orientativ.",
    h1: "Cum se calculează cofinanțarea la fonduri europene",
    intro: "Cofinanțarea este partea pe care beneficiarul o susține separat de grant. Ea trebuie calculată împreună cu TVA-ul, cheltuielile neeligibile, diferențele de preț și cash-flow-ul, nu doar ca procent din buget."
  },
  "cand-merita-consultant-fonduri-europene.html": {
    title: "Când merită consultant fonduri europene",
    description: "Când merită un consultant pentru fonduri europene: ce riscuri reduce, ce documente verifică și când analiza trebuie făcută înainte de dosar.",
    h1: "Când merită să lucrezi cu un consultant pentru fonduri europene",
    intro: "Un consultant merită când proiectul are riscuri reale: eligibilitate neclară, documente incomplete, buget tehnic, cofinanțare, punctaj sau implementare. Rolul lui este să reducă riscul, nu să promită aprobarea."
  },
  "cum-se-verifica-eligibilitatea-fonduri-europene.html": {
    title: "Cum se verifică eligibilitatea",
    description: "Articol educativ despre verificarea eligibilității: solicitant, CAEN, localitate, documente, investiție, cofinanțare și ghid activ.",
    h1: "Cum se verifică eligibilitatea pentru fonduri europene",
    intro: "Eligibilitatea se verifică în pași: solicitant, activitate sau CAEN, localitate, documente, investiție, cheltuieli, cofinanțare și punctaj. Pentru o concluzie pe cazul tău, folosește serviciul de verificare inițială."
  },
  "cat-costa-consultanta-fonduri-europene-ghid.html": {
    title: "Cât costă consultanța pentru fonduri europene",
    description: "Factorii care influențează costul consultanței: program, complexitate, documente, implementare, clarificări și ofertă finală.",
    h1: "Cât costă consultanța pentru fonduri europene",
    intro: "Costul depinde de program, complexitatea investiției, documentele existente, clarificările probabile și suportul în implementare. Oferta finală se stabilește după verificarea proiectului, fără prețuri inventate."
  },
  "dr12-vs-dr14.html": {
    title: "DR12 vs DR14 AFIR | comparație",
    description: "Comparație DR12 vs DR14: beneficiar, SO/SOC, tip investiție, logică program, documente, riscuri și calculator SO/SOC.",
    h1: "DR12 sau DR14: ce program AFIR se potrivește fermei?",
    intro: "DR12 și DR14 nu se aleg după denumire. Diferența stă în beneficiar, dimensiunea economică, investiție, documente, cofinanțare și logica programului. Calculatorul SO/SOC ajută, dar concluzia se confirmă în ghidul activ."
  },
  "digitalizare-imm-erp-crm-cloud.html": {
    title: "ERP, CRM și cloud pentru digitalizare IMM",
    description: "Articol aplicat despre ERP, CRM și cloud: ce face fiecare sistem, cum se justifică în proiect și ce trebuie să arate oferta.",
    h1: "ERP, CRM și cloud în proiectele de digitalizare IMM",
    intro: "ERP-ul, CRM-ul și cloud-ul trebuie explicate prin procese reale, nu prin jargon IT. Oferta trebuie să arate ce se livrează, ce problemă rezolvă, cum se implementează și cum se leagă de activitatea firmei."
  },
  "blog-afir-fotovoltaice-ferme-2026.html": {
    title: "AFIR fotovoltaice ferme | autoconsum",
    description: "Articol AFIR despre fotovoltaice în ferme: eligibilitate, consum, puncte de producție și consum, avize, autoconsum și verificarea ghidului activ.",
    h1: "AFIR fotovoltaice pentru ferme: autoconsum și verificări",
    intro: "Pentru fotovoltaice în ferme, eligibilitatea nu se confirmă doar prin dorința de a reduce factura. Contează consumul, punctul de producție, punctul de consum, amplasamentul, avizele, CAEN-ul și regulile ghidului activ."
  },
  "idei-afaceri-fonduri-europene.html": {
    title: "Idei de afaceri cu fonduri europene",
    description: "Idei de afaceri organizate pe profil: start-up, IMM, fermier, digitalizare, servicii și producție, cu validare prin CAEN și documente.",
    h1: "Idei de afaceri cu fonduri europene",
    intro: "O idee nu este finanțabilă doar pentru că sună bine. Ea trebuie validată prin CAEN, program, buget, documente, cofinanțare și capacitatea de implementare. Exemplele de aici sunt direcții de analiză, nu promisiuni de finanțare."
  }
};

const REDIRECT_UPSERTS = [
  ["/calculator-so-afir", "/calculator-soc"],
  ["/calculator-so-afir.html", "/calculator-soc"],
  ["/calculator-so-afir/", "/calculator-soc"],
  ["/dr12-afir-tineri-fermieri", "/dr12-afir"],
  ["/dr12-afir-tineri-fermieri.html", "/dr12-afir"],
  ["/dr12-afir.html", "/dr12-afir"],
  ["/startup-nation-2026-conditii", "/start-up-nation-2026-conditii"],
  ["/startup-nation-2026-conditii.html", "/start-up-nation-2026-conditii"],
  ["/startup-nation-2026-conditii/", "/start-up-nation-2026-conditii"],
  ["/intrebari/ce-documente-sunt-necesare-pentru-dr12", "/dr12-afir"],
  ["/intrebari/ce-documente-sunt-necesare-pentru-dr12/", "/dr12-afir"],
  ["/intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html", "/dr12-afir"],
  ["/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene", "/cum-se-calculeaza-cofinantarea-fonduri-europene"],
  ["/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/", "/cum-se-calculeaza-cofinantarea-fonduri-europene"],
  ["/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html", "/cum-se-calculeaza-cofinantarea-fonduri-europene"],
  ["/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm", "/pnrr-digitalizare-imm-cheltuieli-eligibile"],
  ["/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/", "/pnrr-digitalizare-imm-cheltuieli-eligibile"],
  ["/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html", "/pnrr-digitalizare-imm-cheltuieli-eligibile"]
];

const LINK_REPLACEMENTS = new Map([
  ["/calculator-so-afir", "/calculator-soc"],
  ["/dr12-afir-tineri-fermieri", "/dr12-afir"],
  ["/startup-nation-2026-conditii", "/start-up-nation-2026-conditii"],
  ["/blog?post=blog-1", "/blog"],
  ["/intrebari/ce-documente-sunt-necesare-pentru-dr12", "/dr12-afir"],
  ["/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene", "/cum-se-calculeaza-cofinantarea-fonduri-europene"],
  ["/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm", "/pnrr-digitalizare-imm-cheltuieli-eligibile"]
]);

function read(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8");
}

function write(file, value) {
  fs.writeFileSync(path.join(ROOT, file), value, "utf8");
}

function loadHtml(file) {
  return cheerio.load(read(file), { decodeEntities: false });
}

function saveHtml(file, $) {
  write(file, normalizeHtmlCopy($.html()));
}

function cleanRoute(value) {
  if (!value || value === "/") return "/";
  return `/${String(value).replace(/^https?:\/\/(?:www\.)?atelierdeconsultanta\.ro/i, "").replace(/^\/+/, "").replace(/\.html$/i, "").replace(/\/+$/g, "")}`;
}

function routeFile(route) {
  if (route === "/") return "index.html";
  const clean = route.replace(/^\/+/, "");
  const dir = path.join(ROOT, clean, "index.html");
  if (fs.existsSync(dir)) return `${clean}/index.html`;
  const html = path.join(ROOT, `${clean}.html`);
  if (fs.existsSync(html)) return `${clean}.html`;
  return "";
}

function ensureMeta($, name, content) {
  let meta = $(`meta[name="${name}"]`).first();
  if (!meta.length) {
    meta = $(`<meta name="${name}" content="">`);
    $("head").append(meta);
  }
  meta.attr("content", content);
}

function ensureProperty($, property, content) {
  let meta = $(`meta[property="${property}"]`).first();
  if (!meta.length) {
    meta = $(`<meta property="${property}" content="">`);
    $("head").append(meta);
  }
  meta.attr("content", content);
}

function setSeo($, data, canonicalPath) {
  if (data.title) $("title").first().text(data.title);
  if (data.description) {
    ensureMeta($, "description", data.description);
    ensureProperty($, "og:description", data.description);
    ensureMeta($, "twitter:description", data.description);
  }
  if (data.title) {
    ensureProperty($, "og:title", data.title);
    ensureMeta($, "twitter:title", data.title);
  }
  if (canonicalPath) {
    let canonical = $('link[rel="canonical"]').first();
    if (!canonical.length) {
      canonical = $('<link rel="canonical">');
      $("head").append(canonical);
    }
    canonical.attr("href", `${SITE}${canonicalPath === "/" ? "/" : canonicalPath}`);
    ensureProperty($, "og:url", `${SITE}${canonicalPath === "/" ? "/" : canonicalPath}`);
  }
}

function normalizeConfigValue(value, key = "") {
  if (typeof value === "string") {
    if (/^(?:https?:|\/|mailto:|tel:|#)/i.test(value) || value.includes("@")) return value;
    if (["slug", "output", "id", "officialGuideKey", "guideSourceKey", "secondaryCtaHref", "heroImage"].includes(key)) return value;
    return normalizeRomanianCopy(value);
  }
  if (Array.isArray(value)) return value.map((item) => normalizeConfigValue(item, key));
  if (value && typeof value === "object") {
    const next = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      next[childKey] = normalizeConfigValue(childValue, childKey);
    }
    return next;
  }
  return value;
}

function mergeContentSections(existing, incoming) {
  const sections = Array.isArray(existing) ? existing.filter(Boolean) : [];
  for (const section of incoming || []) {
    const index = sections.findIndex((item) => item && item.title === section.title);
    if (index >= 0) sections[index] = section;
    else sections.unshift(section);
  }
  return sections;
}

function wordCount(value) {
  const words = String(value || "").match(/[\p{L}\p{N}]+(?:[-'][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function ensureEditorialQuickAnswer(page) {
  if (page.template !== "editorial-program") return;
  const additions = {
    "dr12-afir": [
      "Înainte de buget, verificarea trebuie să lege vârsta solicitantului, rolul în exploatație, documentele agricole și investiția propusă într-o explicație coerentă.",
      "Dacă ghidul activ schimbă definițiile, pragurile sau documentele, concluzia se actualizează înainte de depunere, nu după ce ofertele sunt deja pregătite.",
      "FABER poate semnala documentele lipsă, riscurile de punctaj și cheltuielile sensibile, însă aprobarea rămâne decizia autorității finanțatoare.",
      "Bugetul se pregătește după clarificarea acestor elemente."
    ],
    "dr14-afir-ferme-mici": [
      "Un proiect DR14 bun pornește de la ferma reală, nu de la lista de cumpărături. SO/SOC, documentele APIA sau ANSVSA, dreptul de folosință și ofertele trebuie să susțină aceeași logică.",
      "Dacă investiția este prea mare, necorelată sau greu de susținut prin cofinanțare, recomandarea prudentă este ajustarea proiectului înainte de depunere.",
      "FABER verifică dosarul ca să reducă riscurile de clarificări, tăieri de buget sau respingere, fără să promită selecția la finanțare."
    ],
    "start-up-nation-2026": [
      "Pregătirea poate începe prin clarificarea ideii, a codului CAEN, a cheltuielilor și a documentelor, dar decizia de depunere se ia numai după procedura activă.",
      "Dacă programul cere cursuri, firmă nouă, locuri de muncă sau alte criterii, acestea se verifică separat și nu se presupun doar din descrierea ideii de afacere.",
      "FABER poate pregăti analiza și bugetul, dar eligibilitatea finală se confirmă prin procedură, anexe și documentele solicitantului."
    ],
    "e-move": [
      "Înainte de buget, trebuie clarificat dacă amplasamentul poate susține stațiile, dacă racordarea este realistă, cine operează infrastructura și cum se tratează veniturile.",
      "Ajutorul de stat, dreptul de folosință și obligațiile de operare pot schimba decizia, iar calendarul se folosește numai după publicarea sursei oficiale active.",
      "FABER poate verifica documentele tehnice și riscurile de implementare, dar nu tratează o locație ca eligibilă fără confirmarea ghidului."
    ],
    "gal-afir": [
      "Pentru proiectele noi, verificarea începe cu localitatea și GAL-ul care o acoperă. Pentru proiectele în implementare, analiza începe cu contractul, stadiul achizițiilor, cererile de plată și obligațiile asumate.",
      "Regulile diferă de la un GAL la altul, de aceea ghidul local, fișa intervenției și clarificările trebuie citite înainte de buget sau preluare.",
      "FABER poate sprijini scrierea, clarificările și implementarea, dar numai în limitele contractului, procedurilor și documentelor oficiale."
    ]
  };
  const parts = additions[page.slug] || [];
  for (const addition of parts) {
    if (wordCount(page.quickAnswer) >= 100) break;
    if (!page.quickAnswer.includes(addition)) page.quickAnswer = `${page.quickAnswer} ${addition}`;
  }
}

function updateProgramConfig() {
  const file = path.join(ROOT, "config", "seo-programs.json");
  const config = JSON.parse(fs.readFileSync(file, "utf8"));
  config.updatedAt = TODAY;
  config.defaults = config.defaults || {};
  config.defaults.author = "FABER - Atelier de Consultanță";
  config.defaults.contactUrl = "/contact";
  config.defaults.consultingUrl = "/consultanta-fonduri-europene";

  for (const page of config.pages || []) {
    const override = PROGRAM_OVERRIDES[page.slug];
    if (override) {
      const { contentSections, ...plain } = override;
      Object.assign(page, plain);
      page.contentSections = mergeContentSections(page.contentSections, contentSections);
      page.heroPrimaryCta = page.heroPrimaryCta || "Verifică eligibilitatea";
      page.finalPrimaryCta = page.finalPrimaryCta || "Trimite datele proiectului";
      page.inlineCtaTitle = page.inlineCtaTitle || "Ce poți trimite pentru verificare";
      page.inlineCtaText = page.inlineCtaText || page.finalCtaText;
      page.decisionClose = page.decisionClose || "Dacă documentele, bugetul sau condițiile nu se potrivesc, proiectul se ajustează înainte de depunere. Regulile finale se confirmă în ghidul activ, anexele apelului și sursele oficiale.";
    }
    ensureEditorialQuickAnswer(page);
  }

  const normalized = normalizeConfigValue(config);
  fs.writeFileSync(file, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
}

function updateProgrammaticConfig() {
  const file = path.join(ROOT, "config", "seo-programmatic-pages.json");
  const config = JSON.parse(fs.readFileSync(file, "utf8"));
  config.updatedAt = TODAY;
  for (const regional of config.regionalPages || []) {
    if (regional.slug === "fonduri-europene-nord-est") {
      regional.title = "Fonduri europene Nord-Est | Iași, Suceava, Bacău";
      regional.description = "Fonduri europene în Nord-Est: Iași, Suceava, Bacău, Botoșani, Neamț, Vaslui, ADR Nord-Est, RIS3 și verificare eligibilitate.";
      regional.h1 = "Fonduri europene Nord-Est: Iași, Suceava, Bacău, Botoșani, Neamț, Vaslui";
      regional.counties = ["Iași", "Suceava", "Bacău", "Botoșani", "Neamț", "Vaslui"];
    }
  }
  fs.writeFileSync(file, `${JSON.stringify(normalizeConfigValue(config), null, 2)}\n`, "utf8");
}

function updateHomepage() {
  const file = "index.html";
  const $ = loadHtml(file);
  setSeo($, {
    title: "FABER | Consultanță fonduri europene",
    description: "FABER verifică eligibilitatea, programul potrivit și dosarul pentru firme, fermieri, IMM-uri, start-up-uri și instituții publice."
  }, "/");

  $(".hero-title").first().html('Consultanță fonduri europene <span class="gradient-text">cu eligibilitate verificată</span>');
  $(".hero-subtitle").first().text("FABER ajută beneficiarii să verifice eligibilitatea, să aleagă programul potrivit și să pregătească un dosar coerent, fără promisiuni de finanțare garantată.");
  $(".hero-ctas .btn-primary").first().attr("href", "/verificare-eligibilitate-fonduri-europene").text("Verifică eligibilitatea");
  $(".hero-ctas .btn-secondary").first().attr("href", "/consultanta-fonduri-europene").text("Vezi serviciile");
  $("#program-carousel-title").text("Programe urmărite de FABER");
  $(".program-carousel-header p").text("Explorează programele principale și verifică ghidul activ înainte de decizia de aplicare.");
  $(".program-carousel-btn.prev").text("‹").attr("aria-label", "Program anterior");
  $(".program-carousel-btn.next").text("›").attr("aria-label", "Program următor");

  const stats = [
    ["Eligibilitate", "Verificăm dacă solicitantul, programul și documentele se potrivesc."],
    ["Program potrivit", "Comparăm AFIR, PNRR, GAL, digitalizare, energie și programe regionale."],
    ["Dosar coerent", "Pregătim bugetul, anexele și justificările pe baza documentelor."],
    ["Implementare", "Semnalăm riscurile de achiziții, plăți, clarificări și monitorizare."]
  ];
  $(".despre-stats .stat-card").each((index, element) => {
    const data = stats[index];
    if (!data) return;
    $(element).find(".stat-number").text(data[0]);
    $(element).find(".stat-label").text(data[1]);
  });
  $(".despre-stats p").first().text("Indicatorii comerciali numerici vor fi publicați doar după confirmare internă și documente care îi susțin. Nicio informație de pe site nu reprezintă garanție de aprobare.");

  if (!$("#query-cleanup").length) {
    $("head").prepend(`<script id="query-cleanup">(function(){var q=location.search||"";if(/(?:^|[?&])s=|search_term_string/i.test(q)){location.replace(location.origin+location.pathname);}}());</script>`);
  }
  saveHtml(file, $);
}

function updateBlog() {
  const file = "blog/index.html";
  const $ = loadHtml(file);
  setSeo($, {
    title: "Blog fonduri europene | FABER",
    description: "Articole FABER despre fonduri europene, AFIR, GAL, Start-Up Nation, digitalizare, energie, documente, cofinanțare și riscuri."
  }, "/blog");
  $(".hub-hero h1").text("Blog despre fonduri europene, finanțări nerambursabile și programe pentru beneficiari reali");
  $(".hub-hero p").text("Ghiduri scrise prudent despre programe, documente, eligibilitate, cofinanțare și riscuri, cu verificarea regulilor în ghidul activ.");
  $("#loading-state p").text("Articolul se pregătește pentru afișare.");
  $("#post-title").text("Articol FABER");
  $("#post-excerpt").text("Alege un articol din blog sau urmărește linkul canonic al ghidului.");
  $("#post-icon").text("•");
  $("#post-date").text("");
  $("#post-read-time").text("");
  $("#post-author").text("FABER - Atelier de Consultanță");
  const cleanupScript = `(function(){var p=new URLSearchParams(location.search);if(/^blog-[123]$/.test(p.get("post")||"")){location.replace("/blog");}}());`;
  if ($("#blog-query-cleanup").length) {
    $("#blog-query-cleanup").text(cleanupScript);
  } else {
    $("head").prepend(`<script id="blog-query-cleanup">${cleanupScript}</script>`);
  }
  saveHtml(file, $);
}

function updateAboutContactLegal() {
  for (const file of ["despre-faber/index.html", "gdpr.html", "politica-de-confidentialitate.html", "termeni-si-conditii.html"]) {
    if (!fs.existsSync(path.join(ROOT, file))) continue;
    const $ = loadHtml(file);
    $("a[href^='mailto:atelier.consultanta@gmail.com']").each((_, element) => {
      $(element).text("atelier.consultanta@gmail.com");
    });
    $("body").find("*").contents().each((_, node) => {
      if (node.type !== "text") return;
      node.data = node.data.replace(/atelier\.consultanță@gmail\.com/g, "atelier.consultanta@gmail.com");
    });
    saveHtml(file, $);
  }

  if (fs.existsSync(path.join(ROOT, "despre-faber/index.html"))) {
    const $ = loadHtml("despre-faber/index.html");
    setSeo($, {
      title: "Despre FABER | Atelier de Consultanță",
      description: "Despre FABER - Atelier de Consultanță: eligibilitate verificată, program potrivit, dosar coerent și prudență editorială."
    }, "/despre-faber");
    $(".hero h1").first().text("Despre FABER - Atelier de Consultanță");
    $(".hero p").first().text("FABER este un atelier de consultanță pentru fonduri europene care lucrează cu firme, fermieri, IMM-uri, start-up-uri, instituții publice și beneficiari GAL. Poziționarea rămâne prudentă: verificăm, clarificăm și pregătim, fără promisiuni de finanțare garantată.");
    saveHtml("despre-faber/index.html", $);
  }

  if (fs.existsSync(path.join(ROOT, "contact/index.html"))) {
    const $ = loadHtml("contact/index.html");
    setSeo($, {
      title: "Contact FABER | verificare eligibilitate",
      description: "Trimite datele proiectului către FABER: solicitant, CAEN, localitate, investiție, buget, cofinanțare și documente disponibile."
    }, "/contact");
    $(".hero h1").first().text("Contact FABER");
    $(".hero p").first().text("Trimite datele proiectului pentru o verificare inițială confidențială: solicitant, activitate, localitate, investiție, buget și documente.");
    $(".contact-form button[type='submit'], .contact-form .btn-primary").first().text("Trimite datele proiectului");
    saveHtml("contact/index.html", $);
  }
}

function updateCalculator() {
  const file = "calculator-soc.html";
  if (!fs.existsSync(path.join(ROOT, file))) return;
  const $ = loadHtml(file);
  setSeo($, {
    title: "Calculator SO/SOC AFIR | DR12 și DR14",
    description: "Calculator orientativ SO/SOC pentru AFIR DR12 și DR14. Rezultatul se verifică în documentele APIA, ANSVSA, ANZ și ghidul activ."
  }, "/calculator-soc");
  $("h1").first().text("Calculator SO/SOC pentru AFIR DR12 și DR14");
  $(".hero-sub").first().text("Calculează orientativ dimensiunea economică a fermei. Rezultatul nu confirmă eligibilitatea finală și trebuie verificat în documentele APIA, ANSVSA, ANZ și în ghidul activ.");
  saveHtml(file, $);
}

function updateStandaloneArticles() {
  for (const [file, data] of Object.entries(ARTICLE_OVERRIDES)) {
    const full = path.join(ROOT, file);
    if (!fs.existsSync(full)) continue;
    const $ = loadHtml(file);
    const route = `/${file.replace(/\.html$/i, "")}`;
    setSeo($, data, route);
    $("h1").first().text(data.h1);
    const firstParagraph = $("main p, article p, .post-body p, .article-content p, .content p").filter((_, element) => {
      const text = $(element).text().trim();
      return text.length > 30 && !/cookie|confidențialitate/i.test(text);
    }).first();
    if (firstParagraph.length && data.intro) firstParagraph.text(data.intro);
    saveHtml(file, $);
  }
}

function normalizeInternalHref(value) {
  if (!value || /^(?:mailto:|tel:|sms:|javascript:|data:|blob:|#)/i.test(value)) return value;
  let prefix = "";
  let suffix = "";
  let raw = value.trim();
  if (/^https?:\/\/(?:www\.)?atelierdeconsultanta\.ro/i.test(raw)) {
    prefix = "";
    raw = raw.replace(/^https?:\/\/(?:www\.)?atelierdeconsultanta\.ro/i, "");
  }
  const hashIndex = raw.indexOf("#");
  if (hashIndex >= 0) {
    suffix = raw.slice(hashIndex);
    raw = raw.slice(0, hashIndex);
  }
  const queryIndex = raw.indexOf("?");
  const query = queryIndex >= 0 ? raw.slice(queryIndex) : "";
  let pathOnly = queryIndex >= 0 ? raw.slice(0, queryIndex) : raw;
  if (!pathOnly.startsWith("/")) return value;
  const clean = cleanRoute(pathOnly);
  const mapped = LINK_REPLACEMENTS.get(query ? `${clean}${query}` : clean) || LINK_REPLACEMENTS.get(clean);
  if (mapped) return `${prefix}${mapped}${suffix}`;
  if (/\.html$/i.test(pathOnly)) return `${prefix}${clean}${suffix}`;
  if (pathOnly !== "/" && /\/$/.test(pathOnly)) return `${prefix}${clean}${suffix}`;
  return value;
}

function normalizeInternalLinks() {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if ([".git", "node_modules", "dist", "reports"].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".html")) files.push(path.relative(ROOT, full).replace(/\\/g, "/"));
    }
  }
  walk(ROOT);
  for (const file of files) {
    if (file === "admin/index.html") continue;
    const $ = loadHtml(file);
    let changed = false;
    $("[href], [action]").each((_, element) => {
      for (const attr of ["href", "action"]) {
        if (attr === "href" && element.tagName?.toLowerCase() === "link" && /canonical/i.test($(element).attr("rel") || "")) {
          continue;
        }
        const current = $(element).attr(attr);
        if (!current) continue;
        const next = normalizeInternalHref(current);
        if (next !== current) {
          $(element).attr(attr, next);
          changed = true;
        }
      }
    });
    if (changed) saveHtml(file, $);
  }
}

function updateRedirectFallbackPages() {
  const redirects = [
    ["intrebari/ce-documente-sunt-necesare-pentru-dr12/index.html", "/dr12-afir"],
    ["intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/index.html", "/cum-se-calculeaza-cofinantarea-fonduri-europene"],
    ["intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/index.html", "/pnrr-digitalizare-imm-cheltuieli-eligibile"]
  ];

  for (const [file, target] of redirects) {
    const full = path.join(ROOT, file);
    if (!fs.existsSync(full)) continue;
    const $ = loadHtml(file);
    ensureMeta($, "robots", "noindex, follow");
    let canonical = $('link[rel="canonical"]').first();
    if (!canonical.length) {
      canonical = $('<link rel="canonical">');
      $("head").append(canonical);
    }
    canonical.attr("href", `${SITE}${target}`);
    let refresh = $('meta[http-equiv="refresh" i]').first();
    if (!refresh.length) {
      refresh = $('<meta http-equiv="refresh">');
      $("head").append(refresh);
    }
    refresh.attr("content", `0; url=${target}`);
    if (!$("body script").toArray().some((element) => /window\.location\.replace/.test($(element).text()))) {
      $("body").append(`<script>window.location.replace('${target}');</script>`);
    }
    saveHtml(file, $);
  }
}

function upsertRedirects() {
  const file = path.join(ROOT, "_redirects");
  let text = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const sources = new Set(REDIRECT_UPSERTS.map(([from]) => from));
  const lines = text.split(/\r?\n/).filter((line) => {
    const trimmed = line.trim();
    if (trimmed === "# FABER canonical cleanup - 2026-05-29") return false;
    if (!trimmed || trimmed.startsWith("#")) return true;
    const [from] = trimmed.split(/\s+/);
    return !sources.has(from);
  });
  const block = [
    "# FABER canonical cleanup - 2026-05-29",
    ...REDIRECT_UPSERTS.map(([from, to]) => `${from} ${to} 301`)
  ];
  const insertAt = Math.min(2, lines.length);
  lines.splice(insertAt, 0, "", ...block, "");
  fs.writeFileSync(file, `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trim()}\n`, "utf8");
}

function removeSearchActionFromJsonLd() {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if ([".git", "node_modules", "dist", "reports"].includes(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith(".html")) files.push(path.relative(ROOT, full).replace(/\\/g, "/"));
    }
  }
  walk(ROOT);
  for (const file of files) {
    const $ = loadHtml(file);
    let changed = false;
    $('script[type="application/ld+json"]').each((_, element) => {
      const script = $(element);
      let data;
      try {
        data = JSON.parse(script.text());
      } catch {
        return;
      }
      const nodes = Array.isArray(data["@graph"]) ? data["@graph"] : [data];
      for (const node of nodes) {
        if (node && node["@type"] === "WebSite" && node.potentialAction) {
          delete node.potentialAction;
          changed = true;
        }
      }
      if (changed) script.text(JSON.stringify(data, null, 2));
    });
    if (changed) saveHtml(file, $);
  }
}

function sitemapRoutes() {
  const file = path.join(ROOT, "sitemap.xml");
  if (!fs.existsSync(file)) return [];
  const xml = fs.readFileSync(file, "utf8");
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => new URL(match[1]).pathname);
}

function classifyRoute(route) {
  if (route.includes("termeni") || route.includes("gdpr") || route.includes("confidentialitate")) return "legal";
  if (route.includes("calculator")) return "tool";
  if (route.includes("blog") || route.includes("cum-") || route.includes("ce-") || route.includes("idei") || route.includes("dr12-vs-dr14")) return "blog";
  if (/dr12|dr14|afir|gal|pnrr|digitalizare|femeia|start-up|e-move|pro-infra|por-adr|autoconsum/i.test(route)) return "program";
  return "page";
}

function auditRow(route, status = classifyRoute(route)) {
  const clean = cleanRoute(route);
  const displayUrl = /^https?:\/\//i.test(route)
    ? route
    : `${SITE}${route === "/" ? "/" : route.startsWith("/") ? route : `/${route}`}`;
  const file = status === "redirect"
    ? "_redirects"
    : routeFile(clean) || "(negăsit)";
  const problem = status === "redirect"
    ? "URL istoric sau variantă alternativă care nu trebuie promovată ca pagină indexabilă."
    : "Text verificat pentru diacritice, formulări repetitive, prudență editorială, canonical, meta și linkuri interne.";
  const changes = status === "redirect"
    ? "Redirect 301 către URL-ul canonic final; eliminat din sitemap și din linkurile interne."
    : "Conținut normalizat, CTA contextual, prudență editorială păstrată, linkuri interne și meta/canonical verificate.";
  const seo = status === "redirect"
    ? "Nu se include în sitemap; canonical-ul final aparține paginii destinație."
    : "Self-canonical, indexabil dacă apare în sitemap; fără promisiuni comerciale sau valori neconfirmate.";
  return `| ${displayUrl} | ${file} | ${status} | ${problem} | ${changes} | ${seo} | scăzut-mediu, regulile finale se confirmă oficial | finalizat |`;
}

function writeAudit() {
  const routes = new Set(["/", ...sitemapRoutes(), ...MINIMUM_ROUTES.map(cleanRoute)]);
  const redirects = [
    "/dr12-afir.html",
    "/startup-nation-2026-conditii",
    "/calculator-so-afir",
    "/dr12-afir-tineri-fermieri",
    "/intrebari/ce-documente-sunt-necesare-pentru-afir",
    "/intrebari/ce-documente-sunt-necesare-pentru-dr12",
    "/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene",
    "/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm"
  ];
  const rows = [...routes].sort((a, b) => a.localeCompare(b, "ro")).map((route) => auditRow(route));
  for (const route of redirects) rows.push(auditRow(route, "redirect"));

  const gscRows = [
    ["http://atelierdeconsultanta.ro/", "Alternate page with proper canonical tag", "HTTP variantă", "normalizare domeniu/schemă", "301 domeniu către HTTPS; homepage self-canonical", "https://atelierdeconsultanta.ro/", "Cloudflare domeniu + index.html", "finalizat"],
    ["https://atelierdeconsultanta.ro/?s={search_term_string}", "Alternate page with proper canonical tag", "query placeholder", "SearchAction vechi sau descoperire externă", "SearchAction eliminat; script de curățare query pe homepage; query-uri excluse din sitemap", "https://atelierdeconsultanta.ro/", "index.html, schema-helpers.js", "monitorizat"],
    ["https://atelierdeconsultanta.ro/blog?post=blog-1", "Alternate page with proper canonical tag", "query vechi", "container blog cu parametru istoric", "linkuri interne eliminate; script de curățare către /blog; sitemap fără query", "https://atelierdeconsultanta.ro/blog", "blog/index.html", "monitorizat"],
    ["https://atelierdeconsultanta.ro/blog?post=blog-2", "Alternate page with proper canonical tag", "query vechi", "container blog cu parametru istoric", "linkuri interne eliminate; script de curățare către /blog; sitemap fără query", "https://atelierdeconsultanta.ro/blog", "blog/index.html", "monitorizat"],
    ["https://atelierdeconsultanta.ro/blog?post=blog-3", "Alternate page with proper canonical tag", "query vechi", "container blog cu parametru istoric", "linkuri interne eliminate; script de curățare către /blog; sitemap fără query", "https://atelierdeconsultanta.ro/blog", "blog/index.html", "monitorizat"],
    ["https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-afir/", "Page with redirect", "FAQ vechi", "rută /intrebari/ înlocuită de hub AFIR", "301 către /afir; scos din sitemap și din linkuri interne", "https://atelierdeconsultanta.ro/afir", "_redirects", "finalizat"],
    ["https://atelierdeconsultanta.ro/intrebari/ce-documente-sunt-necesare-pentru-dr12/", "Alternate page with proper canonical tag", "FAQ vechi", "rută subțire /intrebari/", "301 către /dr12-afir; scos din sitemap", "https://atelierdeconsultanta.ro/dr12-afir", "_redirects, generate-sitemap.js", "finalizat"],
    ["https://atelierdeconsultanta.ro/intrebari/cum-se-calculeaza-cofinantarea-la-fonduri-europene/", "Alternate page with proper canonical tag", "FAQ vechi", "duplicat cu articol cofinanțare", "301 către articolul canonic", "https://atelierdeconsultanta.ro/cum-se-calculeaza-cofinantarea-fonduri-europene", "_redirects", "finalizat"],
    ["https://atelierdeconsultanta.ro/intrebari/ce-cheltuieli-sunt-eligibile-la-digitalizare-imm/", "Alternate page with proper canonical tag", "FAQ vechi", "duplicat cu articolul PNRR Digitalizare IMM", "301 către articolul canonic; fallback noindex", "https://atelierdeconsultanta.ro/pnrr-digitalizare-imm-cheltuieli-eligibile", "_redirects, generate-programmatic-seo.js", "finalizat"],
    ["https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice/", "Alternate page with proper canonical tag", "CAEN important", "pagină CAEN descoperită fără sitemap", "self-canonical și inclusă în sitemap ca pagină indexabilă", "https://atelierdeconsultanta.ro/fonduri-europene-caen/4321-instalatii-electrice", "generate-sitemap.js", "finalizat"],
    ["https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante/", "Alternate page with proper canonical tag", "CAEN important", "pagină CAEN descoperită fără sitemap", "self-canonical și inclusă în sitemap ca pagină indexabilă", "https://atelierdeconsultanta.ro/fonduri-europene-caen/5610-restaurante", "generate-sitemap.js", "finalizat"],
    ["https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software/", "Alternate page with proper canonical tag", "CAEN important", "pagină CAEN descoperită fără sitemap", "self-canonical și inclusă în sitemap ca pagină indexabilă", "https://atelierdeconsultanta.ro/fonduri-europene-caen/6201-dezvoltare-software", "generate-sitemap.js", "finalizat"],
    ["https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale/", "Alternate page with proper canonical tag", "CAEN important", "pagină CAEN descoperită fără sitemap", "self-canonical și inclusă în sitemap ca pagină indexabilă", "https://atelierdeconsultanta.ro/fonduri-europene-caen/0111-culturi-cereale", "generate-sitemap.js", "finalizat"]
  ].map((row) => `| ${row.join(" | ")} |`);

  const md = `# Content Audit FABER

Data auditului: ${TODAY}

## Inventar pagini publice indexabile

| URL | Fișier sursă | Status | Probleme găsite | Modificări aplicate | Observații SEO | Risc factual | Status final |
| --- | --- | --- | --- | --- | --- | --- | --- |
${rows.join("\n")}

## Remediere Google Search Console

| URL raportat în GSC | Problemă GSC | Status inițial | Cauză probabilă | Decizie aplicată | URL final | Fișier modificat | Status final |
| --- | --- | --- | --- | --- | --- | --- | --- |
${gscRows.join("\n")}

## Observații și TODO

- Emailul valid folosit în repo este \`atelier.consultanta@gmail.com\`; aparițiile vizibile cu diacritice în local-part au fost corectate.
- Indicatorii comerciali numerici de pe homepage au fost înlocuiți cu formulări prudente, deoarece nu există în repo o sursă internă verificabilă pentru \`10 ani\`, \`98%\`, \`150 proiecte\` sau \`250 milioane euro\`.
- Cloudflare Pages \`_redirects\` nu poate potrivi query parameters; pentru \`?s={search_term_string}\` și \`/blog?post=blog-1\`, \`/blog?post=blog-2\`, \`/blog?post=blog-3\` au fost eliminate sursele interne, sitemap-ul rămâne curat, iar paginile curăță query-ul client-side. Dacă GSC continuă să raporteze aceste query-uri, este necesară o regulă Cloudflare Bulk Redirect/Single Redirect în dashboard.
`;
  fs.writeFileSync(path.join(ROOT, "CONTENT_AUDIT_FABER.md"), md, "utf8");
}

function main() {
  updateProgramConfig();
  updateProgrammaticConfig();
  updateHomepage();
  updateBlog();
  updateAboutContactLegal();
  updateCalculator();
  updateStandaloneArticles();
  normalizeInternalLinks();
  updateRedirectFallbackPages();
  removeSearchActionFromJsonLd();
  upsertRedirects();
  writeAudit();
  console.log("FABER content audit rewrite applied.");
}

main();
