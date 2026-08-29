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
  "diaspora-investeste-acasa": {
    eyebrow: "Antreprenoriat · investiții în România",
    lead: "Un reper practic pentru românii din diaspora care analizează înființarea unei afaceri în țară. Separăm informațiile deja anunțate oficial de regulile care încă lipsesc.",
    metrics: [["100 mil. €", "buget anunțat"], ["max. 200.000 €", "componentă nerambursabilă"], ["max. 60%", "din creditul de investiții"], ["5–10%", "contribuție proprie minimă anunțată"]],
    answer: "Programul a fost anunțat pentru întreprinderi nou-înființate, deținute majoritar de cetățeni români cu domiciliul sau reședința în străinătate. Comunicarea oficială descrie un credit de investiții susținut printr-o componentă nerambursabilă, însă procedura de înscriere, grila de evaluare și calendarul nu sunt încă publicate.",
    fit: ["Locuiești în străinătate și poți documenta domiciliul sau reședința.", "Vei înființa o întreprindere în România și vei păstra controlul majoritar.", "Ai un proiect de investiții bancabil și poți acoperi contribuția proprie și costurile neeligibile."],
    caution: ["Nu există încă o platformă de depunere ori un termen oficial de deschidere.", "Grantul anunțat nu este un avans independent, ci este legat de creditul de investiții.", "CAEN-urile, cheltuielile și condițiile complete trebuie reconfirmate după publicarea procedurii."],
    investments: [["Investiția productivă", "Echipamente, amenajări și active necesare afacerii vor trebui încadrate în lista finală de cheltuieli."], ["Capitalul afacerii", "Planul trebuie să arate sursele proprii, creditul, fluxul de numerar și capacitatea de rambursare."], ["Locuri de muncă și impact", "Documentează rezultatele economice, piața, furnizorii și modul în care investiția funcționează în România."]],
    documents: [["Identitate și legătura cu diaspora", "Acte de identitate, documente privind domiciliul sau reședința în străinătate și structura viitoarei societăți."], ["Planul de investiții", "Buget pe categorii, oferte comparabile, calendar, amplasament și justificarea tehnică a achizițiilor."], ["Dosarul financiar", "Contribuția proprie, ipotezele de venituri și cheltuieli, necesarul de credit și scenarii de rambursare."], ["Dreptul asupra amplasamentului", "Acte de proprietate, închiriere sau concesiune și verificarea autorizărilor necesare activității."]],
    steps: ["Confirmă profilul de beneficiar și pregătește dovada legăturii cu diaspora.", "Construiește investiția și bugetul fără a presupune că toate cheltuielile vor fi eligibile.", "Testează bancabilitatea și contribuția proprie cu o instituție financiară.", "Revalidează dosarul imediat ce procedura și calendarul oficial devin publice."],
    extraSources: [["Ministerul Finanțelor – informații instituționale", "https://mfinante.gov.ro/"]],
    faqs: [["Este deschisă depunerea?", "Nu. La 29 august 2026 era publicată comunicarea programului, nu o procedură de înscriere cu termen activ."], ["Grantul poate ajunge la 200.000 euro?", "Comunicarea oficială indică maximum 200.000 euro și maximum 60% din creditul de investiții; plafonul final se verifică în procedura aplicabilă."], ["Este suficient să fi lucrat în străinătate?", "Nu presupunem acest lucru. Condiția anunțată privește domiciliul sau reședința și deținerea majoritară; documentele exacte urmează să fie definite."], ["Pot înființa firma înainte de apel?", "Momentul optim depinde de condiția de întreprindere nou-înființată din procedura viitoare. Nu lua o decizie ireversibilă înainte de publicarea regulilor."], ["Este necesar un credit?", "Mecanismul anunțat este legat de un credit de investiții, deci bancabilitatea face parte din pregătire."], ["Ce pot pregăti acum?", "Profilul solicitantului, conceptul, piața, amplasamentul, ofertele, bugetul și sursele financiare, toate marcate ca versiune de lucru."]]
  },
  "e-drive": {
    eyebrow: "Transport rutier · vehicule cu emisii zero",
    lead: "Schema e-DRIVE explicată pe cele două măsuri: înlocuirea flotelor IMM-urilor și a vehiculelor operatorilor de transport rutier de persoane, cu plafoane și criterii diferite.",
    metrics: [["56,9 mil. €", "buget total al schemei"], ["15 mil. €", "măsura 1 · de minimis"], ["41,9 mil. €", "măsura 2 · competitivă"], ["max. 4 mil. €", "per beneficiar în măsura 2"]],
    answer: "e-DRIVE este schema aprobată pentru înlocuirea vehiculelor poluante cu vehicule electrice noi. Măsura 1 se adresează microîntreprinderilor și IMM-urilor pentru vehicule M1 și M2, iar măsura 2 operatorilor de transport rutier de persoane pentru M1, M2 și M3. Bugetul total este de 56,9 milioane euro. Aprobarea schemei nu echivalează cu deschiderea depunerii.",
    fit: ["Pentru măsura 1, ești microîntreprindere sau IMM și respecți sectoarele excluse de schema de minimis.", "Pentru măsura 2, desfășori transport rutier de persoane prin activitățile CAEN Rev. 3 prevăzute de schemă.", "Vehiculele propuse sunt noi și exclusiv electrice, iar vehiculele poluante înlocuite pot fi casate în termen."],
    caution: ["Vehiculele hibride și cele hibride reîncărcabile nu sunt vehicule cu emisii zero în sensul schemei.", "Vehiculul poluant înlocuit trebuie casat în maximum 60 de zile de la primirea vehiculului electric.", "TVA nu este eligibilă, iar ajutorul competitiv se raportează la diferența de cost față de alternativa convențională comparabilă."],
    investments: [["Măsura 1 · de minimis", "Vehicule electrice noi M1 și M2, în limita a 300.000 euro pe întreprindere unică; pentru un vehicul M1, ajutorul este limitat la 30.000 euro."], ["Măsura 2 · competitivă", "Vehicule electrice noi M1, M2 și M3 pentru transport rutier de persoane, cu maximum 4 milioane euro per beneficiar."], ["Tranziția flotei", "Analiza include vehiculele scoase din uz, infrastructura de încărcare, asigurarea, mentenanța și exploatarea noii flote."]],
    documents: [["Eligibilitatea întreprinderii", "Certificat constatator, activitatea CAEN când măsura o cere, licențe și structura întreprinderii unice."], ["Flota existentă", "Inventar, proprietate de minimum un an ori documentele excepției prevăzute de schemă, caracteristici tehnice și vehiculele propuse pentru casare."], ["Configurația noii flote", "Minimum două oferte în condițiile schemei, categorie de omologare, autonomie, capacitate, garanții și calendar de livrare."], ["Planul financiar", "Cost comparabil, ajutor solicitat, surse proprii, TVA neeligibilă și costurile operaționale neeligibile."]],
    steps: ["Alege măsura după categoria beneficiarului, activitate și vehicule.", "Verifică încadrarea ca întreprindere unică și ajutoarele de minimis relevante.", "Corelează fiecare vehicul nou cu obligația de casare în 60 de zile și cu infrastructura de încărcare.", "Depune numai după publicarea calendarului și a procedurii operaționale."],
    extraSources: [["Ordinul de modificare nr. 100/12.02.2026", "https://legislatie.just.ro/Public/DetaliiDocument/307361"]],
    faqs: [["Programul e-DRIVE este deschis?", "Nu. Schema este aprobată, dar la 29 august 2026 nu există un termen activ de depunere confirmat oficial."], ["Cine poate aplica la măsura 1?", "Microîntreprinderile și IMM-urile, indiferent de codul CAEN, cu respectarea sectoarelor excluse de schema de minimis și a tuturor condițiilor aplicabile."], ["Sunt eligibile vehiculele hibride?", "Nu. Schema vizează vehicule noi exclusiv electrice; o ofertă hibridă nu este echivalentă."], ["Care este plafonul de minimis?", "Măsura 1 folosește plafonul de 300.000 euro pe întreprindere unică; ajutorul pentru un vehicul M1 este limitat la 30.000 euro."], ["Ce înseamnă măsura competitivă?", "În măsura 2, ajutorul se raportează la costul suplimentar față de un vehicul convențional comparabil și nu poate depăși 4 milioane euro pe beneficiar."], ["Casarea este obligatorie?", "Da. Vehiculul poluant înlocuit trebuie casat în maximum 60 de zile de la primirea vehiculului cu emisii zero."], ["Cât trebuie păstrată investiția?", "Vehiculele finanțate trebuie menținute în investiție timp de cinci ani, conform schemei."]]
  },
  "e-mobility-ro": {
    eyebrow: "Infrastructură rutieră · reîncărcare electrică",
    lead: "e-Mobility RO este prezentat ca proiect de infrastructură, nu ca simplă achiziție de stații: amplasamentul, racordarea, accesul public și configurația tehnică decid fezabilitatea.",
    metrics: [["299 mil. €", "bugetul schemei"], ["procedură", "competitivă"], ["TEN-T", "coridoare și proximitate"], ["max. 40%", "din buget pentru un beneficiar"]],
    answer: "Schema e-Mobility RO susține infrastructură de reîncărcare de-a lungul autostrăzilor, drumurilor expres și drumurilor naționale ori în proximitatea admisă a ieșirilor rețelei TEN-T. Pot fi analizate și producția regenerabilă și stocarea asociate, dacă respectă limitele și legătura funcțională prevăzute de schemă.",
    fit: ["Întreprinderea este eligibilă conform schemei și nu se află în situațiile de excludere.", "Ai un amplasament eligibil, cu drepturi clare și acces rutier demonstrabil.", "Poți documenta racordarea, puterea disponibilă, accesul public și funcționarea pe termen lung."],
    caution: ["O distanță mică față de un drum nu dovedește singură eligibilitatea amplasamentului.", "Întreprinderile nou-înființate sunt excluse de schema aprobată.", "Procentul de ajutor este rezultat al procedurii competitive și nu trebuie bugetat automat la maximum."],
    investments: [["Stații și puncte de reîncărcare", "Echipamente, montaj, sisteme de plată, comunicații, semnalizare și lucrările strict legate de infrastructură."], ["Racordare și lucrări", "Branșament, transformare, proiectare și lucrări necesare punerii în funcțiune, încadrate după regulile apelului."], ["Regenerabile și stocare asociată", "Componentele asociate pot fi analizate doar în limitele tehnice și funcționale stabilite de schemă."]],
    documents: [["Amplasament și traseu", "Coordonate, extras de carte funciară, drept de folosință, acces din rețeaua rutieră și dovada distanței admise."], ["Racordare", "Aviz sau studiu de soluție, putere disponibilă, lucrări, termene și riscuri de implementare."], ["Soluția tehnică", "Număr de puncte, puteri, standarde, interoperabilitate, plată, operare și mentenanță."], ["Modelul economic", "Trafic estimat, tarife, costuri, venituri, ofertă competitivă și sustenabilitatea după finalizare."]],
    steps: ["Elimină amplasamentele care nu satisfac coridorul și accesul eligibil.", "Cere date de racordare înainte de a fixa bugetul și calendarul.", "Dimensionează stațiile după trafic și obligațiile tehnice, nu doar după plafon.", "Pregătește oferta competitivă după publicarea documentelor de depunere."],
    extraSources: [["Schema e-Mobility RO – Portal Legislativ", "https://legislatie.just.ro/Public/DetaliiDocument/301593"]],
    faqs: [["e-Mobility RO este deschis pentru depuneri?", "Nu este prezentat ca apel deschis. Schema este aprobată, iar un calendar activ trebuie confirmat separat."], ["Pot aplica firmele nou-înființate?", "Schema aprobată exclude întreprinderile nou-înființate; istoricul și situațiile financiare trebuie analizate."], ["Unde poate fi amplasată stația?", "Pe tipurile de drum și în proximitatea unei ieșiri TEN-T admise de schemă, cu accesul și distanța documentate."], ["Este eligibilă o baterie?", "Stocarea poate fi asociată infrastructurii în condițiile schemei; nu este tratată ca proiect stand-alone în această pagină."], ["Ajutorul este 100%?", "Schema permite un maximum în procedura competitivă, însă solicitantul trebuie să își asume procentul rezultat și costurile neeligibile."], ["Care este prima verificare tehnică?", "Amplasamentul și racordarea. Fără drept de folosință, acces eligibil și putere disponibilă, bugetul echipamentelor nu este suficient."]]
  },
  "fondul-modernizare-pc1-stocare": {
    eyebrow: "Fondul pentru Modernizare · Program-cheie 1",
    lead: "Un cadru de pregătire pentru capacități noi de stocare stand-alone racordate la rețea, construit pe ghidul aprobat prin Ordinul Ministerului Energiei nr. 915/14.08.2026.",
    metrics: [["150 mil. €", "bugetul ghidului aprobat"], ["max. 15 mil. €", "per întreprindere"], ["69.000 €/MWh", "plafon al ajutorului"], ["stand-alone", "stocare racordată la rețea"]],
    answer: "Ghidul aprobat vizează investiții noi în capacități de stocare stand-alone conectate la rețea. Bugetul este de 150 milioane euro, ajutorul poate ajunge la 15 milioane euro pe întreprindere și este plafonat la 69.000 euro/MWh. Perioada și mecanismul operațional de depunere nu sunt încă anunțate.",
    fit: ["Activitatea și structura solicitantului se încadrează în condițiile domeniului energetic.", "Proiectul este o capacitate de stocare stand-alone și are o soluție credibilă de racordare.", "Poți demonstra capacitatea financiară, drepturile asupra terenului și implementarea individuală a proiectului."],
    caution: ["Pagina nu descrie un apel deschis: ghidul este aprobat, dar calendarul depunerii nu este publicat.", "Plafonul pe MWh este o limită a ajutorului, nu o promisiune de finanțare la valoarea maximă.", "Racordarea, licențierea și veniturile din piața de energie necesită analiză separată."],
    investments: [["Sisteme de baterii", "Echipamente noi de stocare, conversie, control, protecție și monitorizare, în condițiile ghidului aprobat."], ["Lucrări și racordare", "Construcții, instalații și componente de racordare direct legate de punerea în funcțiune a capacității."], ["Proiectare și integrare", "Studii și servicii tehnice eligibile numai dacă sunt prevăzute și încadrate corect în ghidul aprobat."]],
    documents: [["Societatea și activitatea", "Certificat constatator, CAEN, situații financiare ori capital social pentru solicitantul nou-înființat și declarații de eligibilitate."], ["Teren și urbanism", "Drept real sau de folosință, certificat de urbanism, restricții, acces și calendarul autorizării."], ["Racordare și capacitate", "Studiu de soluție, ATR sau stadiul acestuia, putere, capacitate MWh, cicluri și punctul de conexiune."], ["Model financiar", "Cost pe MWh, oferte, surse proprii, scenarii de venit, sensibilități și costurile neeligibile."]],
    steps: ["Fixează puterea și capacitatea numai după o analiză de racordare și piață.", "Verifică solicitantul, CAEN-ul și situația financiară în ghidul aprobat.", "Construiește un buget trasabil pe MWh și un calendar realist de autorizare.", "Revalidează eventualele corrigenda și calendarul înaintea unei decizii de investiție."],
    extraSources: [["Cadrul Fondului pentru Modernizare – OUG nr. 60/2022", "https://legislatie.just.ro/Public/DetaliiDocument/294449"]],
    faqs: [["Apelul PC1 stocare este deschis?", "Nu. Ghidul final a fost publicat la 17 august 2026, dar la 29 august 2026 perioada și mecanismul operațional de depunere nu erau anunțate."], ["Ce înseamnă stand-alone?", "Capacitatea de stocare este proiectată ca activ distinct conectat la rețea, nu doar ca anexă a unei centrale de producție pentru autoconsum."], ["Pot aplica firme nou-înființate?", "Da, dacă îndeplinesc condițiile aplicabile din ghidul aprobat, inclusiv cerințele juridice și financiare prevăzute pentru această categorie."], ["Finanțarea ajunge la 15 milioane euro?", "Da. Ghidul aprobat stabilește un plafon de maximum 15.000.000 euro pe întreprindere, în limita costului eligibil, a bugetului și a procedurii competitive."], ["Este finanțarea 100%?", "Poate ajunge la maximum 100% conform ghidului aprobat, în limita costului eligibil și a competiției; costurile neeligibile și depășirile rămân în sarcina beneficiarului."], ["Ce poate bloca proiectul?", "Lipsa unei soluții de racordare, drepturile insuficiente asupra terenului, calendarul de autorizare și un model economic neverificat sunt riscuri majore."]]
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
  <meta property="og:type" content="website"><meta property="og:locale" content="ro_RO"><meta property="og:title" content="${e(program.metaTitle)}"><meta property="og:description" content="${e(program.metaDescription)}"><meta property="og:url" content="${canonical}"><meta property="og:image" content="${SITE}/og-image.jpg"><meta name="twitter:card" content="summary_large_image">
  <link rel="stylesheet" href="/assets/seo-hub.css"><link rel="stylesheet" href="/assets/program-showcase-2026.css?v=20260809-1">
  <script type="application/ld+json">${JSON.stringify(schema).replace(/</g, "\\u003c")}</script>
</head><body class="program-showcase-page page-family-program" data-page-type="program" data-program-id="${e(program.id)}">
${HEADER}
<main>
  <section class="program-hero" aria-labelledby="program-title">
    <div class="program-hero__content">
      <nav class="program-breadcrumbs" aria-label="Breadcrumb"><a href="/">Acasă</a><span>/</span><a href="/fonduri-europene">Programe</a><span>/</span><span aria-current="page">${e(program.shortName)}</span></nav>
      <p class="program-eyebrow">${e(content.eyebrow)}</p><h1 id="program-title">${e(program.name)}</h1><p class="program-lead">${e(content.lead)}</p>
      <div class="program-status" data-program-status="${e(program.status)}"><span aria-hidden="true"></span>${e(program.statusLabel)}</div>
      <div class="program-hero__actions"><a class="program-button program-button--primary" href="/contact#program_slug=${e(program.slug)}">Verifică proiectul</a><a class="program-button" href="#raspuns-rapid">Vezi condițiile</a></div>
    </div><div class="program-hero__visual">${renderSvg(program.slug)}</div>
  </section>
  <section class="program-metrics" aria-label="Repere de finanțare">${content.metrics.map(([value, label]) => `<div><strong>${e(value)}</strong><span>${e(label)}</span></div>`).join("")}</section>
  <section class="program-section program-section--answer" id="raspuns-rapid"><div><p class="section-kicker">Răspuns rapid</p><h2>Ce finanțează și în ce stadiu este?</h2></div><div class="answer-card"><p>${e(content.answer)}</p><small>Statut verificat la <time datetime="${program.verifiedAt}">${program.verifiedAt}</time>. ${e(program.editorialDisclaimer)}</small></div></section>
  <section class="program-section program-section--fit"><div class="section-heading"><p class="section-kicker">Filtru inițial</p><h2>Merită continuată analiza?</h2><p>Compară profilul proiectului cu aceste criterii înainte de a investi în documentație. Concluzia finală se bazează pe actele solicitantului și pe forma oficială aplicabilă.</p></div><div class="program-fit-grid"><article class="fit-card fit-card--yes"><h3>Profil care merită verificat</h3>${renderList(content.fit)}</article><article class="fit-card fit-card--caution"><h3>Condiții care cer clarificare</h3>${renderList(content.caution)}</article></div></section>
  <section class="program-section program-section--soft"><div class="section-heading"><p class="section-kicker">Arhitectura proiectului</p><h2>Ce intră în analiza investiției</h2></div><div class="program-card-grid">${renderCards(content.investments)}</div></section>
  <section class="program-section program-section--documents"><div class="section-heading"><p class="section-kicker">Dosar de lucru</p><h2>Documente de pregătit</h2><p>Deschide fiecare grup și construiește o versiune trasabilă, cu dată, sursă și responsabil.</p></div><div class="program-details">${renderDetails(content.documents)}</div></section>
  <section class="program-section"><div class="section-heading"><p class="section-kicker">Parcurs recomandat</p><h2>De la idee la decizia de depunere</h2></div><ol class="program-steps">${content.steps.map((step, index) => `<li><span>${index + 1}</span><p>${e(step)}</p></li>`).join("")}</ol></section>
  <section class="program-section program-section--source" id="surse-oficiale"><div><p class="section-kicker">Trasabilitate</p><h2>Surse oficiale și limitări</h2><p>Pagina consolidează actele disponibile, în limbaj propriu, și păstrează distinct statutul schemei de existența unei sesiuni de depunere.</p></div><div class="source-card"><a href="${e(program.sourceUrl)}" target="_blank" rel="noopener noreferrer"><strong>${e(program.sourceName)}</strong><span>${e(program.sourceVersion)}</span></a>${content.extraSources.map(([label, url]) => `<a href="${e(url)}" target="_blank" rel="noopener noreferrer"><strong>${e(label)}</strong><span>Deschide sursa instituțională</span></a>`).join("")}<p>Ultima verificare editorială: <time datetime="${program.verifiedAt}">${program.verifiedAt}</time>.</p></div></section>
  <section class="program-section program-section--faq"><div class="section-heading"><p class="section-kicker">Întrebări frecvente</p><h2>Clarificări înainte de pregătire</h2></div><div class="program-details">${renderDetails(content.faqs)}</div></section>
  <section class="program-final-cta"><div><p class="section-kicker">Următorul pas</p><h2>Verifică proiectul pe documente, nu doar pe promisiunea programului.</h2><p>Trimite profilul solicitantului, investiția, amplasamentul și bugetul. Primești o concluzie orientativă și lista neclarităților care trebuie rezolvate.</p></div><a class="program-button program-button--primary" href="/contact#program_slug=${e(program.slug)}&source_page=${encodeURIComponent(program.pageUrl)}">Începe verificarea</a></section>
</main>
<footer class="program-footer">© 2026 FABER – Atelier de Consultanță · <a href="/fonduri-europene">Toate programele</a> · <a href="/contact">Contact</a> · <a href="/politica-de-confidentialitate">Confidențialitate</a></footer>
<script src="/assets/program-showcase-2026.js?v=20260809-1" defer></script>
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
