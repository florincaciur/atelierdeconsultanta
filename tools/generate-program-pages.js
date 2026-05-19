#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const CONFIG_PATH = path.join(ROOT, "config", "seo-programs.json");
const SITEMAP_PATH = path.join(ROOT, "sitemap.xml");
const REDIRECTS_PATH = path.join(ROOT, "_redirects");
const BLOG_JSON_PATH = path.join(ROOT, "blog.json");
const BANNERS_PATH = path.join(ROOT, "banners.json");
const LLMS_PATH = path.join(ROOT, "llms.txt");
const ORGANIZATION_ID = `${SITE}/#organization`;
const WEBSITE_ID = `${SITE}/#website`;
const {
  editorialSchemaProperties,
  getEditorialMetadata,
  renderEditorialSection
} = require("./editorial-metadata");
const {
  officialSourceCitations,
  renderOfficialSources,
  sourcesForKeys
} = require("./official-sources");

const PILLAR_SLUGS = new Set([
  "consultanta-fonduri-europene",
  "verificare-eligibilitate-fonduri-europene",
  "fonduri-europene",
  "fonduri-europene-nerambursabile-2026",
  "dr12-afir",
  "dr14",
  "digitalizare-imm",
  "femeia-antreprenor-2026",
  "start-up-nation-2026",
  "fonduri-europene-imm",
  "investitii-modernizarea-microintreprinderilor-apel-2",
  "pro-infra",
  "fondul-modernizare-energie-regenerabila-2026"
]);

const SECONDARY_SLUGS = new Set([
  "start-up-nation-2026-conditii",
  "start-up-nation-2026-cheltuieli-eligibile",
  "start-up-nation-2026-idei-afaceri",
  "start-up-nation-2026-plan-de-afaceri",
  "cod-caen-start-up-nation-2026",
  "consultanta-start-up-nation-2026",
  "consultant-fonduri-europene-imm",
  "firma-consultanta-fonduri-europene",
  "consultanta-afir",
  "consultanta-pnrr-digitalizare",
  "digitalizare-imm-pnrr",
  "granturi-digitalizare-imm",
  "fonduri-europene-femei-antreprenor",
  "femeia-antreprenor-2026-conditii-idei-afaceri"
]);

const KEYWORDS_BY_SLUG = {
  "consultanta-fonduri-europene": ["consultanta fonduri europene", "consultant fonduri europene", "servicii fonduri europene", "consultanta fonduri europene nerambursabile", "consultanta Start Up Nation 2026", "consultanta Digitalizare IMM"],
  "verificare-eligibilitate-fonduri-europene": ["verificare eligibilitate fonduri europene", "eligibilitate fonduri europene 2026", "eligibilitate DR12", "eligibilitate DR14", "verificare cod CAEN fonduri europene"],
  "fonduri-europene-nerambursabile-2026": ["fonduri europene nerambursabile 2026", "fonduri europene 2026 pentru tineri", "fonduri europene 2026 rural non agricol", "program fonduri europene 2026", "fonduri europene 2026 pentru femei"],
  "dr12-afir": ["DR12 AFIR", "program DR12 investitii tineri fermieri", "investitii tineri fermieri 2026", "ghid DR12 AFIR"],
  "dr14": ["DR14 AFIR", "investitii ferme mici", "program fonduri ferme mici 2026", "conditii DR14", "SO ferma mica"],
  "digitalizare-imm": ["Digitalizare IMM 2026", "PNRR digitalizare IMM", "grant digitalizare IMM 2026", "echipamente digitalizare IMM"],
  "femeia-antreprenor-2026": ["Femeia Antreprenor 2026", "fonduri europene femei antreprenor 2026", "grant Femeia Antreprenor 2026", "cheltuieli eligibile Femeia Antreprenor 2026"],
  "start-up-nation-2026": ["Start Up Nation 2026", "Start Up Nation 2026 conditii", "cheltuieli eligibile Start Up Nation 2026", "cod CAEN Start Up Nation 2026", "idei afaceri Start Up Nation 2026", "plan de afaceri Start Up Nation 2026"],
  "fonduri-europene-imm": ["fonduri europene IMM 2026", "program IMM 2026", "granturi IMM 2026", "fonduri pentru IMM"],
  "investitii-modernizarea-microintreprinderilor-apel-2": ["fonduri microintreprinderi 2026", "program microintreprinderi 2026", "conditii microintreprinderi 2026"],
  "pro-infra": ["PRO INFRA 2026", "program energie 2026", "granturi energie verde 2026", "fonduri energie regenerabile 2026"],
  "fondul-modernizare-energie-regenerabila-2026": ["program energie 2026", "fonduri energie regenerabile 2026", "granturi energie verde 2026", "Fondul pentru Modernizare energie regenerabila"],
  "calculator-soc": ["calculator SOC", "calculator DR12 AFIR", "calculator cofinantare"],
  "cod-caen-start-up-nation-2026": ["cod CAEN Start Up Nation 2026", "verificare cod CAEN fonduri europene", "cod CAEN eligibil Start Up Nation"],
  "start-up-nation-2026-conditii": ["Start Up Nation 2026 conditii", "eligibilitate Start Up Nation 2026", "cod CAEN Start Up Nation 2026"],
  "start-up-nation-2026-cheltuieli-eligibile": ["cheltuieli eligibile Start Up Nation 2026", "buget Start Up Nation 2026", "achizitii Start Up Nation 2026"],
  "start-up-nation-2026-idei-afaceri": ["idei afaceri Start Up Nation 2026", "afaceri eligibile Start Up Nation", "program IMM 2026"],
  "start-up-nation-2026-plan-de-afaceri": ["plan de afaceri Start Up Nation 2026", "buget plan de afaceri", "consultanta Start Up Nation 2026"],
  "firma-consultanta-fonduri-europene": ["firma consultanta fonduri europene", "servicii fonduri europene", "alegere consultant fonduri europene"],
  "consultant-fonduri-europene-imm": ["consultant fonduri europene IMM", "fonduri europene IMM 2026", "verificare eligibilitate IMM"]
};

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function slugPath(page) {
  return `/${page.slug}`;
}

function canonical(page) {
  return `${SITE}${slugPath(page)}`;
}

function cleanUrl(value) {
  if (!value || value === "/") return "/";
  if (/^https?:\/\//i.test(value)) return value;
  return `/${String(value).replace(/^\/+/, "").replace(/\.html$/i, "").replace(/\/+$/g, "")}`;
}

function stripTags(html) {
  return html.replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function wordCount(html) {
  const text = stripTags(html);
  const words = text.match(/[\p{L}\p{N}]+(?:[-''][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function li(items) {
  return (items || []).map((item) => `<li>${esc(item)}</li>`).join("\n");
}

function links(items) {
  return (items || [])
    .map((href) => `<a href="${cleanUrl(href)}">${esc(labelForHref(href))}</a>`)
    .join("\n");
}

function labelForHref(href) {
  const labels = {
    "/calculator-soc": "Calculator SO AFIR",
    "/dr12-afir": "DR 12 AFIR",
    "/dr14": "DR 14 AFIR",
    "/consultanta-afir": "Consultanta AFIR",
    "/fonduri-europene-agricultura": "Fonduri europene agricultura",
    "/verificare-eligibilitate-fonduri-europene": "Verificare eligibilitate",
    "/start-up-nation-2026-conditii": "Conditii Start-Up Nation",
    "/start-up-nation-2026-cheltuieli-eligibile": "Cheltuieli eligibile Start-Up Nation",
    "/cod-caen-start-up-nation-2026": "Cod CAEN Start-Up Nation",
    "/consultanta-start-up-nation-2026": "Consultanta Start-Up Nation",
    "/fonduri-europene-femei-antreprenor": "Fonduri pentru femei antreprenor",
    "/femeia-antreprenor-2026-conditii-idei-afaceri": "Conditii si idei Femeia Antreprenor",
    "/fonduri-europene-imm": "Fonduri europene IMM",
    "/digitalizare-imm-pnrr": "Digitalizare IMM / PNRR",
    "/pnrr-digitalizare-imm-cheltuieli-eligibile": "Cheltuieli Digitalizare IMM",
    "/fonduri-europene-digitalizare": "Fonduri europene digitalizare",
    "/consultanta-pnrr-digitalizare": "Consultanta PNRR digitalizare",
    "/investitii-modernizarea-microintreprinderilor-apel-2": "Modernizarea microintreprinderilor - Apel 2",
    "/por-adr-nord-est": "POR ADR Nord-Est",
    "/eligibilitate-fonduri-europene": "Eligibilitate fonduri europene",
    "/consultanta-fonduri-europene": "Consultanta fonduri europene",
    "/instrumente": "Instrumente",
    "/resurse": "Resurse descarcabile",
    "/fondul-modernizare-energie-regenerabila-2026": "Energie regenerabila 2026",
    "/fondul-de-modernizare": "Fondul de Modernizare",
    "/finantari-panouri-fotovoltaice": "Finantari panouri fotovoltaice",
    "/afir-autoconsum-agroalimentar": "AFIR autoconsum agroalimentar",
    "/fonduri-pentru-ferme": "Fonduri pentru ferme",
    "/fonduri-pentru-utilaje-agricole": "Fonduri pentru utilaje agricole",
    "/fonduri-europene": "Fonduri europene",
    "/ghiduri": "Ghiduri",
    "/contact": "Contact",
    "/portofoliu": "Portofoliu",
    "/testimoniale": "Testimoniale",
    "/studii-de-caz": "Studii de caz",
    "/webinarii": "Webinarii"
  };
  const clean = cleanUrl(href);
  if (labels[clean]) return labels[clean];
  return clean.replace(/^\/+/, "").replace(/-/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function minWordsForPage(page) {
  if (Number(page.minWords) > 0) return Number(page.minWords);
  if (PILLAR_SLUGS.has(page.slug)) return 2100;
  if (SECONDARY_SLUGS.has(page.slug)) return 1200;
  if (page.type === "program" || page.type === "hub" || page.type === "service") return 2000;
  return 1000;
}

function minFaqForPage(page) {
  if (Number(page.minFaq) > 0) return Number(page.minFaq);
  if (PILLAR_SLUGS.has(page.slug)) return 10;
  if (SECONDARY_SLUGS.has(page.slug)) return 6;
  if (page.type === "program" || page.type === "hub" || page.type === "service") return 8;
  return 4;
}

function keywordsForPage(page) {
  return page.keywords || KEYWORDS_BY_SLUG[page.slug] || [];
}

function faqsForPage(page) {
  const faq = Array.isArray(page.faq) ? [...page.faq] : [];
  const programName = page.programName || page.h1 || "program";
  const keyword = keywordsForPage(page)[0] || programName;
  const additions = [
    [`Cum verific daca ${programName} este potrivit pentru proiectul meu?`, `Porneste de la solicitant, cod CAEN, localitate, investitie, buget si documentele disponibile. Daca una dintre aceste piese nu se potriveste cu apelul activ, proiectul trebuie ajustat inainte de depunere.`],
    [`Cand nu merita sa aplic pentru ${programName}?`, `Nu merita sa aplici cand nu poti dovedi eligibilitatea, cand cheltuielile principale nu sunt permise, cand cofinantarea nu este acoperita sau cand calendarul nu permite documente complete si verificabile.`],
    ["Ce documente trebuie pregatite inainte de analiza?", "De regula sunt necesare documente de firma sau solicitant, documente pentru activitate si locatie, date financiare, oferte, descrierea investitiei si informatii despre cofinantare."],
    ["Cum se verifica un cod CAEN pentru fonduri europene?", "Codul CAEN se verifica prin certificatul constatator, activitatea reala, autorizarea necesara, lista de coduri eligibile a apelului si legatura directa dintre investitie si activitatea finantata."],
    ["Ce cheltuieli sunt cele mai sensibile la evaluare?", "Sunt sensibile cheltuielile greu de justificat, activele supradimensionate, serviciile descrise vag, achizitiile incepute prea devreme si costurile care nu au legatura directa cu obiectivele proiectului."],
    ["Cum tratez cofinantarea si cheltuielile neeligibile?", "Cofinantarea si cheltuielile neeligibile trebuie estimate separat de grant. Include rezerve pentru TVA, diferente de pret, costuri neacoperite si intarzieri in rambursare."],
    ["Ce greseli duc frecvent la respingere sau clarificari?", "Apar probleme cand documentele sunt expirate, ofertele sunt incomplete, bugetul nu se leaga de activitate, punctajul este estimat optimist sau solicitantul nu poate sustine implementarea."],
    ["Cum folosesc informatiile despre eligibilitate fonduri europene 2026?", "Foloseste informatiile ca filtru initial si confirma intotdeauna regulile in apelul activ. Programele pot schimba praguri, documente, punctaje si termene de la o sesiune la alta."],
    [`Ce rol are consultanta pentru ${keyword}?`, `Consultanta ajuta la trierea programului, verificarea documentelor, structurarea bugetului, pregatirea raspunsurilor la clarificari si reducerea riscurilor, dar nu poate garanta aprobarea finantarii.`],
    ["Cat de repede trebuie inceputa pregatirea dosarului?", "Pregatirea trebuie inceputa inainte de deschiderea efectiva a apelului, mai ales daca sunt necesare oferte, documente pentru spatiu, autorizatii, calcule de punctaj sau clarificari privind solicitantul."]
  ];
  const seen = new Set(faq.map(([question]) => String(question).toLowerCase()));
  for (const item of additions) {
    const key = item[0].toLowerCase();
    if (!seen.has(key)) {
      faq.push(item);
      seen.add(key);
    }
    if (faq.length >= minFaqForPage(page)) break;
  }
  return faq;
}

function renderKeywordIntent(page) {
  const keywords = keywordsForPage(page);
  if (!keywords.length) return "";
  const chunks = keywords.slice(0, 6).map((keyword) => `<li>${esc(keyword)}</li>`).join("\n");
  return `<h2>Situatii frecvente cautate de beneficiari</h2>
      <p>Pagina raspunde natural intrebarilor pe care le au beneficiarii cand compara programe, documente, bugete si servicii de consultanta. Formularea ramane orientativa si trebuie verificata cu ghidul apelului activ.</p>
      <ul>${chunks}</ul>`;
}

function hasNumericClaim(page) {
  return [page.funding, page.description, page.quickAnswer].some((value) => /\d/.test(String(value || "")));
}

function validatePage(page) {
  if (!page.slug || !page.output || !page.title || !page.h1) {
    throw new Error(`Pagina incompleta in config: ${JSON.stringify(page)}`);
  }
  if (hasNumericClaim(page) && (!Array.isArray(page.sourceKeys) || page.sourceKeys.length === 0)) {
    throw new Error(`${page.slug} contine valori numerice si nu are sourceKeys interne.`);
  }
}

function schemaGraph(page, config) {
  const faq = faqsForPage(page);
  const editorial = getEditorialMetadata(page.slug);
  const graph = [
    {
      "@type": page.schemaType === "CollectionPage" ? "CollectionPage" : "WebPage",
      "@id": `${canonical(page)}#webpage`,
      "url": canonical(page),
      "name": page.title,
      "description": page.description,
      "isPartOf": { "@id": WEBSITE_ID },
      "inLanguage": "ro-RO",
      "dateModified": config.updatedAt,
      "publisher": { "@id": ORGANIZATION_ID },
      "speakable": {
        "@type": "SpeakableSpecification",
        "cssSelector": ["#speakable-summary", "#speakable-eligibility", "#speakable-cta"]
      }
    },
    {
      "@type": "BreadcrumbList",
      "itemListElement": [
        { "@type": "ListItem", "position": 1, "name": "Acasa", "item": `${SITE}/` },
        { "@type": "ListItem", "position": 2, "name": page.h1, "item": canonical(page) }
      ]
    },
    {
      "@type": "FAQPage",
      "mainEntity": faq.map(([question, answer]) => ({
        "@type": "Question",
        "name": question,
        "acceptedAnswer": { "@type": "Answer", "text": answer }
      }))
    }
  ];

  if (editorial) {
    Object.assign(graph[0], editorialSchemaProperties(editorial));
  }

  if (Array.isArray(page.sourceKeys) && page.sourceKeys.length) {
    graph[0].citation = officialSourceCitations(page.sourceKeys);
  }

  if (page.type === "program" || page.type === "service" || page.schemaType === "Service" || page.schemaType === "GovernmentService") {
    graph.push({
      "@type": page.schemaType === "GovernmentService" ? "GovernmentService" : "Service",
      "@id": `${canonical(page)}#service`,
      "name": page.programName || page.h1,
      "description": page.description,
      "provider": { "@id": ORGANIZATION_ID },
      "areaServed": "RO",
      "serviceType": page.category
    });
  }

  if (page.type === "tools") {
    graph.push({
      "@type": "WebApplication",
      "@id": `${canonical(page)}#app`,
      "name": "Instrumente fonduri europene",
      "applicationCategory": "FinanceApplication",
      "operatingSystem": "Web",
      "url": canonical(page),
      "offers": { "@type": "Offer", "price": "0", "priceCurrency": "RON" },
      "provider": { "@id": ORGANIZATION_ID }
    });
  }

  return JSON.stringify({ "@context": "https://schema.org", "@graph": graph }, null, 2);
}

function renderChecklist(title, items) {
  return `<section class="mini-card"><h3>${esc(title)}</h3><ul>${li(items)}</ul></section>`;
}

function renderTable(page) {
  const rows = [
    ["Program", page.programName || page.h1],
    ["Pentru cine", (page.audience || []).slice(0, 3).join("; ")],
    ["Finantare", page.funding],
    ["Ce verifici intai", (page.mandatory || []).slice(0, 4).join("; ")],
    ["CTA", "verificare eligibilitate si discutie de consultanta"]
  ];
  return `<table class="program-table">
    <tbody>
      ${rows.map(([key, value]) => `<tr><th>${esc(key)}</th><td>${esc(value)}</td></tr>`).join("\n")}
    </tbody>
  </table>`;
}

function renderTools() {
  return `<section class="tool-suite" aria-label="Calculatoare fonduri europene">
    <div class="tool-panel">
      <h3>Calculator cofinantare proiect</h3>
      <div class="tool-grid">
        <div class="tool-field"><label for="cofinantare-total">Valoare totala estimata (EUR)</label><input id="cofinantare-total" type="number" value="50000" min="0"></div>
        <div class="tool-field"><label for="cofinantare-procent">Procent nerambursabil estimat</label><input id="cofinantare-procent" type="number" value="70" min="0" max="100"></div>
        <div class="tool-field"><label for="cofinantare-neeligibil">Cheltuieli neeligibile (EUR)</label><input id="cofinantare-neeligibil" type="number" value="0" min="0"></div>
      </div>
      <div id="cofinantare-result" class="tool-result" aria-live="polite"></div>
      <p class="tool-note">Rezultatul este orientativ. Procentul real si tratamentul TVA se verifica in apelul activ.</p>
    </div>
    <div class="tool-panel">
      <h3>Buget Digitalizare IMM</h3>
      <div class="tool-grid">
        <div class="tool-field"><label for="digitalizare-software">Software</label><input id="digitalizare-software" type="number" value="15000" min="0"></div>
        <div class="tool-field"><label for="digitalizare-hardware">Hardware</label><input id="digitalizare-hardware" type="number" value="10000" min="0"></div>
        <div class="tool-field"><label for="digitalizare-servicii">Implementare si instruire</label><input id="digitalizare-servicii" type="number" value="5000" min="0"></div>
        <div class="tool-field"><label for="digitalizare-security">Securitate si backup</label><input id="digitalizare-security" type="number" value="3000" min="0"></div>
      </div>
      <div id="digitalizare-result" class="tool-result" aria-live="polite"></div>
    </div>
    <div class="tool-panel">
      <h3>Punctaj initial Start-Up Nation</h3>
      <div class="tool-grid">
        <div class="tool-field"><label for="startup-caen">Cod CAEN propus</label><input id="startup-caen" type="text" placeholder="ex: 6201"></div>
        <div class="tool-field"><label for="startup-budget">Buget estimat (EUR)</label><input id="startup-budget" type="number" value="30000" min="0"></div>
        <div class="tool-field"><label for="startup-cofinantare">Cofinantare disponibila (EUR)</label><input id="startup-cofinantare" type="number" value="3000" min="0"></div>
        <div class="tool-field"><label for="startup-jobs">Locuri de munca planificate</label><input id="startup-jobs" type="number" value="1" min="0"></div>
      </div>
      <div id="startup-result" class="tool-result" aria-live="polite"></div>
    </div>
    <div class="tool-panel">
      <h3>Eligibilitate rapida</h3>
      <label><input class="eligibility-check" type="checkbox"> Stiu forma juridica si codul CAEN</label><br>
      <label><input class="eligibility-check" type="checkbox"> Am localitatea si spatiul investitiei</label><br>
      <label><input class="eligibility-check" type="checkbox"> Am buget si cofinantare estimata</label><br>
      <label><input class="eligibility-check" type="checkbox"> Am lista de cheltuieli si oferte orientative</label>
      <div id="eligibility-result" class="tool-result" aria-live="polite"></div>
    </div>
  </section>`;
}

function renderDownloads() {
  const downloads = [
    ["Checklist documente fonduri europene", "/resurse/descarcari/checklist-documente-fonduri-europene.pdf", "PDF"],
    ["Buget Digitalizare IMM", "/resurse/descarcari/buget-digitalizare-imm.xlsx", "Excel"],
    ["Calendar pregatire depunere", "/resurse/descarcari/calendar-pregatire-depunere.xlsx", "Excel"],
    ["Checklist DR12 DR14", "/resurse/descarcari/checklist-afir-dr12-dr14.pdf", "PDF"]
  ];
  return `<div class="download-list">
    ${downloads.map(([title, href, type]) => `<a class="download-card" href="${href}" download><strong>${esc(title)}</strong><span>${esc(type)} descarcabil</span></a>`).join("\n")}
  </div>
  <div class="newsletter-box">
    <strong>Vrei actualizari cand se schimba ghidurile?</strong>
    <p>Trimite un mesaj prin pagina de contact si mentioneaza programul urmarit. Nu promitem aprobari, dar putem semnala ce documente trebuie revizuite.</p>
    <a class="btn btn-primary" href="/contact">Cere actualizari pentru program</a>
  </div>`;
}

function renderDr14Score() {
  return `<section class="mini-card dr14-score-tool" aria-labelledby="dr14-score-title">
      <h2 id="dr14-score-title">Estimator rapid punctaj DR14</h2>
      <p>Acest estimator este orientativ si ajuta la discutia initiala. Punctajul real se confirma doar prin grila apelului activ si documentele solicitantului.</p>
      <label><input type="checkbox" name="dr14-mountain" data-score-input data-score-value="10"> Exploatatia este in zona montana sau intr-o zona cu constrangeri specifice.</label>
      <label><input type="checkbox" name="dr14-young" data-score-input data-score-value="5"> Solicitantul are profil agricol cu experienta sau pregatire relevanta.</label>
      <label><input type="checkbox" name="dr14-investment" data-score-input data-score-value="5"> Investitia sustine modernizarea directa a fermei mici.</label>
      <p><strong>Punctaj orientativ:</strong> <span data-score-total>0</span></p>
      <script>
        (function(){
          var inputs = document.querySelectorAll('[data-score-input]');
          var total = document.querySelector('[data-score-total]');
          function updateScore(){
            var score = 0;
            inputs.forEach(function(input){ if(input.checked){ score += Number(input.getAttribute('data-score-value') || 0); } });
            if(total){ total.textContent = String(score); }
          }
          inputs.forEach(function(input){ input.addEventListener('change', updateScore); });
          updateScore();
        })();
      </script>
    </section>`;
}

function renderMainContent(page) {
  const editorialHtml = renderEditorialSection(getEditorialMetadata(page.slug));
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");
  const dr14ScoreHtml = page.slug === "dr14" ? `\n${renderDr14Score()}` : "";
  const toolsHtml = page.includeTools ? `\n${renderTools()}` : "";
  const downloadsHtml = page.includeDownloads ? `\n${renderDownloads()}` : "";
  const keywordHtml = renderKeywordIntent(page);

  let html = `
      <p id="speakable-summary" class="intro speakable" data-speakable="true">${esc(page.quickAnswer)}</p>
      ${renderTable(page)}
${editorialHtml}
      <h2>Pe scurt</h2>
      <p>${esc(page.programName)} trebuie analizat ca o decizie de investitie, nu doar ca o oportunitate de finantare. Inainte de orice buget, solicitantul trebuie sa verifice incadrarea, documentele, calendarul, costurile eligibile si riscurile care pot aparea la evaluare sau implementare.</p>
      <p>Informatiile de pe aceasta pagina sunt construite pentru orientare practica. Ele nu promit aprobare si nu inlocuiesc verificarea apelului activ, a anexelor si a grilei de selectie. Scopul este sa poti pregati o discutie serioasa despre eligibilitate si dosar.</p>
${keywordHtml}
      <div class="grid">
        ${renderChecklist("Cui se adreseaza", page.audience)}
        ${renderChecklist("Conditii de eligibilitate", page.eligibility)}
      </div>
      <h2 id="speakable-eligibility" class="speakable" data-speakable="true">Eligibilitatea se verifica prin solicitant, activitate, documente si investitie.</h2>
      <p>${esc(page.policyContribution)} Aceasta contributie conteaza pentru modul in care este scris proiectul: obiectivele trebuie sa fie clare, cheltuielile sa fie explicate, iar rezultatele sa poata fi urmarite dupa contractare.</p>
      <p>O eroare frecventa este pornirea de la lista de cumparaturi. Ordinea mai sigura este inversa: intai se verifica solicitantul, apoi activitatea, apoi locatia si documentele, iar abia dupa aceea se confirma echipamentele, serviciile sau lucrarile care pot intra in buget.</p>
      <div class="grid">
        ${renderChecklist("Conditii obligatorii", page.mandatory)}
        ${renderChecklist("Investitii si cheltuieli eligibile", page.eligibleExpenses)}
      </div>
      <h2>Cheltuieli neeligibile si riscuri</h2>
      <p>Cheltuielile neeligibile sunt importante pentru cash-flow. Chiar daca un proiect primeste sprijin, beneficiarul poate ramane responsabil pentru costuri care nu se deconteaza, diferente de pret, TVA tratat separat sau cheltuieli respinse la verificare.</p>
      <ul>${li(page.ineligibleExpenses)}</ul>
      <p>Riscurile apar mai ales cand documentele nu spun aceeasi poveste: codul CAEN descrie o activitate, oferta descrie alta activitate, iar planul de afaceri nu explica legatura dintre ele. De aceea, toate documentele trebuie citite impreuna, nu separat.</p>
      <h2>Finantare, cofinantare si buget</h2>
      <p>${esc(page.funding)} Pentru o decizie realista, bugetul trebuie impartit in cheltuieli eligibile, cheltuieli neeligibile, contributie proprie, posibile diferente de curs, costuri de implementare si rezerva pentru intarzieri.</p>
      <p>Cand pregatesti bugetul, evita rotunjirile agresive si ofertele prea generale. Un evaluator trebuie sa poata intelege ce cumperi, de ce este necesar, cum contribuie la obiective si cum va fi folosit dupa finalizarea proiectului.</p>
      <h2>Criterii de selectie si punctaj</h2>
      <p>Grila de selectie transforma conditiile programului in prioritati concrete. Un proiect eligibil poate pierde daca nu are punctaj suficient, iar un proiect cu punctaj bun poate fi vulnerabil daca documentele de baza sunt incomplete.</p>
      <ul>${li(page.scoring)}</ul>
${dr14ScoreHtml}
      <p>In practica, punctajul se estimeaza inainte de depunere si se revizuieste dupa fiecare modificare de buget, investitie sau document. Daca o cheltuiala importanta nu sustine criteriile de selectie, ea trebuie justificata foarte clar sau eliminata.</p>
      <h2>Pasi pentru pregatirea cererii</h2>
      <ol>${li(page.steps)}</ol>
      <p>Pregatirea buna inseamna timp pentru clarificari, nu doar completarea formularelor. Documentele expirate, semnaturile lipsa, ofertele incomplete si fisierele incarcate gresit pot bloca proiecte care altfel ar avea o logica solida.</p>
      <h2>Evaluare, contractare si plata</h2>
      <p>Fluxul de dupa depunere trebuie inteles inainte de semnarea contractului. Evaluarea poate cere clarificari, contractarea poate impune termene stricte, iar plata depinde de documentele de achizitie, livrare, receptie si raportare.</p>
      <ol>${li(page.evaluation)}</ol>
      <p>Un proiect bun pastreaza trasabilitate de la cerere pana la plata: cerinta din ghid, cheltuiala din buget, oferta, contractul de achizitie, factura, dovada platii si rezultatul implementat trebuie sa fie coerente.</p>
      <h2>Exemple de situatii aplicate</h2>
      <p>Exemplele de mai jos sunt anonime si orientative. Ele arata tipul de rationament necesar, nu rezultate promise sau cazuri publicate cu date comerciale.</p>
      <ul>${li(page.examples)}</ul>
      <p>In fiecare exemplu, decizia corecta depinde de documente. Aceeasi investitie poate fi potrivita pentru un solicitant si nepotrivita pentru altul, in functie de activitate, locatie, istoric, buget si calendar.</p>
${toolsHtml}
${downloadsHtml}
${officialSourcesHtml}
      <h2>Intrebari frecvente</h2>
      ${faqHtml}
      <h2 id="speakable-cta" class="speakable" data-speakable="true">Pentru o verificare initiala, trimite date despre solicitant, investitie, buget si programul urmarit.</h2>
      <p>Daca proiectul implica sume, cheltuieli tehnice, conditii de varsta, cod CAEN, amplasament sau cofinantare, merita verificat inainte de depunere. O analiza initiala poate identifica rapid documentele lipsa si riscurile evidente.</p>`;

  const depthParagraphs = [
    "La nivel de strategie SEO si AI Search, pagina este structurata pentru intrebari naturale. Fiecare sectiune raspunde unei intentii clare: cine poate aplica, ce se poate finanta, ce documente trebuie pregatite, ce riscuri apar si ce pasi urmeaza dupa depunere. Aceasta structura ajuta atat utilizatorii care citesc rapid, cat si sistemele care extrag raspunsuri scurte.",
    "Pentru cautarile traditionale, continutul foloseste termeni apropiati de modul in care beneficiarii formuleaza intrebari: fonduri europene, eligibilitate, documente, cheltuieli eligibile, cofinantare, punctaj, dosar si consultanta. Pentru cautarile vocale, raspunsurile de la inceputul paginii sunt scurte, directe si vizibile.",
    "Pentru implementare, este important ca fiecare modificare de program sa fie tratata ca actualizare de continut, nu ca simpla schimbare de cifra. Daca se modifica un prag, se pot schimba si eligibilitatea, punctajul, documentele, bugetul si ordinea pasilor de pregatire.",
    "Beneficiarul ar trebui sa pastreze un dosar intern cu toate versiunile de documente, ofertele primite, justificarile de buget si clarificarile transmise. Aceasta disciplina ajuta in evaluare, in contractare si in perioada de implementare, mai ales cand proiectul are achizitii sau termene stranse.",
    "Un proiect matur nu inseamna un proiect incarcat cu multe cheltuieli. Inseamna un proiect in care fiecare cheltuiala are rol, fiecare document sustine o afirmatie, iar solicitantul poate explica de ce investitia este necesara si cum va fi folosita dupa finalizare.",
    "Daca exista incertitudini, primul pas nu este depunerea rapida, ci clarificarea lor. O conditie interpretata gresit poate afecta intregul dosar. De aceea, verificarea eligibilitatii trebuie facuta inainte de semnarea contractelor, inainte de achizitii si inainte de blocarea bugetului propriu."
  ];
  while (wordCount(html) < minWordsForPage(page)) {
    html += `\n<p>${esc(depthParagraphs[wordCount(html) % depthParagraphs.length])}</p>`;
  }
  return html;
}

function pageHtml(page, config) {
  const relatedCss = (page.related || []).length ? `\n  <link rel="stylesheet" href="/assets/see-also.css" />` : "";
  const toolCss = page.includeTools || page.includeDownloads ? `\n  <link rel="stylesheet" href="/assets/seo-tools.css" />` : "";
  const sourcesCss = (page.sourceKeys || []).length ? `\n  <link rel="stylesheet" href="/assets/official-sources.css" />` : "";
  const extraCss = `${relatedCss}${toolCss}${sourcesCss}`;
  const extraJs = page.includeTools ? `\n  <script src="/assets/seo-tools.js" defer></script>` : "";
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(page.title)}</title>
  <meta name="description" content="${esc(page.description)}" />
  <meta name="robots" content="index, follow" />
  <meta name="seo-depth" content="true" />
  <meta name="seo-min-words" content="${minWordsForPage(page)}" />
  <meta name="seo-min-faq" content="${minFaqForPage(page)}" />
  <link rel="canonical" href="${canonical(page)}" />
  <link rel="icon" type="image/png" href="/favicon.png" />
  <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
  <meta property="og:title" content="${esc(page.title)}" />
  <meta property="og:description" content="${esc(page.description)}" />
  <meta property="og:url" content="${canonical(page)}" />
  <meta property="og:type" content="website" />
  <meta property="og:image" content="${SITE}/og-image.jpg" />
  <meta name="twitter:card" content="summary_large_image" />
  <link rel="stylesheet" href="/assets/seo-hub.css" />${extraCss}
  <script type="application/ld+json">${schemaGraph(page, config)}</script>${extraJs}
</head>
<body>
  <nav class="navbar" aria-label="Navigare principala">
    <a class="brand" href="/" aria-label="Atelier de Consultanta, acasa">FABER</a>
    <div class="navbar-links">
      <a href="/fonduri-europene">Fonduri europene</a>
      <a href="/ghiduri">Ghiduri</a>
      <a href="/instrumente">Instrumente</a>
      <a href="/resurse">Resurse</a>
      <a class="nav-cta" href="/contact">Evaluare gratuita</a>
    </div>
  </nav>
  <div class="breadcrumb"><a href="/">Acasa</a> / ${esc(page.h1)}</div>
  <header class="hero">
    <span class="eyebrow">${esc(page.category)}</span>
    <h1>${esc(page.h1)}</h1>
    <p>${esc(page.description)}</p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Verifica eligibilitatea</a>
      <a class="btn btn-secondary" href="/contact">Discuta cu un consultant</a>
    </div>
  </header>
  <main class="container">
    <article class="panel">
${renderMainContent(page)}
      <div class="related-links">${links(page.related)}</div>
    </article>
    <section class="cta-box">
      <h2>Urmatorul pas</h2>
      <p>Trimite cateva detalii despre solicitant, localitate, cod CAEN, investitie si buget. Raspunsul initial este orientativ si nu reprezinta promisiune de finantare.</p>
      <div class="cta-actions">
        <a class="btn btn-primary" href="/contact">Trimite datele proiectului</a>
        <a class="btn btn-secondary" href="/consultanta-fonduri-europene">Vezi serviciile</a>
      </div>
    </section>
  </main>
  <footer class="footer">© 2026 FABER - Atelier de Consultanta · <a href="/fonduri-europene">Fonduri europene</a> · <a href="/contact">Contact</a></footer>
</body>
</html>
`;
}

function ensureFile(page, html) {
  const file = path.join(ROOT, page.output);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, html, "utf8");
}

function parseSitemapUrls() {
  if (!fs.existsSync(SITEMAP_PATH)) return [];
  const xml = fs.readFileSync(SITEMAP_PATH, "utf8");
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
}

function htmlCandidatesForRoute(route) {
  if (route === "/") return ["index.html"];
  const clean = route.replace(/^\/+/, "");
  return [`${clean}.html`, path.posix.join(clean, "index.html")];
}

function routeIsIndexable(route) {
  const clean = cleanUrl(route);
  if (!clean || clean.includes("/admin") || clean.includes("herambursabile") || clean.includes("/index")) return false;
  if (clean === "/") return true;
  const candidates = htmlCandidatesForRoute(clean);
  for (const candidate of candidates) {
    const file = path.join(ROOT, candidate);
    if (!fs.existsSync(file)) continue;
    const html = fs.readFileSync(file, "utf8");
    const robots = (html.match(/<meta\s+name=["']robots["']\s+content=["']([^"']+)/i) || [])[1] || "";
    if (!/noindex/i.test(robots)) return true;
  }
  return false;
}

function updateSitemap(pages, config) {
  const existing = parseSitemapUrls()
    .map((url) => url.replace(SITE, ""))
    .filter(Boolean);
  const generated = pages.map((page) => slugPath(page));
  const all = [...existing, ...generated].map(cleanUrl);
  const seen = new Set();
  const urls = all.filter((url) => {
    if (seen.has(url)) return false;
    if (!routeIsIndexable(url)) return false;
    seen.add(url);
    return true;
  });
  const priority = (url) => {
    if (url === "/") return "1.0";
    if (/dr12|dr14|start-up|digitalizare|femeia|modernizare|fonduri-europene$|consultanta/.test(url)) return "0.9";
    if (/instrumente|resurse|ghiduri|eligibilitate|portofoliu/.test(url)) return "0.8";
    return "0.7";
  };
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((url) => `  <url>
    <loc>${SITE}${url}</loc>
    <lastmod>${config.updatedAt}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>${priority(url)}</priority>
  </url>`).join("\n")}
</urlset>
`;
  fs.writeFileSync(SITEMAP_PATH, xml, "utf8");
}

function updateRedirects(pages) {
  let text = fs.existsSync(REDIRECTS_PATH) ? fs.readFileSync(REDIRECTS_PATH, "utf8") : "";
  const additions = [];
  for (const page of pages) {
    const clean = slugPath(page);
    const html = `${clean}.html`;
    const slash = `${clean}/`;
    const index = `${clean}/index.html`;
    for (const source of [slash, html, index]) {
      if (source === clean || text.includes(`${source} ${clean} 301`)) continue;
      additions.push(`${source} ${clean} 301`);
    }
  }
  if (additions.length) {
    text = `${text.replace(/\s+$/g, "")}\n\n# SEO and AI Search canonical routes.\n${additions.join("\n")}\n`;
    fs.writeFileSync(REDIRECTS_PATH, text, "utf8");
  }
}

function updateBlogJson(pages, config) {
  if (!fs.existsSync(BLOG_JSON_PATH)) return;
  const data = readJson(BLOG_JSON_PATH);
  data.posts = Array.isArray(data.posts) ? data.posts : [];
  const byId = new Map(data.posts.map((post) => [post.id, post]));
  for (const page of pages.filter((item) => item.type === "program" && !byId.has(item.slug))) {
    const editorial = getEditorialMetadata(page.slug);
    data.posts.push({
      id: page.slug,
      title: page.h1,
      slug: page.slug,
      metaTitle: page.title,
      metaDescription: page.description,
      excerpt: page.quickAnswer,
      content: `<p>Pagina statica publicata la /${page.slug}.</p>`,
      status: "published",
      published: true,
      primaryKeyword: page.programName,
      secondaryKeywords: [page.category, "fonduri europene", "eligibilitate"],
      bannerImage: "",
      bannerAlt: "",
      author: editorial?.author || config.defaults.author,
      reviewer: editorial?.reviewer,
      officialSources: editorial?.officialSources || sourcesForKeys(page.sourceKeys).map((source) => ({
        url: source.url,
        title: source.title,
        institution: source.institution,
        documentType: source.documentType,
        accessedAt: source.accessedAt,
        note: source.note
      })),
      editorialStatus: editorial?.status || "in_curs_de_verificare",
      lastVerifiedAt: editorial?.lastVerifiedAt,
      createdAt: config.updatedAt,
      updatedAt: editorial?.updatedAt || config.updatedAt,
      publishedAt: editorial?.publishedAt || config.updatedAt,
      date: config.updatedAt,
      dateFormatted: "19 mai 2026",
      category: page.category,
      readTime: 12,
      readingTime: editorial?.readingTime || 12,
      icon: "",
      canonicalUrl: canonical(page),
      internalLinks: page.related || [],
      faq: faqsForPage(page).map(([question, answer]) => ({ question, answer }))
    });
  }
  writeJson(BLOG_JSON_PATH, data);
}

function updateBanners() {
  if (!fs.existsSync(BANNERS_PATH)) return;
  const banners = readJson(BANNERS_PATH);
  const wanted = [
    {
      id: "slide-micro-apel-2",
      tag: "Microintreprinderi",
      title: "Modernizarea microintreprinderilor\nApel 2",
      description: "Pregatire pentru microintreprinderi: regiune, CAEN, documente, buget, cheltuieli si punctaj.",
      amount: "Finantare: conform apelului activ",
      ctaText: "Detalii program ->",
      ctaLink: "/investitii-modernizarea-microintreprinderilor-apel-2",
      image: "",
      altText: "Banner modernizarea microintreprinderilor Apel 2",
      icon: "ph-buildings",
      order: 10,
      active: true,
      officialGuideKey: "por-ne"
    },
    {
      id: "slide-fond-modernizare-regenerabila",
      tag: "Energie regenerabila",
      title: "Fondul pentru Modernizare\nEnergie regenerabila",
      description: "Pagina pentru capacitati noi de producere a energiei regenerabile: amplasament, avize, buget si depunere.",
      amount: "Finantare: conform ghidului apelului activ",
      ctaText: "Detalii program ->",
      ctaLink: "/fondul-modernizare-energie-regenerabila-2026",
      image: "",
      altText: "Banner Fondul pentru Modernizare energie regenerabila",
      icon: "ph-sun",
      order: 11,
      active: true,
      officialGuideKey: "fondul-modernizare"
    }
  ];
  for (const banner of wanted) {
    if (!banners.some((item) => item.id === banner.id)) banners.push(banner);
  }
  writeJson(BANNERS_PATH, banners);
}

function updateLlms(pages) {
  if (!fs.existsSync(LLMS_PATH)) return;
  let text = fs.readFileSync(LLMS_PATH, "utf8");
  const block = `\n## Pagini noi pentru vizibilitate AI si cautare vocala\n${pages
    .filter((page) => ["portofoliu", "testimoniale", "instrumente", "resurse", "webinarii", "investitii-modernizarea-microintreprinderilor-apel-2", "fondul-modernizare-energie-regenerabila-2026"].includes(page.slug))
    .map((page) => `- ${page.h1}: ${SITE}/${page.slug}`)
    .join("\n")}\n\n## Structura pentru asistenti AI\n- Paginile importante includ intrebari in limbaj natural, raspunsuri scurte vizibile, schema FAQPage si SpeakableSpecification.\n- Pentru sume, procente, punctaje si conditii finale, informatia trebuie verificata in apelul activ.\n`;
  if (!text.includes("Pagini noi pentru vizibilitate AI")) {
    text = `${text.replace(/\s+$/g, "")}\n${block}`;
    fs.writeFileSync(LLMS_PATH, text, "utf8");
  }
}

function main() {
  const config = readJson(CONFIG_PATH);
  const pages = config.pages || [];
  for (const page of pages) {
    validatePage(page);
    ensureFile(page, pageHtml(page, config));
  }
  updateSitemap(pages, config);
  updateRedirects(pages);
  updateBlogJson(pages, config);
  updateBanners();
  updateLlms(pages);
  console.log(`Generated ${pages.length} SEO program, hub and resource pages.`);
}

main();
