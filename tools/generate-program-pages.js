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
const {
  breadcrumbSchema,
  faqPageSchema,
  jsonLdGraph,
  organizationSchema,
  serviceSchema,
  webApplicationSchema,
  webPageSchema,
  websiteSchema
} = require("./schema-helpers");
const CLARITY_TRACKING_CODE = `  <script type="text/javascript">
    (function(c,l,a,r,i,t,y){
        c[a]=c[a]||function(){(c[a].q=c[a].q||[]).push(arguments)};
        t=l.createElement(r);t.async=1;t.src="https://www.clarity.ms/tag/"+i;
        y=l.getElementsByTagName(r)[0];y.parentNode.insertBefore(t,y);
    })(window, document, "clarity", "script", "wnvzyco6rq");
  </script>`;

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
  "consultanta-fonduri-europene": ["consultanță fonduri europene", "firmă consultanță fonduri europene", "consultant fonduri europene", "verificare eligibilitate fonduri europene", "cost consultanță fonduri europene", "dosar fonduri europene"],
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

function textWordCount(value) {
  const words = String(value || "").match(/[\p{L}\p{N}]+(?:[-''][\p{L}\p{N}]+)*/gu);
  return words ? words.length : 0;
}

function isEditorialProgram(page) {
  return page.template === "editorial-program";
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
  if (isEditorialProgram(page)) return Number(page.minWords || 1200);
  if (Number(page.minWords) > 0) return Number(page.minWords);
  if (PILLAR_SLUGS.has(page.slug)) return 2100;
  if (SECONDARY_SLUGS.has(page.slug)) return 1200;
  if (page.type === "program" || page.type === "hub" || page.type === "service") return 2000;
  return 1000;
}

function minFaqForPage(page) {
  if (isEditorialProgram(page)) return Math.min(6, Math.max(2, (page.faq || []).length || 2));
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
  if (isEditorialProgram(page)) return faq.slice(0, 6);
  const programName = page.programName || page.h1 || "program";
  const keyword = keywordsForPage(page)[0] || programName;
  const additions = [
    [`Cum verific daca ${programName} este potrivit pentru proiectul meu?`, `Porneste de la solicitant, cod CAEN, localitate, investitie, buget si documentele disponibile. Daca una dintre aceste piese nu se potriveste cu apelul activ, proiectul trebuie ajustat inainte de depunere.`],
    [`Cand nu merita sa aplic pentru ${programName}?`, `Nu merita sa aplici cand nu poti dovedi eligibilitatea, cand cheltuielile principale nu sunt permise, cand cofinantarea nu este acoperita sau cand calendarul nu permite documente complete si verificabile.`],
    [`Ce documente trebuie pregatite pentru ${programName}?`, "De regula sunt necesare documente de firma sau solicitant, documente pentru activitate si locatie, date financiare, oferte, descrierea investitiei si informatii despre cofinantare."],
    [`Cum se verifica un cod CAEN pentru ${programName}?`, "Codul CAEN se verifica prin certificatul constatator, activitatea reala, autorizarea necesara, lista de coduri eligibile a apelului si legatura directa dintre investitie si activitatea finantata."],
    [`Ce cheltuieli sunt sensibile la evaluare pentru ${programName}?`, "Sunt sensibile cheltuielile greu de justificat, activele supradimensionate, serviciile descrise vag, achizitiile incepute prea devreme si costurile care nu au legatura directa cu obiectivele proiectului."],
    [`Cum tratez cofinantarea si cheltuielile neeligibile pentru ${programName}?`, "Cofinantarea si cheltuielile neeligibile trebuie estimate separat de grant. Include rezerve pentru TVA, diferente de pret, costuri neacoperite si intarzieri in rambursare."],
    [`Ce greseli duc frecvent la respingere sau clarificari pentru ${programName}?`, "Apar probleme cand documentele sunt expirate, ofertele sunt incomplete, bugetul nu se leaga de activitate, punctajul este estimat optimist sau solicitantul nu poate sustine implementarea."],
    [`Cum folosesc informatiile despre ${programName} in 2026?`, "Foloseste informatiile ca filtru initial si confirma intotdeauna regulile in apelul activ. Programele pot schimba praguri, documente, punctaje si termene de la o sesiune la alta."],
    [`Ce rol are consultanta pentru ${keyword}?`, `Consultanta ajuta la trierea programului, verificarea documentelor, structurarea bugetului, pregatirea raspunsurilor la clarificari si reducerea riscurilor, dar nu poate garanta aprobarea finantarii.`],
    [`Cat de repede trebuie inceputa pregatirea dosarului pentru ${programName}?`, "Pregatirea trebuie inceputa inainte de deschiderea efectiva a apelului, mai ales daca sunt necesare oferte, documente pentru spatiu, autorizatii, calcule de punctaj sau clarificari privind solicitantul."]
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
  if (isEditorialProgram(page)) {
    const quickAnswerWords = textWordCount(page.quickAnswer);
    if (quickAnswerWords < 100 || quickAnswerWords > 150) {
      throw new Error(`${page.slug} trebuie sa aiba raspuns scurt intre 100 si 150 cuvinte; are ${quickAnswerWords}.`);
    }
    if ((page.faq || []).length > 6) {
      throw new Error(`${page.slug} trebuie sa aiba maximum 6 intrebari FAQ.`);
    }
    if ((page.commonMistakes || []).length < 6) {
      throw new Error(`${page.slug} trebuie sa aiba cel putin 6 greseli frecvente.`);
    }
  }
}

function schemaGraph(page, config) {
  const faq = faqsForPage(page);
  const editorial = getEditorialMetadata(page.slug);
  const pageNode = webPageSchema({
    type: page.schemaType === "CollectionPage" ? "CollectionPage" : "WebPage",
    url: canonical(page),
    name: page.title,
    description: page.description,
    dateModified: config.updatedAt
  });

  if (editorial) {
    Object.assign(pageNode, editorialSchemaProperties(editorial));
  }

  if (Array.isArray(page.sourceKeys) && page.sourceKeys.length) {
    pageNode.citation = officialSourceCitations(page.sourceKeys);
  }
  if (isEditorialProgram(page)) {
    pageNode.mainEntity = { "@id": `${canonical(page)}#service` };
    pageNode.about = {
      "@type": page.schemaType === "GovernmentService" ? "GovernmentService" : "Service",
      name: page.programName || page.h1,
      serviceType: page.category
    };
  }

  const graph = [
    organizationSchema(),
    websiteSchema(),
    pageNode,
    breadcrumbSchema([
      { name: "Acasa", item: `${SITE}/` },
      { name: page.h1, item: canonical(page) }
    ]),
    faqPageSchema(faq, { minItems: 2 })
  ];

  if (page.type === "program" || page.type === "service" || page.schemaType === "Service" || page.schemaType === "GovernmentService") {
    const serviceNode = serviceSchema({
      type: page.schemaType === "GovernmentService" ? "GovernmentService" : "Service",
      url: canonical(page),
      name: page.programName || page.h1,
      description: page.description,
      serviceType: page.category
    });
    if (isEditorialProgram(page)) {
      serviceNode.audience = (page.audience || []).slice(0, 4).map((item) => ({
        "@type": "Audience",
        audienceType: item
      }));
      serviceNode.potentialAction = {
        "@type": "CommunicateAction",
        name: "Trimite date pentru verificarea eligibilitatii",
        target: `${SITE}/contact`
      };
    }
    graph.push(serviceNode);
  }

  if (page.type === "tools") {
    graph.push(webApplicationSchema({
      url: canonical(page),
      name: "Instrumente fonduri europene",
      description: page.description,
      applicationCategory: "FinanceApplication"
    }));
  }

  return jsonLdGraph(graph);
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

function renderEditorialTable(title, columns, rows) {
  const safeRows = Array.isArray(rows) ? rows : [];
  return `<h2>${esc(title)}</h2>
      <div class="table-wrap">
        <table class="program-table">
          <thead>
            <tr>${columns.map((column) => `<th>${esc(column)}</th>`).join("")}</tr>
          </thead>
          <tbody>
            ${safeRows.map((row) => `<tr>${columns.map((_, index) => `<td>${esc(Array.isArray(row) ? row[index] : "")}</td>`).join("")}</tr>`).join("\n")}
          </tbody>
        </table>
      </div>`;
}

function renderPreparationSteps(steps) {
  const safeSteps = Array.isArray(steps) ? steps : [];
  return `<ol class="process-list">
        ${safeSteps.map((step) => {
    const title = Array.isArray(step) ? step[0] : "";
    const detail = Array.isArray(step) ? step[1] : step;
    return `<li><strong>${esc(title)}</strong>${detail ? ` ${esc(detail)}` : ""}</li>`;
  }).join("\n")}
      </ol>`;
}

function renderCaseExample(example) {
  const item = example || {};
  const rows = [
    ["Tip beneficiar", item.beneficiary || "TODO_CLIENT_EXEMPLU"],
    ["Obiectiv investi\u021bie", item.investmentObjective || "TODO_CLIENT_EXEMPLU"],
    ["Provoc\u0103ri", item.challenges || "TODO_CLIENT_EXEMPLU"],
    ["Ce s-a verificat", item.checked || "TODO_CLIENT_EXEMPLU"]
  ];
  return `${item.note ? `<p class="note">${esc(item.note)}</p>` : ""}
      <div class="table-wrap">
        <table class="program-table">
          <tbody>
            ${rows.map(([key, value]) => `<tr><th>${esc(key)}</th><td>${esc(value)}</td></tr>`).join("\n")}
          </tbody>
        </table>
      </div>`;
}

function renderEditorialNotes(notes) {
  if (!Array.isArray(notes) || !notes.length) return "";
  return `<h2>Note de verificare</h2>
      ${notes.map((note) => `<p>${esc(note)}</p>`).join("\n")}`;
}

function renderEditorialProgramContent(page) {
  const editorialHtml = renderEditorialSection(getEditorialMetadata(page.slug));
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
${editorialHtml}
      <h2>R\u0103spuns scurt</h2>
      <p class="intro">${esc(page.quickAnswer)}</p>
      ${renderEditorialTable("Cine poate aplica", ["Tip solicitant", "Eligibilitate posibil\u0103", "Ce trebuie verificat", "Observa\u021bii"], page.applicantRows)}
      ${renderEditorialTable("Ce investi\u021bii pot fi eligibile", ["Categorie cheltuial\u0103", "Exemple", "Aten\u021bie la", "Surs\u0103/TODO"], page.eligibleInvestmentRows)}
      ${renderEditorialTable("Documente necesare", ["Document", "Cine \u00eel preg\u0103te\u0219te", "C\u00e2nd este necesar", "Risc dac\u0103 lipse\u0219te"], page.documentRows)}
      <h2>Pa\u0219i de preg\u0103tire</h2>
      ${renderPreparationSteps(page.preparationSteps)}
      <h2>Gre\u0219eli frecvente</h2>
      <ul class="warning-list">${li(page.commonMistakes)}</ul>
      <h2>Exemplu realist anonimizat</h2>
      ${renderCaseExample(page.caseExample)}
      ${renderEditorialNotes(page.editorialNotes)}
${officialSourcesHtml}
      <h2>FAQ</h2>
      ${faqHtml}
      <h2>CTA</h2>
      <p>Trimite-ne codul CAEN / tipul fermei / investi\u021bia dorit\u0103 pentru verificarea eligibilit\u0103\u021bii.</p>`;
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

function renderConsultantaPillarContent(page) {
  const editorialHtml = renderEditorialSection(getEditorialMetadata(page.slug));
  const officialSourcesHtml = renderOfficialSources(page.sourceKeys, { id: `${page.slug}-official-sources` });
  const faqHtml = faqsForPage(page)
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  return `
      <p class="intro">FABER ajută firmele, fermierii și antreprenorii să decidă dacă un proiect merită pregătit pentru finanțare, ce program poate fi potrivit și ce riscuri trebuie clarificate înainte de dosar. Analiza pornește de la datele solicitantului, documente, buget și regulile apelului activ.</p>
${editorialHtml}

      <h2>Ce face o firmă de consultanță fonduri europene?</h2>
      <p>O firmă de consultanță pentru fonduri europene verifică dacă solicitantul, activitatea, investiția și documentele disponibile se potrivesc cu un program de finanțare. Rolul ei nu este să promită aprobarea, ci să reducă riscurile înainte ca beneficiarul să investească timp și bani într-un dosar. În practică, consultantul analizează codul CAEN, localitatea, forma juridică, istoricul firmei sau fermei, bugetul, cofinanțarea, cheltuielile propuse și grila de punctaj. Apoi recomandă programul potrivit, structurează strategia de depunere, pregătește documentația, răspunde la clarificări și poate sprijini etapa de contractare sau implementare. O colaborare bună începe cu date minime clare și cu o concluzie prudentă: proiect potrivit, proiect cu riscuri de clarificat sau proiect care nu ar trebui depus în forma actuală.</p>

      <h2>Pentru cine lucrăm</h2>
      <div class="grid">
        <section class="mini-card"><h3>Solicitanți</h3><ul>
          <li>firme existente;</li>
          <li>start-up-uri;</li>
          <li>fermieri;</li>
          <li>microîntreprinderi.</li>
        </ul></section>
        <section class="mini-card"><h3>Tipuri de proiecte</h3><ul>
          <li>proiecte de digitalizare;</li>
          <li>investiții agricole;</li>
          <li>producție și servicii;</li>
          <li>investiții regionale sau energetice, dacă apelul permite.</li>
        </ul></section>
      </div>

      <h2>Ce verificăm înainte de dosar</h2>
      <p>Verificarea inițială separă ideile promițătoare de dosarele riscante. Tabelul de mai jos arată informațiile cerute înainte de recomandarea unui program sau a unei strategii de punctaj.</p>
      <div class="table-wrap">
        <table class="program-table">
          <thead>
            <tr>
              <th>Element verificat</th>
              <th>De ce contează</th>
              <th>Documente/date necesare</th>
              <th>Risc dacă este ignorat</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Solicitant și formă juridică</td>
              <td>Programul poate accepta doar anumite categorii de beneficiari.</td>
              <td>CUI, certificat constatator, formă juridică, vechime.</td>
              <td>Dosar respins administrativ sau eligibilitate interpretată greșit.</td>
            </tr>
            <tr>
              <td>Cod CAEN și activitate reală</td>
              <td>Investiția trebuie să fie legată de activitatea finanțată.</td>
              <td>Coduri CAEN, autorizări, descriere activitate, punct de lucru.</td>
              <td>Cheltuieli neeligibile sau punctaj supraestimat.</td>
            </tr>
            <tr>
              <td>Localizare și spațiu</td>
              <td>Multe apeluri depind de regiune, rural/urban sau dreptul de folosință.</td>
              <td>Adresă proiect, contract spațiu, acte teren/clădire, durată folosință.</td>
              <td>Blocaj la contractare, clarificări sau imposibilitate de implementare.</td>
            </tr>
            <tr>
              <td>Buget și cofinanțare</td>
              <td>Grantul nu acoperă toate costurile și nu elimină presiunea de cash-flow.</td>
              <td>Buget estimativ, oferte, sursă cofinanțare, tratament TVA.</td>
              <td>Proiect aprobat pe hârtie, dar greu de susținut financiar.</td>
            </tr>
            <tr>
              <td>Cheltuieli propuse</td>
              <td>Fiecare achiziție trebuie să fie permisă și justificată prin obiective.</td>
              <td>Listă echipamente/servicii, specificații, oferte, justificare necesitate.</td>
              <td>Tăieri de buget, corecții sau respingere la evaluare.</td>
            </tr>
            <tr>
              <td>Punctaj și priorități</td>
              <td>Eligibilitatea nu înseamnă automat selecție la finanțare.</td>
              <td>Grilă de evaluare, criterii aplicabile, documente care susțin punctajul.</td>
              <td>Depunere cu șanse slabe sau strategie construită pe presupuneri.</td>
            </tr>
          </tbody>
        </table>
      </div>

      <h2>Cum decurge procesul</h2>
      <ol class="process-list">
        <li><strong>Discuție inițială.</strong> Clarificăm solicitantul, investiția, bugetul și termenul dorit.</li>
        <li><strong>Analiză eligibilitate.</strong> Verificăm datele minime, documentele disponibile și riscurile evidente.</li>
        <li><strong>Alegere program.</strong> Comparăm apelurile relevante și eliminăm programele nepotrivite.</li>
        <li><strong>Strategie punctaj.</strong> Estimăm prudent criteriile care pot fi susținute prin documente.</li>
        <li><strong>Dosar.</strong> Pregătim cererea, bugetul, anexele și justificările necesare.</li>
        <li><strong>Depunere.</strong> Verificăm forma finală și încărcarea documentelor în platforma programului.</li>
        <li><strong>Clarificări.</strong> Răspundem solicitărilor primite de la autoritate, pe baza documentelor.</li>
        <li><strong>Contractare.</strong> Verificăm condițiile de semnare, termenele și obligațiile beneficiarului.</li>
        <li><strong>Implementare.</strong> Sprijinim achizițiile, raportările și cererile de plată/rambursare dacă serviciul este inclus.</li>
      </ol>

      <h2>Ce NU promitem</h2>
      <ul class="warning-list">
        <li>Nu promitem finanțare garantată.</li>
        <li>Nu recomandăm programe nepotrivite doar pentru a depune un dosar.</li>
        <li>Nu estimăm șanse fără date minime despre solicitant, investiție, buget și documente.</li>
      </ul>
      <p>Un răspuns responsabil poate fi uneori „nu acum” sau „nu pe acest program”. Este mai util să oprești un dosar slab înainte de depunere decât să consumi resurse într-un proiect care nu poate fi susținut.</p>

      <h2>Cost consultanță fonduri europene</h2>
      <p>Costul consultanței depinde de program, complexitatea investiției, documentele existente, etapa în care se află proiectul și suportul cerut după depunere. Un dosar simplu, cu documente pregătite, nu se estimează la fel ca un proiect cu investiții tehnice, achiziții complexe, clarificări sau implementare pe termen lung.</p>
      <p>Nu introducem prețuri standard dacă ele nu există deja în proiect. Pentru o estimare prudentă, trimite datele de bază și programul vizat, iar FABER poate indica ce trebuie verificat înainte de ofertare.</p>
      <p><a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">Solicită evaluare pentru cost</a></p>

      <h2>Programe relevante</h2>
      <p>Pagina aceasta funcționează ca punct de intrare. Pentru reguli, documente și condiții specifice, verifică pagina programului potrivit și sursa oficială a apelului activ.</p>
      <div class="related-links">
        <a href="/consultanta-afir">Consultanță AFIR</a>
        <a href="/dr12-afir">DR 12 AFIR</a>
        <a href="/dr14">DR 14 AFIR</a>
        <a href="/start-up-nation-2026">Start-Up Nation</a>
        <a href="/digitalizare-imm">Digitalizare IMM</a>
        <a href="/por-adr-nord-est">POR / ADR Nord-Est</a>
        <a href="/fonduri-europene-agricultura">Fonduri europene agricultură</a>
        <a href="/fondul-de-modernizare">Fondul de Modernizare</a>
      </div>

      <h2>Ce intră, de regulă, într-un dosar</h2>
      <p>Un dosar pentru fonduri europene nu este doar un formular completat. El trebuie să lege solicitantul, investiția, bugetul și documentele suport într-o explicație coerentă. Documentele diferă de la program la program, dar de obicei includ informații despre firmă sau fermă, situații financiare, acte pentru spațiu, oferte, descrierea investiției, buget, declarații și anexe specifice apelului.</p>
      <p>Înainte de depunere, verificarea internă trebuie să urmărească dacă fiecare afirmație poate fi susținută prin documente. Dacă bugetul include echipamente, serviciile sau lucrările trebuie să fie justificate prin nevoia proiectului. Dacă se solicită punctaj pentru o condiție, acea condiție trebuie să poată fi demonstrată. Această disciplină reduce clarificările și riscul de respingere.</p>

      <h2>Responsabilități în colaborare</h2>
      <p>Consultanța funcționează bine atunci când responsabilitățile sunt clare de la început. Beneficiarul cunoaște activitatea, investiția și constrângerile reale ale afacerii. Consultantul cunoaște logica programului, documentele cerute, riscurile frecvente și modul în care informațiile trebuie așezate în dosar. Niciuna dintre părți nu poate înlocui complet rolul celeilalte.</p>
      <ul>
        <li>Clientul furnizează date corecte despre firmă, fermă, localizare, buget și documentele disponibile.</li>
        <li>FABER verifică potrivirea cu programele relevante și semnalează riscurile înainte de depunere.</li>
        <li>Bugetul se construiește pe oferte și justificări, nu pe estimări optimiste.</li>
        <li>Decizia de depunere se ia după verificarea ghidului activ și a documentelor minime.</li>
      </ul>
      <p>Această împărțire este importantă mai ales când proiectul trece din etapa de idee în etapa de implementare. După contractare, apar termene, achiziții, raportări și obligații de menținere a investiției. Un dosar pregătit corect ar trebui să poată fi implementat, nu doar depus.</p>

      <h2>Riscuri frecvente înainte de depunere</h2>
      <p>Cele mai multe probleme apar când proiectul este construit prea repede sau când programul este ales doar pentru că pare popular. Un cod CAEN nealiniat cu investiția, un spațiu fără documente suficiente, o ofertă prea generală sau o cofinanțare neclară pot transforma o idee bună într-un dosar vulnerabil. De aceea, verificarea eligibilității trebuie făcută înainte de achiziții, contracte ferme sau promisiuni către furnizori.</p>
      <p>Un alt risc este supraestimarea punctajului. Dacă un criteriu nu poate fi susținut prin documente, el nu ar trebui tratat ca punctaj sigur. La fel, dacă un program cere condiții de vechime, localizare, dimensiune economică sau activitate autorizată, aceste elemente trebuie confirmate înainte de a investi în documentație completă.</p>

      <h2>Când recomandăm să nu depui imediat</h2>
      <p>Există situații în care o amânare este mai sănătoasă decât o depunere rapidă. Dacă documentele pentru spațiu nu acoperă perioada cerută, dacă ofertele nu descriu suficient cheltuielile, dacă solicitantul nu poate susține cofinanțarea sau dacă activitatea nu este clar legată de investiție, dosarul trebuie corectat înainte de depunere. Aceeași prudență se aplică atunci când programul este încă în consultare, când ghidul nu este final sau când informațiile publice nu permit o estimare serioasă a punctajului. În aceste cazuri, rolul consultanței este să protejeze beneficiarul de decizii costisitoare, nu să forțeze un dosar doar pentru a respecta un calendar comercial. Concluzia trebuie documentată și revizuită când apar reguli noi.</p>
      <p>Pentru proiectele aflate la limită, recomandarea poate fi pregătirea documentelor lipsă, ajustarea investiției, schimbarea calendarului sau urmărirea unui apel viitor. Această etapă nu blochează proiectul; îl face mai ușor de apărat la evaluare.</p>

      <h2>Întrebări frecvente</h2>
      ${faqHtml}

      <h2>Surse și metodologie</h2>
      <p>Metodologia FABER pornește de la verificarea eligibilității, a documentelor, a grilei de punctaj și a riscurilor de implementare. Pentru decizii finale se verifică întotdeauna ghidul oficial, anexele, corrigendumurile și comunicările autorității.</p>
      <div class="related-links">
        <a href="/metodologie-verificare-eligibilitate">Metodologia FABER</a>
        <a href="/surse-oficiale-fonduri-europene">Surse oficiale fonduri europene</a>
        <a href="/glosar-fonduri-europene">Glosar fonduri europene</a>
        <a href="/verificare-eligibilitate-fonduri-europene">Verificare eligibilitate</a>
      </div>
      ${officialSourcesHtml}
      <p class="note">Data actualizării: <time datetime="2026-05-20">20 mai 2026</time>. Indicatorii comerciali precum număr de proiecte, valoare atrasă sau rată de aprobare trebuie publicați doar dacă există documente interne, portofoliu sau metodologie care îi susțin.</p>
`;
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
  if (page.slug === "consultanta-fonduri-europene") {
    return renderConsultantaPillarContent(page);
  }
  if (isEditorialProgram(page)) {
    return renderEditorialProgramContent(page);
  }

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
      <p class="intro">${esc(page.quickAnswer)}</p>
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
      <h2>Eligibilitatea se verifica prin solicitant, activitate, documente si investitie.</h2>
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
      <h2>Pentru o verificare initiala, trimite date despre solicitant, investitie, buget si programul urmarit.</h2>
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
  const isConsultantaPillar = page.slug === "consultanta-fonduri-europene";
  const primaryCta = isConsultantaPillar ? "Solicită verificare eligibilitate" : "Verifica eligibilitatea";
  const secondaryCta = isConsultantaPillar ? "Vezi metodologia de lucru" : "Discuta cu un consultant";
  const secondaryHref = isConsultantaPillar ? "/metodologie-verificare-eligibilitate" : "/contact";
  const finalCtaTitle = isEditorialProgram(page) ? "Verificare eligibilitate" : "Urmatorul pas";
  const finalCtaText = isEditorialProgram(page)
    ? "Trimite-ne codul CAEN / tipul fermei / investi\u021bia dorit\u0103 pentru verificarea eligibilit\u0103\u021bii."
    : "Trimite cateva detalii despre solicitant, localitate, cod CAEN, investitie si buget. Raspunsul initial este orientativ si nu reprezinta promisiune de finantare.";
  const finalPrimaryCta = isEditorialProgram(page) ? "Trimite datele pentru verificare" : "Trimite datele proiectului";
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
${CLARITY_TRACKING_CODE}
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
      <a class="btn btn-primary" href="/verificare-eligibilitate-fonduri-europene">${esc(primaryCta)}</a>
      <a class="btn btn-secondary" href="${secondaryHref}">${esc(secondaryCta)}</a>
    </div>
  </header>
  <main class="container">
    <article class="panel">
${renderMainContent(page)}
      <div class="related-links">${links(page.related)}</div>
    </article>
    <section class="cta-box">
      <h2>${esc(finalCtaTitle)}</h2>
      <p>${esc(finalCtaText)}</p>
      <div class="cta-actions">
        <a class="btn btn-primary" href="/contact">${esc(finalPrimaryCta)}</a>
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
    .join("\n")}\n\n## Structura pentru asistenti AI\n- Paginile importante includ intrebari in limbaj natural, raspunsuri scurte vizibile si schema FAQPage doar cand intrebarile sunt vizibile in pagina.\n- Pentru sume, procente, punctaje si conditii finale, informatia trebuie verificata in apelul activ.\n`;
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
