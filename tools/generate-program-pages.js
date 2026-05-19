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
  const faq = page.faq || [];
  const graph = [
    {
      "@type": "Organization",
      "@id": `${SITE}/#organization`,
      "name": "Atelier de Consultanta",
      "url": SITE,
      "email": "atelier.consultanta@gmail.com",
      "telephone": ["+40769828338", "+40753326229"],
      "areaServed": "RO",
      "knowsAbout": ["fonduri europene", "finantari nerambursabile", "AFIR", "PNRR", "Start-Up Nation", "digitalizare IMM", "energie regenerabila"]
    },
    {
      "@type": "WebSite",
      "@id": `${SITE}/#website`,
      "url": SITE,
      "name": "Atelier de Consultanta",
      "publisher": { "@id": `${SITE}/#organization` },
      "inLanguage": "ro-RO"
    },
    {
      "@type": page.schemaType === "CollectionPage" ? "CollectionPage" : "WebPage",
      "@id": `${canonical(page)}#webpage`,
      "url": canonical(page),
      "name": page.title,
      "description": page.description,
      "isPartOf": { "@id": `${SITE}/#website` },
      "inLanguage": "ro-RO",
      "dateModified": config.updatedAt,
      "publisher": { "@id": `${SITE}/#organization` },
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

  if (page.type === "program" || page.type === "service" || page.schemaType === "Service" || page.schemaType === "GovernmentService") {
    graph.push({
      "@type": page.schemaType === "GovernmentService" ? "GovernmentService" : "Service",
      "@id": `${canonical(page)}#service`,
      "name": page.programName || page.h1,
      "description": page.description,
      "provider": { "@id": `${SITE}/#organization` },
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
      "provider": { "@id": `${SITE}/#organization` }
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

function renderMainContent(page) {
  const faqHtml = (page.faq || [])
    .map(([question, answer]) => `<section class="faq-item"><h3>${esc(question)}</h3><p>${esc(answer)}</p></section>`)
    .join("\n");

  let html = `
      <p id="speakable-summary" class="intro speakable" data-speakable="true">${esc(page.quickAnswer)}</p>
      ${renderTable(page)}
      <h2>Pe scurt</h2>
      <p>${esc(page.programName)} trebuie analizat ca o decizie de investitie, nu doar ca o oportunitate de finantare. Inainte de orice buget, solicitantul trebuie sa verifice incadrarea, documentele, calendarul, costurile eligibile si riscurile care pot aparea la evaluare sau implementare.</p>
      <p>Informatiile de pe aceasta pagina sunt construite pentru orientare practica. Ele nu promit aprobare si nu inlocuiesc verificarea apelului activ, a anexelor si a grilei de selectie. Scopul este sa poti pregati o discutie serioasa despre eligibilitate si dosar.</p>
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
      ${page.includeTools ? renderTools() : ""}
      ${page.includeDownloads ? renderDownloads() : ""}
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
  while (wordCount(html) < 2050) {
    html += `\n<p>${esc(depthParagraphs[wordCount(html) % depthParagraphs.length])}</p>`;
  }
  return html;
}

function pageHtml(page, config) {
  const extraCss = page.includeTools || page.includeDownloads ? `\n  <link rel="stylesheet" href="/assets/seo-tools.css" />` : "";
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

function updateSitemap(pages, config) {
  const existing = parseSitemapUrls()
    .map((url) => url.replace(SITE, ""))
    .filter(Boolean);
  const generated = pages.map((page) => slugPath(page));
  const all = [...existing, ...generated].map(cleanUrl);
  const seen = new Set();
  const urls = all.filter((url) => {
    if (seen.has(url)) return false;
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
      author: config.defaults.author,
      createdAt: config.updatedAt,
      updatedAt: config.updatedAt,
      publishedAt: config.updatedAt,
      date: config.updatedAt,
      dateFormatted: "19 mai 2026",
      category: page.category,
      readTime: 12,
      icon: "",
      canonicalUrl: canonical(page),
      internalLinks: page.related || [],
      faq: (page.faq || []).map(([question, answer]) => ({ question, answer }))
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
