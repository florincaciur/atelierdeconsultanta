#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { normalizeQuestion } = require("./schema-helpers");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";

function read(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8");
}

function write(file, value) {
  fs.writeFileSync(path.join(ROOT, file), value, "utf8");
}

function load(file) {
  return cheerio.load(read(file), { decodeEntities: false });
}

function save(file, $) {
  write(file, $.html());
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

function faqEntity(question, answer) {
  return {
    "@type": "Question",
    name: question,
    acceptedAnswer: {
      "@type": "Answer",
      text: answer
    }
  };
}

function uniqueFaqPairs(faqs) {
  const seen = new Set();
  const unique = [];
  for (const [question, answer] of faqs) {
    const key = normalizeQuestion(question);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    unique.push([question, answer]);
  }
  return unique;
}

function visibleFaqKeys($, container) {
  const keys = new Set();
  container.find(".faq-item h3, .faq-item summary, .faq-q").each((_, element) => {
    const key = normalizeQuestion($(element).text());
    if (key) keys.add(key);
  });
  return keys;
}

function dedupeVisibleFaqs($, container) {
  const seen = new Set();
  container.find(".faq-item").each((_, element) => {
    const key = normalizeQuestion($(element).find("h3, summary, .faq-q").first().text());
    if (!key) return;
    if (seen.has(key)) {
      $(element).remove();
      return;
    }
    seen.add(key);
  });
}

function addFaqSchema($, faqs) {
  const uniqueFaqs = uniqueFaqPairs(faqs);
  let handled = false;
  $('script[type="application/ld+json"]').each((_, element) => {
    if (handled) return;
    const script = $(element);
    let data;
    try {
      data = JSON.parse(script.text());
    } catch {
      return;
    }
    const graph = Array.isArray(data["@graph"]) ? data["@graph"] : null;
    const faq = graph
      ? graph.find((node) => node && node["@type"] === "FAQPage")
      : data["@type"] === "FAQPage" ? data : null;
    if (!faq) return;
    faq.mainEntity = Array.isArray(faq.mainEntity) ? faq.mainEntity : [];
    const merged = [];
    const seen = new Set();
    for (const item of faq.mainEntity) {
      const key = normalizeQuestion(item?.name || item?.question || "");
      if (!key || seen.has(key)) continue;
      seen.add(key);
      merged.push(item);
    }
    for (const [question, answer] of uniqueFaqs) {
      const key = normalizeQuestion(question);
      if (!seen.has(key)) {
        merged.push(faqEntity(question, answer));
        seen.add(key);
      }
    }
    faq.mainEntity = merged;
    script.text(JSON.stringify(data, null, 2));
    handled = true;
  });
  if (!handled) {
    $("head").append(`<script type="application/ld+json">${JSON.stringify({
      "@context": "https://schema.org",
      "@type": "FAQPage",
      mainEntity: uniqueFaqs.map(([question, answer]) => faqEntity(question, answer))
    }, null, 2)}</script>`);
  }
}

function updateConfig() {
  const file = path.join(ROOT, "config", "seo-programs.json");
  const config = JSON.parse(fs.readFileSync(file, "utf8"));
  const page = config.pages.find((item) => item.slug === "consultanta-fonduri-europene");
  if (page) {
    page.title = "Consultanță pentru fonduri europene | Eligibilitate, dosar și cost";
    page.description = "Consultanță pentru fonduri europene: evaluarea proiectului, alegerea programului potrivit, strategie de punctaj, dosar și clarificări FABER.";
    page.h1 = "Consultanță pentru Fonduri Europene";
    page.quickAnswer = "FABER oferă consultanță pentru fonduri europene prin evaluarea proiectului, alegerea programului potrivit și construirea unei strategii de punctaj bazate pe documente. Analiza include eligibilitatea solicitantului, cofinanțarea, cheltuielile propuse și riscurile de clarificat înainte de depunere.";
    page.programName = "Consultanță pentru fonduri europene";
  }
  const aboutTrust = config.pages.find((item) => item.slug === "testimoniale");
  if (aboutTrust && Array.isArray(aboutTrust.faq)) {
    const wanted = [
      ["Cum colectam testimoniale?", "Feedbackul este cerut dupa etape concrete de lucru si este publicat doar daca beneficiarul isi da acordul."],
      ["Clientul isi da acordul pentru publicare?", "Da. Fara acord explicit, testimonialul ramane intern sau este anonimizat strict."]
    ];
    for (const item of wanted) {
      if (!aboutTrust.faq.some(([q]) => q === item[0])) aboutTrust.faq.push(item);
    }
  }
  fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function updateHome() {
  const file = "index.html";
  const $ = load(file);
  $("#requested-content-css").remove();
  $(".hero-title").first().html('Consultanță Fonduri Europene<br><span class="gradient-text">și Finanțări Nerambursabile</span>');
  $(".hero-subtitle").first().text("FABER ajută firme, fermieri, start-up-uri și IMM-uri să verifice eligibilitatea, să aleagă programul potrivit, să construiască strategia de punctaj și să pregătească dosarul pentru finanțări nerambursabile.");
  const heroCta = $("#hero .hero-ctas .btn-primary").first();
  heroCta
    .attr("href", "#eligibility-whatsapp-dialog")
    .attr("data-whatsapp-dialog-open", "")
    .attr("aria-haspopup", "dialog")
    .attr("aria-controls", "eligibility-whatsapp-dialog")
    .text("Verifică eligibilitatea");
  $("#seo-ai-snippet").remove();
  $("#servicii .section-label").first().text("Ce facem");
  $("#servicii .section-title").first().text("Consultanță clară, de la eligibilitate la clarificări");
  $("#servicii .section-subtitle").first().text("Serviciile includ analiza eligibilității, alegerea programului, strategia de punctaj, redactarea dosarului și suportul în clarificări.");
  const faqSection = $("#homepage-faq .homepage-faq-grid").first();
  const visibleFaqs = [
    ["Cum se face analiza eligibilității?", "Analiza pornește de la solicitant, cod CAEN sau activitate, localitatea investiției, documentele disponibile, buget, cofinanțare și regulile apelului activ."],
    ["Cât durează procesul?", "O verificare inițială poate fi făcută după primirea datelor de bază, iar pregătirea dosarului depinde de program, documente, oferte, avize și termenul apelului."],
    ["Ce servicii include colaborarea?", "Colaborarea poate include analiza eligibilității, alegerea programului, strategia de punctaj, redactarea dosarului și suport în clarificări."],
    ["De ce nu promite FABER finanțare garantată?", "Aprobarea depinde de ghidul oficial, punctaj, bugetul apelului, documentele solicitantului și evaluarea autorității."]
  ];
  dedupeVisibleFaqs($, faqSection);
  const existingHomeFaqs = visibleFaqKeys($, faqSection);
  for (const [question, answer] of visibleFaqs) {
    const key = normalizeQuestion(question);
    if (!existingHomeFaqs.has(key)) {
      faqSection.append(`<section class="homepage-faq-item faq-item"><h3>${question}</h3><p>${answer}</p></section>`);
      existingHomeFaqs.add(key);
    }
  }
  addFaqSchema($, visibleFaqs);
  save(file, $);
}

function updateAbout() {
  const file = "despre-faber/index.html";
  const $ = load(file);
  $(".hero .eyebrow").first().text("Consultanță cu integritate și rezultate");
  $(".hero h1").first().text("Despre FABER");
  $(".hero p").first().text("FABER este Atelier de Consultanță pentru fonduri europene și finanțări nerambursabile: o echipă care verifică eligibilitatea, explică riscurile și pregătește proiecte pentru firme, fermieri, IMM-uri, start-up-uri și organizații.");
  $(".hero-actions").first().html('<a class="btn btn-primary" href="/contact">Contactează-ne</a><a class="btn btn-secondary" href="/metodologie-verificare-eligibilitate">Vezi metodologia</a>');
  $(".panel > p.intro").first().text("FABER combină consultanța practică pentru fonduri europene cu o regulă simplă: recomandările trebuie să fie documentabile. Valorile echipei sunt onestitatea, responsabilitatea și prudența, mai ales atunci când un proiect pare atractiv, dar are riscuri de eligibilitate, punctaj sau cofinanțare.");
  $("td").each((_, element) => {
    const text = $(element).text();
    if (/Se publica dupa confirmare|Date in curs de validare/i.test(text)) $(element).closest("tr").remove();
  });
  if (!$("body").text().includes("Misiune si valori FABER")) {
    $("h2").filter((_, el) => $(el).text().includes("Ce nu promite")).first().before(`
      <h2>Misiune si valori FABER</h2>
      <p>Misiunea FABER este sa transforme ideile de investitie in decizii mai clare: continuam, ajustam sau amanam pana cand documentele sustin proiectul. Onestitatea inseamna sa spunem cand un program nu se potriveste. Responsabilitatea inseamna sa legam bugetul de activitatea reala. Prudenta inseamna sa nu tratam punctajul ca sigur daca nu exista dovezi.</p>
      <p>In proiecte anonimizate, FABER a ajutat beneficiari sa curete bugete de digitalizare prea generale, sa verifice SO pentru ferme mici, sa separe cheltuielile eligibile de cele neeligibile si sa pregateasca raspunsuri la clarificari fara promisiuni de aprobare garantata.</p>
    `);
  }
  if (!$("body").text().includes("rezultatele vor fi actualizate")) {
    $("h2").filter((_, el) => $(el).text().includes("Claims")).first().after('<p class="note">Rezultatele, valorile de portofoliu si orice claim numeric vor fi actualizate doar cand exista dovada interna, acord de publicare sau document public verificabil.</p>');
  }
  const faqContainer = $(".faq").first();
  const faqs = [
    ["Cum a apărut FABER?", "FABER a apărut ca un atelier de consultanță orientat spre decizii prudente: eligibilitate verificată, program potrivit și dosar construit pe documente."],
    ["De ce nu promiteți finanțare garantată?", "Pentru că aprobarea depinde de autoritatea finanțatoare, ghidul activ, punctaj, bugetul apelului și documentele beneficiarului."],
    ["Ce valori ghidează colaborarea?", "Onestitatea, responsabilitatea și prudența: spunem ce se poate verifica, ce lipsește și ce risc trebuie clarificat înainte de depunere."],
    ["Cu ce tipuri de proiecte lucrați?", "Lucrăm cu firme, IMM-uri, fermieri, start-up-uri și organizații care pregătesc investiții în agricultură, digitalizare, energie, producție sau servicii."],
    ["Când actualizați rezultatele publice?", "Le actualizăm când există dovezi publicabile, acordul clientului și o metodologie clară pentru cifrele prezentate."]
  ];
  dedupeVisibleFaqs($, faqContainer);
  const existingAboutFaqs = visibleFaqKeys($, faqContainer);
  for (const [question, answer] of faqs) {
    const key = normalizeQuestion(question);
    if (!existingAboutFaqs.has(key)) {
      faqContainer.append(`<section class="faq-item"><h3>${question}</h3><p>${answer}</p></section>`);
      existingAboutFaqs.add(key);
    }
  }
  addFaqSchema($, faqs);
  save(file, $);
}

function updateContact() {
  const file = "contact/index.html";
  const $ = load(file);
  const title = "Contactează consultantul tău pentru fonduri europene – FABER";
  $("title").text(title);
  ensureMeta($, "description", "Contactează consultantul tău pentru fonduri europene – FABER. Trimite datele proiectului pentru o analiză inițială confidențială.");
  ensureProperty($, "og:title", title);
  ensureProperty($, "og:description", "Hai să discutăm despre proiectul tău. Datele transmise sunt folosite doar pentru analiza solicitării și răspunsul FABER.");
  $(".hero .eyebrow").first().text("Contact");
  $(".hero h1").first().text("Contactează-ne");
  $(".hero p").first().text("Hai să discutăm despre proiectul tău");
  if (!$(".hero-actions").length) {
    $(".hero").append('<div class="hero-actions"><a class="btn btn-primary" href="#contact-form-title">Solicită verificare eligibilitate</a></div>');
  }
  if (!$(".contact-snippet").length) {
    $(".contact-layout").before('<p class="intro contact-snippet">Pagina de contact este locul în care poți trimite primele date despre proiect pentru o verificare inițială. Informațiile sunt tratate confidențial și sunt folosite doar pentru a înțelege eligibilitatea, programul potrivit, documentele necesare și riscurile posibile.</p>');
  }
  $(".contact-form").find("input, select, textarea").each((_, element) => {
    const field = $(element);
    if (field.attr("type") === "hidden") return;
    if (!field.attr("required") && field.attr("id") !== "website") field.attr("required", "required");
    const id = field.attr("id");
    if (!id) return;
    const small = field.parent().find(".error-message").first();
    if (small.length) {
      small.attr("id", `${id}-error`).attr("aria-live", "polite");
      field.attr("aria-describedby", `${id}-error`);
      const label = $(`label[for="${id}"]`).first().text().trim() || "Acest câmp";
      small.text(`${label} este obligatoriu.`);
    }
  });
  const gdprError = $(".consent-row .error-message").first();
  if (gdprError.length) {
    gdprError.attr("id", "gdpr-error").attr("aria-live", "polite").text("Acordul pentru prelucrarea datelor este obligatoriu.");
    $("#gdpr").attr("aria-describedby", "gdpr-error").attr("required", "required");
  }
  const faqContainer = $("#contact-faq-title").parent();
  const faqs = [
    ["Cât durează analiza?", "După primirea datelor de bază, FABER poate indica pașii de clarificare; durata completă depinde de program, documente, oferte și termenul apelului."],
    ["Ce date sunt necesare?", "Sunt utile numele, emailul, telefonul, localitatea investiției, tipul solicitantului, codul CAEN sau activitatea, bugetul, cofinanțarea și descrierea proiectului."],
    ["Datele transmise sunt confidențiale?", "Da. Datele sunt folosite pentru analiza solicitării și nu sunt publicate sau folosite în materiale comerciale fără acord."],
    ["Pot trimite formularul dacă nu știu programul potrivit?", "Da. Alege opțiunea Nu știu încă și descrie investiția, iar programul potrivit va fi verificat după ghidurile active."]
  ];
  dedupeVisibleFaqs($, faqContainer);
  const existingContactFaqs = visibleFaqKeys($, faqContainer);
  for (const [question, answer] of faqs) {
    const key = normalizeQuestion(question);
    if (!existingContactFaqs.has(key)) {
      faqContainer.append(`<section class="faq-item"><h3>${question}</h3><p>${answer}</p></section>`);
      existingContactFaqs.add(key);
    }
  }
  addFaqSchema($, faqs);
  save(file, $);
}

function updateLegalPage(file, title, summary) {
  const $ = load(file);
  $(".update-badge").text("Ultima revizuire: 26 mai 2026");
  $(".page-hero h1").first().text(title);
  $(".page-hero p").first().text(summary);
  if (!$(".legal-review-note").length) {
    $(".content-wrapper").prepend(`
      <div class="highlight-box legal-review-note">
        <p><strong>Revizuit la 26 mai 2026.</strong> Pagina este actualizată orientativ conform GDPR, legislației române aplicabile și practicilor de informare transparentă. Pentru situații juridice specifice, verificarea finală trebuie făcută cu un specialist autorizat.</p>
        <p>Surse utile: <a href="https://eur-lex.europa.eu/eli/reg/2016/679/oj" target="_blank" rel="noopener noreferrer">Regulamentul (UE) 2016/679</a> și <a href="https://www.dataprotection.ro/" target="_blank" rel="noopener noreferrer">ANSPDCP</a>.</p>
      </div>`);
  }
  save(file, $);
}

function updateLegal() {
  updateLegalPage("gdpr.html", "Politica GDPR", "Drepturile tale privind datele personale și modul în care FABER răspunde solicitărilor GDPR.");
  updateLegalPage("politica-de-confidentialitate.html", "Politica de Confidențialitate", "Cum colectăm, folosim și protejăm datele transmise prin site și formularul de contact.");
  updateLegalPage("termeni-si-conditii.html", "Termeni și Condiții", "Condițiile generale pentru folosirea site-ului și pentru discuțiile de consultanță cu FABER.");
}

function update404() {
  const file = "404.html";
  const $ = load(file);
  ensureMeta($, "robots", "noindex, nofollow");
  $("title").text("Pagina nu a fost găsită | FABER");
  ensureMeta($, "description", "Pagina solicitată nu a fost găsită. Revino la FABER pentru informații despre fonduri europene.");
  $("h1").first().text("Pagina nu a fost găsită");
  $("main p").first().text("Adresa accesată nu este disponibilă public sau nu mai există. Poți reveni la pagina principală pentru programe de finanțare și consultanță.");
  $("main a").first().attr("href", "/").text("Înapoi la homepage");
  save(file, $);
}

function redirectFallbackHtml(slug) {
  const target = `/${slug}`;
  const title = slug.replace(/-/g, " ");
  return `<!DOCTYPE html>
<html lang="ro">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Redirecționare | ${title}</title>
  <meta name="robots" content="noindex, follow" />
  <link rel="canonical" href="${SITE}${target}" />
  <meta http-equiv="refresh" content="0; url=${target}" />
  <script>window.location.replace('${target}');</script>
</head>
<body>
  <main style="font-family: Arial, sans-serif; max-width: 720px; margin: 12vh auto; padding: 32px; line-height: 1.6; color: #1a2540;">
    <h1>Ești redirecționat către o nouă adresă</h1>
    <p>Pagina veche a fost mutată. Dacă redirecționarea nu pornește automat, deschide <a href="${target}">${target}</a>.</p>
  </main>
</body>
</html>
`;
}

function updateLegacyRedirects() {
  const redirectsPath = path.join(ROOT, "_redirects");
  let redirects = fs.existsSync(redirectsPath) ? fs.readFileSync(redirectsPath, "utf8") : "";
  const additions = [];
  for (const entry of fs.readdirSync(ROOT, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".html")) continue;
    if (["index.html", "404.html", "gdpr.html", "politica-de-confidentialitate.html", "termeni-si-conditii.html"].includes(entry.name)) continue;
    const slug = entry.name.replace(/\.html$/i, "");
    if (!fs.existsSync(path.join(ROOT, slug, "index.html"))) continue;
    fs.writeFileSync(path.join(ROOT, entry.name), redirectFallbackHtml(slug), "utf8");
    for (const source of [`/${slug}.html`, `/${slug}/index.html`]) {
      const line = `${source} /${slug} 301`;
      if (!redirects.includes(line)) additions.push(line);
    }
  }
  if (additions.length) {
    redirects = `${redirects.replace(/\s+$/g, "")}\n\n# Legacy HTML fallback pages.\n${additions.join("\n")}\n`;
    fs.writeFileSync(redirectsPath, redirects, "utf8");
  }
}

function updateRobots() {
  write("robots.txt", `User-agent: *
Allow: /
Disallow: /admin/
Sitemap: ${SITE}/sitemap.xml
`);
}

function main() {
  updateConfig();
  updateHome();
  updateAbout();
  updateContact();
  updateLegal();
  update404();
  updateLegacyRedirects();
  updateRobots();
  console.log("Finalized requested content updates.");
}

main();
