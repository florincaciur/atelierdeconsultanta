#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForPage, loadPriorityConfig } = require("../tools/priority-aeo");
const {
  cleanText,
  comparableText,
  hasType,
  parseJsonLd,
  visibleFaqItems
} = require("../tools/structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DATE = "2026-07-13";
const REPORT_PATH = path.join(ROOT, "reports", `answer-engine-readiness-${REPORT_DATE}.md`);
const WRITE_REPORT = process.argv.includes("--report");
const FACT_TERMS = [
  /cine (?:este|poate fi|poate folosi)/iu,
  /finanț/iu,
  /contribuți/iu,
  /cheltuieli|date intră/iu,
  /documente/iu,
  /criterii|influențează SO/iu,
  /când/iu,
  /statut/iu
];

function words(value) {
  return cleanText(value).split(/\s+/u).filter(Boolean).length;
}

function hiddenContent($, root) {
  return root.find("[hidden], [aria-hidden='true'], [style*='display: none'], [style*='display:none'], [style*='visibility: hidden'], [style*='visibility:hidden'], .visually-hidden, .sr-only");
}

function faqSchemaItems($) {
  const blocks = parseJsonLd($);
  const errors = blocks.filter((block) => block.error).map((block) => block.error);
  const faq = blocks.flatMap((block) => block.nodes).find((node) => hasType(node, "FAQPage"));
  return { errors, items: Array.isArray(faq?.mainEntity) ? faq.mainEntity : [] };
}

function inspectPage(slug, page, config) {
  const errors = [];
  const file = fileForPage(slug, page);
  const $ = cheerio.load(fs.readFileSync(file, "utf8"), { decodeEntities: false });
  const module = $("main .answer-readiness");
  if (module.length !== 1) errors.push(`trebuie exact o secțiune answer-readiness, găsite ${module.length}`);
  const activeModule = module.first();
  const direct = activeModule.find("[data-answer-readiness-direct]");
  const directWords = words(direct.text());
  if (direct.length !== 1) errors.push(`trebuie exact un răspuns direct, găsite ${direct.length}`);
  if (directWords < 45 || directWords > 80) errors.push(`răspunsul direct are ${directWords} cuvinte; intervalul este 45–80`);
  if (direct.length && !direct.parent().children().first().is(direct)) errors.push("răspunsul direct nu este primul element editorial al secțiunii");
  if (!/(consultativ|aprobat|final|activ|orientativ|hub informativ|metoda de lucru|nu confirmă)/iu.test(cleanText(direct.text()))) {
    errors.push("răspunsul direct nu precizează statutul informației");
  }

  const h2 = activeModule.find("h2");
  if (h2.length !== 1 || cleanText(h2.text()) !== page.sectionTitle) errors.push(`H2-ul de intenție trebuie să fie „${page.sectionTitle}”`);
  if (!/^(Cine|Ce|Care|Când|Cum|Condițiile|Datele)/u.test(page.sectionTitle)) errors.push("H2-ul nu este formulat ca întrebare sau intenție explicită");

  const facts = activeModule.find("dl.answer-readiness__facts > div");
  if (facts.length !== 8) errors.push(`lista de definiții are ${facts.length} răspunsuri; sunt necesare 8`);
  const terms = facts.find("dt").map((_, element) => cleanText($(element).text())).get();
  FACT_TERMS.forEach((pattern) => {
    if (!terms.some((term) => pattern.test(term))) errors.push(`lipsește întrebarea operațională ${pattern}`);
  });
  facts.each((_, element) => {
    if (!cleanText($(element).find("dt").text()) || !cleanText($(element).find("dd").text())) errors.push("există o definiție fără întrebare sau răspuns");
  });

  const source = activeModule.find(".answer-readiness__source");
  const sourceText = cleanText(source.text());
  if (source.length !== 1) errors.push("lipsește sursa oficială apropiată de răspunsuri");
  for (const expected of [page.source.document, page.source.institution, page.source.status]) {
    if (!sourceText.includes(expected)) errors.push(`sursa apropiată nu conține „${expected}”`);
  }
  if (source.find(`a[href='${page.source.url}']`).length !== 1) errors.push("URL-ul sursei oficiale nu corespunde configurației");
  const reviewed = page.lastReviewed || config.lastReviewed || config.lastVerified;
  if (source.find(`time[datetime='${reviewed}']`).length !== 1) errors.push(`lipsește data verificării ${reviewed}`);

  if (hiddenContent($, activeModule).length) errors.push("secțiunea answer-readiness conține text ascuns");
  if (activeModule.closest("details:not([open])").length) errors.push("informația principală este într-un accordion închis implicit");
  const compactDetails = activeModule.find("details.answer-readiness__details[data-non-faq]");
  if (page.presentation === "compact-disclosure") {
    if (!activeModule.hasClass("answer-readiness--compact")) errors.push("lipsește modificatorul vizual compact");
    if (compactDetails.length !== 1) errors.push(`panoul compact are ${compactDetails.length} elemente details; este necesar unul`);
    if (compactDetails.is("[open]")) errors.push("panoul compact trebuie să fie închis implicit");
    if (!cleanText(compactDetails.children("summary").first().text())) errors.push("panoul compact nu are un rezumat accesibil");
  } else if (compactDetails.length || activeModule.hasClass("answer-readiness--compact")) {
    errors.push("prezentarea compactă apare pe o pagină fără configurarea aferentă");
  }
  const hiddenFaq = $(".faq-item").filter((_, element) => {
    const item = $(element);
    return item.is("[hidden], [aria-hidden='true']") || item.closest("[hidden], [aria-hidden='true']").length > 0 || /display\s*:\s*none|visibility\s*:\s*hidden/iu.test(item.attr("style") || "");
  });
  if (hiddenFaq.length) errors.push(`${hiddenFaq.length} întrebări FAQ sunt ascunse`);

  if ($(".priority-aeo, .audit-design-summary, #seo-plan-calculator-soc, .program-cluster").length) errors.push("pagina conține un rezumat vizual compact eliminat");
  const legacyHeading = $("main h2").filter((_, element) => /^Răspuns (?:rapid|scurt)$/iu.test(cleanText($(element).text())));
  if (legacyHeading.length) errors.push("pagina conține un titlu vechi «Răspuns rapid/scurt»");

  if (page.layout === "standalone") {
    if (!activeModule.prev().is("header.hero, section#hero")) errors.push("secțiunea nu urmează imediat după introducerea vizuală");
  } else if (!activeModule.parent().is("article.panel") || !activeModule.parent().children().first().is(activeModule)) {
    errors.push("secțiunea nu este primul conținut după introducerea paginii");
  }
  const bodyElements = $("body *");
  const h1Index = bodyElements.index($("h1").first());
  const directIndex = bodyElements.index(direct.first());
  if (h1Index === -1 || directIndex === -1 || directIndex <= h1Index) errors.push("răspunsul direct nu apare după H1");

  const visibleFaq = visibleFaqItems($);
  if (visibleFaq.length < 5 || visibleFaq.length > 8) errors.push(`FAQ-ul vizibil are ${visibleFaq.length} întrebări; intervalul este 5–8`);
  for (const item of visibleFaq) {
    if (/Cum verific dacă .+ este potrivit|Când nu merită să aplic pentru/iu.test(item.question)) errors.push(`întrebare FAQ mecanică: ${item.question}`);
  }
  const schema = faqSchemaItems($);
  for (const error of schema.errors) errors.push(`JSON-LD invalid: ${error}`);
  if (schema.items.length !== visibleFaq.length) errors.push(`FAQ vizibil/JSON-LD diferit: ${visibleFaq.length}/${schema.items.length}`);
  const visibleMap = new Map(visibleFaq.map((item) => [comparableText(item.question), comparableText(item.answer)]));
  for (const item of schema.items) {
    const question = cleanText(item.name);
    const key = comparableText(question);
    const answer = comparableText(item.acceptedAnswer?.text);
    if (!visibleMap.has(key)) errors.push(`FAQ JSON-LD fără corespondent vizibil: ${question}`);
    else if (visibleMap.get(key) !== answer) errors.push(`răspuns FAQ diferit în JSON-LD: ${question}`);
  }

  return {
    errors,
    faqCount: visibleFaq.length,
    file: path.relative(ROOT, file).split(path.sep).join("/"),
    route: page.route,
    source: page.source.document,
    status: page.source.status,
    title: page.sectionTitle,
    words: directWords
  };
}

function writeReport(results) {
  const rows = results.map((result) => `| ${result.route} | ${result.words} | ${result.faqCount} | ${result.errors.length ? "NECONFORM" : "CONFORM"} | ${result.source} |`).join("\n");
  const files = [
    "config/priority-pages.json",
    "config/seo-programs.json",
    "tools/priority-aeo.js",
    "tools/generate-internal-link-map.js",
    "scripts/verify-answer-readiness.js",
    "scripts/verify-structured-data.js",
    "package.json",
    ...results.map((result) => result.file)
  ];
  const uniqueFiles = [...new Set(files)];
  const markdown = `# Raport answer-engine readiness – 13 iulie 2026

## Obiectiv

Cele 11 pagini prioritare au fost verificate pentru răspuns direct, structură editorială naturală, delimitarea statutului documentelor, citarea sursei oficiale și paritatea FAQ vizibil/JSON-LD. Nu au fost folosite carduri compacte, blocuri „Răspuns rapid”, text ascuns sau conținut injectat exclusiv prin JavaScript.

## Rezultate pe rută

| Rută | Cuvinte în răspunsul direct | FAQ | Rezultat | Sursa oficială apropiată |
|---|---:|---:|---|---|
${rows}

## Structura aplicată

- paragraf autonom de 45–80 de cuvinte imediat după introducerea vizuală;
- un H2 formulat ca intenție și opt răspunsuri în listă de definiții;
- document, instituție, statut și data ultimei verificări lângă răspunsurile factuale;
- „Interpretarea FABER” numai unde explică o consecință practică, marcată explicit ca neoficială;
- 5–8 întrebări FAQ vizibile și identice cu datele structurate.

## Fișiere modificate

${uniqueFiles.map((file) => `- \`${file}\``).join("\n")}

## Verificări

- \`node scripts/verify-answer-readiness.js --report\`: ${results.every((result) => !result.errors.length) ? "trece" : "nu trece"};
- lungime răspuns direct: ${results.every((result) => result.words >= 45 && result.words <= 80) ? "11/11 conforme" : "există abateri"};
- statut și sursă oficială apropiată: ${results.every((result) => !result.errors.some((error) => /statut|surs/iu.test(error))) ? "11/11 conforme" : "există abateri"};
- FAQ vizibil/JSON-LD: ${results.every((result) => !result.errors.some((error) => /FAQ|JSON-LD/iu.test(error))) ? "11/11 conforme" : "există abateri"};
- text ascuns și rezumate compacte: ${results.every((result) => !result.errors.some((error) => /ascuns|compact|accordion/iu.test(error))) ? "zero probleme" : "există abateri"}.
`;
  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
  fs.writeFileSync(REPORT_PATH, markdown, "utf8");
}

function main() {
  const config = loadPriorityConfig();
  const results = Object.entries(config.pages).map(([slug, page]) => inspectPage(slug, page, config));
  if (WRITE_REPORT) writeReport(results);
  const errors = results.flatMap((result) => result.errors.map((error) => `${result.route}: ${error}`));
  for (const result of results) console.log(`${result.route}: ${result.words} cuvinte, ${result.faqCount} FAQ, ${result.errors.length ? "NECONFORM" : "conform"}`);
  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`Answer readiness verificat pentru ${results.length} pagini${WRITE_REPORT ? `; raport: ${path.relative(ROOT, REPORT_PATH)}` : ""}.`);
}

main();
