#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  ROOT,
  cofinancingSummaryText,
  contributionAnswerText,
  formatDateRo: formatRegistryDateRo,
  grantAnswerText,
  grantSummaryText,
  isPublicProgram,
  loadProgramConfig,
  renderProgramFactualStatus,
  statusStatement
} = require("./program-factual-governance");
const { loadEditorialGovernance } = require("./editorial-governance");
const { PROGRAM_TEMPLATE_SLOT, syncPageHtml: syncEditorialGovernance } = require("./sync-editorial-governance");
const { synchronizedHtml: syncBreadcrumbs } = require("./sync-breadcrumbs");
const { synchronize: syncProgramVisual } = require("./sync-program-visuals");
const { synchronizeFaqHtml } = require("./faq-governance");

const CONFIG_PATH = path.join(ROOT, "config", "program-page-template.json");
const GUIDES_PATH = path.join(ROOT, "official-guides.json");
const REPORT_PATH = path.join(ROOT, "reports", "program-page-template-pilot-2026-07-21.json");
const CSS_URL = "/assets/program-page-template.css?v=20260721-1";
const PROGRAM_VISUAL_CSS_URL = "/assets/program-visuals.css?v=20260818-1";
const TEMPLATE_VERSION = "p1_11";
const CHECK_ONLY = process.argv.includes("--check");
const FORBIDDEN_LOCAL_FACTS = ["status", "statusLabel", "verifiedAt", "sourceUrl", "sourceVersion", "applicationStart", "applicationEnd", "grantSummary", "cofinancingSummary"];
const SECTION_ORDER = ["eligibility", "funding", "scoreAndRisk", "documentsAndSteps", "consultantAnalysis", "sources", "questions", "cta"];

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function normalizeRoute(value) {
  const route = String(value || "/").replace(/^https?:\/\/[^/]+/i, "").split(/[?#]/)[0] || "/";
  return route === "/" ? route : route.replace(/\/$/, "");
}

function routeFile(route) {
  const slug = normalizeRoute(route).replace(/^\//, "");
  return path.join(ROOT, slug, "index.html");
}

function countWords(value) {
  return String(value || "").replace(/<[^>]*>/g, " ").trim().split(/\s+/u).filter(Boolean).length;
}

function formatDateRo(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))) return String(value || "—");
  return new Intl.DateTimeFormat("ro-RO", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(`${value}T00:00:00Z`));
}

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function loadGuides() {
  return JSON.parse(fs.readFileSync(GUIDES_PATH, "utf8"));
}

function sourceLink(key, guides, options = {}) {
  const source = guides[key];
  if (!source) throw new Error(`Sursa oficială ${key} nu există.`);
  const label = options.short ? source.institution : (source.title || source.name);
  return `<a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" data-source-key="${escapeHtml(key)}" data-analytics-event="source_document_click" data-analytics-component="program_template_source" data-analytics-cta-id="official_source">${escapeHtml(label)}</a>`;
}

function sourceNote(keys, guides, label = "Sursă") {
  return `<p class="program-template__source-note"><strong>${escapeHtml(label)}:</strong> ${keys.map((key) => sourceLink(key, guides)).join("; ")}.</p>`;
}

function renderList(items, className = "") {
  return `<ul${className ? ` class="${escapeHtml(className)}"` : ""}>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderOrderedList(items) {
  return `<ol class="program-template__steps">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol>`;
}

function renderParagraphs(items = []) {
  return items.map((item) => `<p>${escapeHtml(item)}</p>`).join("\n");
}

function sourceCell(key, guides) {
  return `<span class="program-template__inline-source">${sourceLink(key, guides, { short: true })}</span>`;
}

function renderGlance(page, program, guides) {
  const sourceKey = page.sourceKeys[0];
  const grant = grantAnswerText(program);
  const contribution = contributionAnswerText(program);
  const calendar = program.applicationStart || program.applicationEnd
    ? `${formatDateRo(program.applicationStart)} – ${formatDateRo(program.applicationEnd)}`
    : program.statusLabel;
  const rows = [
    ["Beneficiar", page.beneficiarySummary, "applicant"],
    ["Sprijin", grant, "grantSummary"],
    ["Contribuție proprie", contribution, "cofinancingSummary"],
    ["Calendar", calendar, "deadline"],
    ["Verificat la", formatRegistryDateRo(program.verifiedAt), "verifiedAt"],
    ["Document-cheie", page.keyDocumentLabel, "sourceVersion"]
  ];
  return `<section class="program-template__section program-template__glance" aria-labelledby="program-glance-title" data-program-template-section="glance">
    <h2 id="program-glance-title">La o privire</h2>
    <div class="long-form-table-region program-template__table-region" role="region" tabindex="0" aria-label="La o privire: ${escapeHtml(program.shortName)}">
      <table class="program-template__table">
        <tbody>
          ${rows.map(([label, value, field]) => `<tr data-registry-field="${escapeHtml(field)}" data-answer-field="${escapeHtml(field)}"${field === "grantSummary" ? " data-program-grant" : field === "cofinancingSummary" ? " data-program-contribution" : ""}><th scope="row">${escapeHtml(label)}</th><td>${field === "verifiedAt" ? `<time datetime="${escapeHtml(program.verifiedAt)}">${escapeHtml(value)}</time>` : escapeHtml(value)} ${sourceCell(sourceKey, guides)}</td></tr>`).join("\n")}
        </tbody>
      </table>
    </div>
  </section>`;
}

function renderToc() {
  const items = [
    ["program-eligibility", "Cine se poate încadra"],
    ["program-funding", "Ce se finanțează"],
    ["program-score-risk", "Punctaj și riscuri"],
    ["program-documents", "Documente și pași"],
    ["program-analysis", "Analiza consultantului"],
    ["program-sources", "Surse și modificări"],
    ["program-questions", "Întrebări reale"]
  ];
  return `<aside class="long-form-toc program-template__toc" data-long-form-toc data-program-template-toc aria-label="Navigare în pagina programului">
    <details>
      <summary>Cuprins</summary>
      <nav aria-label="Cuprinsul paginii">
        <ol>${items.map(([id, label], index) => `<li><a href="#${id}" data-long-form-toc-link${index === 0 ? ' aria-current="location"' : ""}>${label}</a></li>`).join("")}</ol>
      </nav>
    </details>
  </aside>`;
}

function renderEligibility(section, guides) {
  return `<section class="program-template__section" id="program-eligibility" aria-labelledby="program-eligibility-title" data-program-template-section="eligibility">
    <h2 id="program-eligibility-title">Cine se poate încadra</h2>
    <p class="program-template__section-intro">${escapeHtml(section.intro)}</p>
    ${renderParagraphs(section.paragraphs)}
    ${renderList(section.items, "program-template__checklist")}
    ${sourceNote(section.sourceKeys, guides)}
  </section>`;
}

function renderFunding(section, guides) {
  return `<section class="program-template__section" id="program-funding" aria-labelledby="program-funding-title" data-program-template-section="funding">
    <h2 id="program-funding-title">Ce se finanțează / ce nu se finanțează</h2>
    <p class="program-template__section-intro">${escapeHtml(section.intro)}</p>
    <div class="program-template__comparison">
      <div><h3>Poate fi finanțat</h3>${renderList(section.funded)}</div>
      <div><h3>Nu se finanțează sau rămâne în sarcina beneficiarului</h3>${renderList(section.notFunded)}</div>
    </div>
    ${renderParagraphs(section.paragraphs)}
    ${sourceNote(section.sourceKeys, guides)}
  </section>`;
}

function renderScoreAndRisk(section, guides) {
  return `<section class="program-template__section" id="program-score-risk" aria-labelledby="program-score-risk-title" data-program-template-section="scoreAndRisk">
    <h2 id="program-score-risk-title">Punctaj, condiții eliminatorii și riscuri</h2>
    <p class="program-template__section-intro">${escapeHtml(section.intro)}</p>
    <div class="program-template__three-column">
      <div><h3>Ce influențează punctajul</h3>${renderList(section.scoring)}</div>
      <div><h3>Condiții eliminatorii</h3>${renderList(section.eliminatory)}</div>
      <div><h3>Riscuri de controlat</h3>${renderList(section.risks)}</div>
    </div>
    ${renderParagraphs(section.paragraphs)}
    ${sourceNote(section.sourceKeys, guides)}
  </section>`;
}

function renderDocuments(section, guides) {
  return `<section class="program-template__section" id="program-documents" aria-labelledby="program-documents-title" data-program-template-section="documentsAndSteps">
    <h2 id="program-documents-title">Documente și pași</h2>
    <p class="program-template__section-intro">${escapeHtml(section.intro)}</p>
    <div class="program-template__documents-grid">
      <div><h3>Documente de pregătit</h3>${renderList(section.documents, "program-template__checklist")}</div>
      <div><h3>Ordinea de lucru</h3>${renderOrderedList(section.steps)}</div>
    </div>
    ${renderParagraphs(section.paragraphs)}
    ${sourceNote(section.sourceKeys, guides)}
  </section>`;
}

function renderAnalysis(section) {
  return `<section class="program-template__section program-template__analysis" id="program-analysis" aria-labelledby="program-analysis-title" data-program-template-section="consultantAnalysis">
    <h2 id="program-analysis-title">Analiza consultantului</h2>
    <p class="program-template__section-intro">${escapeHtml(section.intro)}</p>
    <div class="program-template__analysis-grid">
      <div><h3>Ipoteze de lucru</h3>${renderList(section.assumptions)}</div>
      <div><h3>Documente care pot schimba concluzia</h3>${renderList(section.conclusionChangingDocuments)}</div>
      <div><h3>Limitele concluziei</h3>${renderList(section.limits)}</div>
    </div>
  </section>`;
}

function renderSources(page, program, guides) {
  const sources = page.sourceKeys.map((key) => {
    const source = guides[key];
    return `<li class="program-template__source-card" data-source-key="${escapeHtml(key)}">
      <p><strong>${sourceLink(key, guides)}</strong></p>
      <dl>
        <div><dt>Instituție</dt><dd>${escapeHtml(source.institution)}</dd></div>
        <div><dt>Versiune</dt><dd>${escapeHtml(source.title || source.name)}</dd></div>
        <div><dt>Tip</dt><dd>${escapeHtml(source.documentType || "document oficial")}</dd></div>
        <div><dt>Verificat</dt><dd><time datetime="${escapeHtml(program.verifiedAt)}">${escapeHtml(formatDateRo(program.verifiedAt))}</time></dd></div>
      </dl>
    </li>`;
  }).join("");
  return `<section class="program-template__section" id="program-sources" aria-labelledby="program-sources-title" data-program-template-section="sources">
    <h2 id="program-sources-title">Surse, versiune și modificări</h2>
    <ul class="program-template__sources">${sources}</ul>
    ${PROGRAM_TEMPLATE_SLOT}
  </section>`;
}

function renderQuestions(page, guides) {
  return `<section class="program-template__section program-template__questions" id="program-questions" aria-labelledby="program-questions-title" data-program-template-section="questions">
    <h2 id="program-questions-title">Întrebări reale despre program</h2>
    <div class="program-template__faq-list">
      ${page.questions.map((item, index) => `<details class="faq-item long-form-secondary-detail"${index < 3 ? " open" : ""}>
        <summary>${escapeHtml(item.question)}</summary>
        <div class="long-form-secondary-detail__body"><p>${escapeHtml(item.answer)}</p>${sourceNote(item.sourceKeys, guides, "Răspuns bazat pe")}</div>
      </details>`).join("\n")}
    </div>
  </section>`;
}

function renderCta(page, program) {
  const query = new URLSearchParams({
    program: program.slug,
    investment: page.cta.investmentPrefill,
    source_channel: "program_page"
  }).toString();
  const target = `/contact#${query}`;
  return `<!-- P1_09_DECISION_ACTION_START -->
  <aside class="long-form-decision-action program-template__cta" id="program-cta" data-program-template-section="cta" aria-labelledby="program-cta-title">
    <h2 id="program-cta-title">${escapeHtml(page.cta.heading)}</h2>
    <p>${escapeHtml(page.cta.copy)}</p>
    <a href="${escapeHtml(target)}" data-analytics-event="cta_click" data-analytics-component="long_form_decision" data-analytics-cta-id="${escapeHtml(program.slug)}_program_template" data-analytics-target="${escapeHtml(target)}" data-analytics-program-slug="${escapeHtml(program.slug)}" data-analytics-program-family="${escapeHtml(program.family)}">${escapeHtml(page.cta.label)}</a>
  </aside>
<!-- P1_09_DECISION_ACTION_END -->`;
}

function syncTemplateStructuredData($, page, program) {
  $("script[type='application/ld+json']").each((_, node) => {
    const script = $(node);
    try {
      const value = JSON.parse(script.text());
      const nodes = Array.isArray(value?.["@graph"]) ? value["@graph"] : (Array.isArray(value) ? value : [value]);
      for (const item of nodes) {
        const types = new Set(Array.isArray(item?.["@type"]) ? item["@type"] : [item?.["@type"]]);
        if (types.has("Article") || types.has("WebPage")) {
          item.name = program.shortName;
          item.description = page.directAnswer;
          item.dateModified = program.lastMeaningfulUpdate;
          item.citation = [{
            "@type": "CreativeWork",
            name: `${program.sourceName} — ${program.sourceVersion}`,
            url: program.sourceUrl
          }];
        }
        if (types.has("Article")) item.headline = program.shortName;
      }
      script.text(JSON.stringify(value));
    } catch {
      // Validarea contractuală raportează separat orice JSON-LD invalid.
    }
  });
}

function editorialText(page) {
  const values = [];
  const walk = (value) => {
    if (typeof value === "string") values.push(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === "object") Object.values(value).forEach(walk);
  };
  walk(page);
  return values.join(" ");
}

function renderArticle(page, program, guides, wordCount) {
  const hasToc = wordCount > 1500;
  return `<!-- PROGRAM_PAGE_TEMPLATE_START -->
  <!-- ANSWER_READINESS_START -->
  <div class="program-template__answer-first" data-aeo-program-summary>
  <p class="program-template__direct-answer" data-aeo-primary-answer data-aeo-direct-answer data-answer-readiness-direct data-answer-field="status" data-information-status="${escapeHtml(statusStatement(program))}">${escapeHtml(page.directAnswer)}</p>
  ${renderGlance(page, program, guides)}
  </div>
  <!-- ANSWER_READINESS_END -->
${hasToc ? renderToc() : ""}
  <aside class="program-template__disclaimer" aria-label="Limită editorială"><strong>Important:</strong> ${escapeHtml(program.editorialDisclaimer)}</aside>
  ${renderEligibility(page.eligibility, guides)}
  ${renderFunding(page.funding, guides)}
  ${renderScoreAndRisk(page.scoreAndRisk, guides)}
  ${renderDocuments(page.documentsAndSteps, guides)}
  ${renderAnalysis(page.consultantAnalysis)}
  ${renderSources(page, program, guides)}
  ${renderQuestions(page, guides)}
  ${renderCta(page, program)}
<!-- PROGRAM_PAGE_TEMPLATE_END -->`;
}

function validateConfig(config, programs, guides, records) {
  const errors = [];
  if (config.schemaVersion !== 1 || !Array.isArray(config.pages) || !config.pages.length) errors.push("Configurația template-ului este incompletă.");
  const programBySlug = new Map(programs.map((program) => [program.slug, program]));
  const recordById = new Map(records.map((record) => [record.id, record]));
  for (const page of config.pages || []) {
    const where = page.route || page.programSlug || "program";
    for (const field of FORBIDDEN_LOCAL_FACTS) if (Object.prototype.hasOwnProperty.call(page, field)) errors.push(`${where}: câmp factual local interzis (${field}).`);
    const program = programBySlug.get(page.programSlug);
    if (!program) errors.push(`${where}: programul nu există în registrul unic.`);
    else {
      if (!isPublicProgram(program)) errors.push(`${where}: exemplul nu poate folosi un program în pending_validation.`);
      if (normalizeRoute(program.pageUrl) !== normalizeRoute(page.route)) errors.push(`${where}: ruta diferă de pageUrl din registru.`);
    }
    const directWords = countWords(page.directAnswer);
    if (directWords < 50 || directWords > 80) errors.push(`${where}: răspunsul direct are ${directWords} cuvinte; sunt necesare 50–80.`);
    const record = recordById.get(page.editorialGovernanceRecordId);
    if (!record || record.programId !== page.programSlug) errors.push(`${where}: înregistrarea de guvernanță lipsește sau indică alt program.`);
    const sourced = [page.eligibility, page.funding, page.scoreAndRisk, page.documentsAndSteps];
    for (const section of sourced) if (!section || !Array.isArray(section.sourceKeys) || !section.sourceKeys.length) errors.push(`${where}: o secțiune factuală nu are sourceKeys.`);
    for (const key of [...(page.sourceKeys || []), ...(page.questions || []).flatMap((item) => item.sourceKeys || []), ...sourced.flatMap((section) => section?.sourceKeys || [])]) {
      const source = guides[key];
      if (!source || !/^https:\/\//i.test(String(source.url || "")) || !source.institution) errors.push(`${where}: sursa ${key} nu este o sursă oficială completă.`);
    }
    if (!Array.isArray(page.questions) || !page.questions.length) errors.push(`${where}: lipsesc întrebările reale.`);
    if (/\bPe scurt\b/i.test(editorialText(page))) errors.push(`${where}: eticheta generică «Pe scurt» este interzisă.`);
  }
  if (normalizeRoute(config.pilotRoute) !== normalizeRoute(config.pages?.[0]?.route)) errors.push("pilotRoute nu corespunde exemplului configurat.");
  if (errors.length) throw new Error(errors.join("\n"));
}

function cleanLegacyInjection(source) {
  return source
    .replace(/<!-- P1_09_LONG_FORM_TOC_START -->[\s\S]*?<!-- P1_09_LONG_FORM_TOC_END -->\s*/gi, "")
    .replace(/<!-- P1_09_DECISION_ACTION_START -->[\s\S]*?<!-- P1_09_DECISION_ACTION_END -->\s*/gi, "")
    .replace(/<!-- PROGRAM_FACTUAL_STATUS_START -->[\s\S]*?<!-- PROGRAM_FACTUAL_STATUS_END -->\s*/gi, "")
    .replace(/<!-- PROGRAM_PAGE_TEMPLATE_START -->[\s\S]*?<!-- PROGRAM_PAGE_TEMPLATE_END -->\s*/gi, "");
}

function synchronizePage(source, page, program, guides, record) {
  const newline = source.includes("\r\n") ? "\r\n" : "\n";
  const clean = cleanLegacyInjection(source);
  const globalHeader = clean.match(/<!-- GLOBAL_HEADER_START -->[\s\S]*?<!-- GLOBAL_HEADER_END -->/i)?.[0] || "";
  const wordCount = countWords(editorialText(page));
  const $ = cheerio.load(clean, { decodeEntities: false });
  const hero = $(".program-hero").first();
  const article = $("main article.panel").first();
  if (!hero.length || !article.length) throw new Error(`${page.route}: lipsesc hero-ul sau articolul principal.`);

  $("body")
    .attr("data-program-template-version", TEMPLATE_VERSION)
    .attr("data-long-form-page", wordCount > 1500 ? "true" : "false")
    .attr("data-long-form-type", "program")
    .attr("data-long-form-word-count", String(wordCount));
  $("main").first().attr("data-long-form-layout", "rail").attr("data-long-form-content", "true");

  hero.find(".eyebrow").first().text(program.statusLabel).attr("data-program-status-badge", program.status);
  hero.find("h1").first().text(program.shortName);
  hero.children("p, .hero-actions, .program-factual-status").remove();
  hero.find("h1").first().after(renderProgramFactualStatus(program, { mode: "template-header" }));

  article.addClass("program-template").attr("data-program-template", TEMPLATE_VERSION).attr("data-program-slug", program.slug);
  article.html(renderArticle(page, program, guides, wordCount));
  syncTemplateStructuredData($, page, program);
  if (!$(`link[href^="/assets/program-page-template.css"]`).length) $("head").append(`<link rel="stylesheet" href="${CSS_URL}" data-program-page-template-style="${TEMPLATE_VERSION}">`);
  if (!$(`link[href^="/assets/program-visuals.css"]`).length) $("head").append(`<link rel="stylesheet" href="${PROGRAM_VISUAL_CSS_URL}">`);

  let output = $.html();
  if (globalHeader) output = output.replace(/<!-- GLOBAL_HEADER_START -->[\s\S]*?<!-- GLOBAL_HEADER_END -->/i, globalHeader);
  output = syncBreadcrumbs(output, normalizeRoute(page.route));
  output = syncEditorialGovernance(output, record);
  output = syncProgramVisual(output, normalizeRoute(page.route));
  output = synchronizeFaqHtml(output).html;
  output = output.replace(/\r?\n/gu, newline);
  return { html: output, wordCount, hasToc: wordCount > 1500 };
}

function templateOrder($) {
  return $("[data-program-template-section]").map((_, node) => $(node).attr("data-program-template-section")).get();
}

function main() {
  const config = loadConfig();
  const guides = loadGuides();
  const { programs } = loadProgramConfig();
  const { records } = loadEditorialGovernance();
  validateConfig(config, programs, guides, records);
  const programBySlug = new Map(programs.map((program) => [program.slug, program]));
  const recordById = new Map(records.map((record) => [record.id, record]));
  const outOfSync = [];
  const reportPages = [];

  for (const page of config.pages) {
    const file = routeFile(page.route);
    if (!fs.existsSync(file)) throw new Error(`${page.route}: lipsește ${path.relative(ROOT, file)}.`);
    const before = fs.readFileSync(file, "utf8");
    const result = synchronizePage(before, page, programBySlug.get(page.programSlug), guides, recordById.get(page.editorialGovernanceRecordId));
    if (result.html !== before) {
      if (CHECK_ONLY) outOfSync.push(path.relative(ROOT, file).split(path.sep).join("/"));
      else fs.writeFileSync(file, result.html, "utf8");
    }
    const $ = cheerio.load(result.html, { decodeEntities: false });
    reportPages.push({
      route: page.route,
      file: path.relative(ROOT, file).split(path.sep).join("/"),
      programSlug: page.programSlug,
      directAnswerWords: countWords(page.directAnswer),
      editorialWordCount: result.wordCount,
      tocIncluded: result.hasToc,
      sourceCount: page.sourceKeys.length,
      questionCount: page.questions.length,
      openQuestionCount: $("#program-questions details[open]").length,
      sectionOrder: templateOrder($),
      registryRef: "config/seo-programs.json#programs",
      governanceRef: `config/editorial-governance.json#${page.editorialGovernanceRecordId}`
    });
  }

  const report = {
    schemaVersion: 1,
    generatedFor: "P1.11",
    generatedAt: "2026-07-21",
    templateVersion: TEMPLATE_VERSION,
    pilotRoute: config.pilotRoute,
    pages: reportPages
  };
  const reportText = `${JSON.stringify(report, null, 2)}\n`;
  const currentReport = fs.existsSync(REPORT_PATH) ? fs.readFileSync(REPORT_PATH, "utf8") : "";
  if (currentReport !== reportText) {
    if (CHECK_ONLY) outOfSync.push(path.relative(ROOT, REPORT_PATH).split(path.sep).join("/"));
    else fs.writeFileSync(REPORT_PATH, reportText, "utf8");
  }
  if (CHECK_ONLY && outOfSync.length) throw new Error(`Template program nesincronizat: ${outOfSync.join(", ")}`);
  console.log(`Template program ${CHECK_ONLY ? "PASS" : "sincronizat"}: ${reportPages.length} exemplu, ${reportPages[0].editorialWordCount} cuvinte, ${reportPages[0].questionCount} întrebări.`);
}

if (require.main === module) main();

module.exports = {
  CONFIG_PATH,
  CSS_URL,
  FORBIDDEN_LOCAL_FACTS,
  REPORT_PATH,
  SECTION_ORDER,
  TEMPLATE_VERSION,
  countWords,
  editorialText,
  loadConfig,
  normalizeRoute,
  synchronizePage,
  syncTemplateStructuredData,
  validateConfig
};
