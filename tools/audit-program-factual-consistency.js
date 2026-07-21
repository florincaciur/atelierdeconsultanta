#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  ACTIVE_STATUSES,
  ROOT,
  daysSince,
  formatIntensity,
  formatMoneyValue,
  fundingSummary,
  isPublicProgram,
  loadProgramConfig,
  statusLabel,
  statusStatement
} = require("./program-factual-governance");
const { graphNodes, hasType } = require("./structured-data-utils");

const REPORT_MD = path.join(ROOT, "reports", "program-factual-consistency.md");
const REPORT_CSV = path.join(ROOT, "reports", "program-factual-consistency.csv");
const STRICT_FRESHNESS = process.argv.includes("--strict-freshness") || process.env.PROGRAM_FACTS_STRICT_FRESHNESS === "1";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function normalizeText(value) {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function comparable(value) {
  return normalizeText(value).toLocaleLowerCase("ro-RO");
}

function addIssue(issues, program, severity, category, surface, message, expected = "", actual = "") {
  issues.push({
    programId: program?.id || "registry",
    route: program?.route || "",
    severity,
    category,
    surface,
    expected: normalizeText(expected),
    actual: normalizeText(actual),
    message
  });
}

function compare(issues, program, category, surface, expected, actual, message) {
  if (normalizeText(expected) === normalizeText(actual)) return;
  addIssue(issues, program, "error", category, surface, message, expected, actual);
}

function programFile(program) {
  return path.join(ROOT, program.route.replace(/^\//, ""), "index.html");
}

function jsonLdNodes($, issues, program) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, element) => {
    try {
      nodes.push(...graphNodes(JSON.parse($(element).html() || "{}")));
    } catch (error) {
      addIssue(issues, program, "error", "invalid-jsonld", "json-ld", `JSON-LD invalid: ${error.message}`);
    }
  });
  return nodes;
}

function propertyMap(node) {
  return new Map((node?.additionalProperty || []).map((item) => [item.name, String(item.value ?? "")]));
}

function financialClaimTokens(value) {
  const text = String(value || "").toLocaleLowerCase("ro-RO");
  const tokens = new Set();
  const money = /((?:\d{1,3}(?:[.\s]\d{3})+|\d+)(?:,\d+)?)\s*(eur|euro|€|lei|ron)(?:\s*\/\s*(mw|proiect|beneficiar|fermă))?/giu;
  const millions = /(\d+(?:[,.]\d+)?)\s*(?:milioane?|mil\.?|m)\s*(eur|euro|€|lei|ron)/giu;
  const percent = /(\d+(?:[,.]\d+)?)\s*%/gu;
  let match;
  while ((match = money.exec(text))) {
    const amount = Number(match[1].replace(/[.\s]/g, "").replace(",", "."));
    tokens.add(`money:${amount}:${match[2] === "€" || match[2].startsWith("eur") ? "eur" : "ron"}`);
  }
  while ((match = millions.exec(text))) {
    const amount = Number(match[1].replace(",", ".")) * 1000000;
    tokens.add(`money:${amount}:${match[2] === "€" || match[2].startsWith("eur") ? "eur" : "ron"}`);
  }
  while ((match = percent.exec(text))) tokens.add(`percent:${Number(match[1].replace(",", "."))}`);
  return tokens;
}

function auditNarrativeClaims(issues, program, $) {
  const canonicalTokens = financialClaimTokens([
    formatMoneyValue(program.maximumGrant),
    formatMoneyValue(program.minimumGrant),
    formatMoneyValue(program.budget),
    formatIntensity(program.intensity),
    program.ownContribution,
    ...(program.keyConditions || [])
  ].filter(Boolean).join(" "));
  const content = $("main, header.hero").clone();
  content.find("script,style,nav,.program-factual-status").remove();
  const sentences = normalizeText(content.text()).split(/(?<=[.!?])\s+/u);
  const claimSignal = /(finanț|grant|sprijin|intensitat|contribuț|nerambursabil|plafon|maxim|până la|între)/iu;
  for (const sentence of sentences) {
    if (!claimSignal.test(sentence) || /(exemplu|orientativ|ipotetic|ediția 2024|editia 2024|regulile din 2024|regula publicata|istoric|a prevăzut|a prevazut)/iu.test(sentence)) continue;
    const tokens = financialClaimTokens(sentence);
    const unsupported = [...tokens].filter((token) => !canonicalTokens.has(token));
    if (!unsupported.length) continue;
    addIssue(
      issues,
      program,
      "error",
      unsupported.some((token) => token.startsWith("percent")) ? "percentage-mismatch" : "amount-mismatch",
      "page-content",
      "Pagina conține o valoare financiară într-un context factual care nu există în registrul canonic.",
      [...canonicalTokens].join("; "),
      `${unsupported.join("; ")} — ${sentence}`
    );
  }

  const openClaim = sentences.find((sentence) => {
    if (!/\b(?:apelul|apel)\s+(?:este\s+)?deschis\b/iu.test(sentence)) return false;
    if (/\bnu\b[^.!?]{0,120}\bapel(?:ul)?\s+(?:este\s+)?deschis\b/iu.test(sentence)) return false;
    if (/\bapel(?:ul)?\s+(?:este\s+)?deschis\b[^.!?]{0,80}\b(?:confirm|verific)/iu.test(sentence)) return false;
    return true;
  });
  if (openClaim && program.status !== "apel_deschis") {
    addIssue(issues, program, "error", "status-mismatch", "page-content", "Pagina afirmă că apelul este deschis, dar registrul nu are status=apel_deschis.", program.status, openClaim);
  }
}

function auditHeader(issues, programs, header) {
  const $ = cheerio.load(header, { decodeEntities: false }, false);
  for (const program of programs) {
    const desktop = $(`#dropdownPanel a[href="${program.route}"]`);
    const mobile = $(`#mobileMenu a[href="${program.route}"]`);
    if (!desktop.length && !mobile.length) continue;
    if (desktop.length !== 1 || mobile.length !== 1) {
      addIssue(issues, program, "error", "navigation-parity", "navbar", "Programul trebuie să apară o singură dată în meniul desktop și o singură dată în meniul mobil.", "desktop=1; mobile=1", `desktop=${desktop.length}; mobile=${mobile.length}`);
      continue;
    }
    compare(issues, program, "identity-mismatch", "navbar-desktop", program.id, desktop.attr("data-program-id"), "Navbarul desktop nu indică programul canonic.");
    compare(issues, program, "status-mismatch", "navbar-desktop", program.status, desktop.attr("data-program-status"), "Statusul din navbar diferă de registru.");
    compare(issues, program, "label-mismatch", "navbar-desktop", program.statusLabel, desktop.attr("data-status-label"), "Eticheta statusului din navbar diferă de registru.");
    compare(issues, program, "freshness-mismatch", "navbar-desktop", program.verifiedAt, desktop.attr("data-verified-at"), "Data de verificare din navbar diferă de registru.");
    compare(issues, program, "label-mismatch", "navbar-desktop", program.statusLabel, desktop.find(".d-label").text(), "Eticheta secundară din navbar diferă de registru.");
    compare(issues, program, "label-mismatch", "navbar-mobile", program.shortName, mobile.text(), "Eticheta mobilă diferă de registru.");
    const menuFinancial = financialClaimTokens(desktop.find(".d-label").text());
    if (program.status === "consultare_publica" && menuFinancial.size) {
      addIssue(issues, program, "error", "consultation-value-in-navbar", "navbar-desktop", "Navbarul nu trebuie să publice valori consultative.", "fără sume sau procente", [...menuFinancial].join("; "));
    }
  }
}

function auditProgram(issues, program, context) {
  const { pagesByRoute, guides, bannersByProgram, priorityByRoute, llms } = context;
  const pageConfig = pagesByRoute.get(program.route);
  if (pageConfig) {
    compare(issues, program, "identity-mismatch", "page-config", program.id, pageConfig.programId, "Pagina nu referă programul canonic.");
    if (Object.prototype.hasOwnProperty.call(pageConfig, "title") || Object.prototype.hasOwnProperty.call(pageConfig, "description")) addIssue(issues, program, "error", "duplicated-fact", "page-config", "Title-ul și descrierea programului se generează din registru și nu trebuie întreținute local.", "absente", "prezente");
    if (Object.prototype.hasOwnProperty.call(pageConfig, "funding")) addIssue(issues, program, "error", "duplicated-fact", "page-config", "Câmpul funding nu trebuie întreținut separat de registrul programs.", "absent", pageConfig.funding);
  }

  if (!isPublicProgram(program)) {
    const banner = bannersByProgram.get(program.slug);
    if (banner) addIssue(issues, program, "error", "pending-program-published", "banners.json", "Un program pending_validation nu poate apărea în carusel.", "absent", "present");
    const url = `https://atelierdeconsultanta.ro${program.pageUrl}`;
    const escapedUrl = url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`${escapedUrl}(?=\\s|$)`, "m").test(llms)) addIssue(issues, program, "error", "pending-program-published", "llms.txt", "Un program pending_validation nu poate avea o intrare factuală publică.", "absent", url);
    const file = programFile(program);
    if (fs.existsSync(file)) {
      const html = fs.readFileSync(file, "utf8");
      const $ = cheerio.load(html, { decodeEntities: false });
      compare(issues, program, "publication-state-mismatch", "page-html", "pending_validation", $("body").attr("data-publication-state"), "Pagina în validare nu este marcată corect.");
      if (!/noindex/iu.test($("meta[name='robots']").attr("content") || "")) addIssue(issues, program, "error", "pending-page-indexable", "page-html", "Pagina în validare trebuie scoasă temporar din indexare.", "noindex", $("meta[name='robots']").attr("content"));
      if ($(`[data-program-id='${program.slug}'][data-program-status]`).length || $("main [data-program-funding]").length) addIssue(issues, program, "error", "pending-fact-published", "page-html", "Pagina în validare publică încă status sau valori.", "absent", "present");
      const nodes = jsonLdNodes($, issues, program);
      if (nodes.some((node) => hasType(node, "DefinedTerm") && String(node["@id"] || "").endsWith("#funding-program"))) addIssue(issues, program, "error", "pending-jsonld-published", "json-ld", "Programul în validare nu poate apărea în JSON-LD.", "absent", "present");
    }
    return;
  }

  const primaryKey = program.officialGuideKeys?.[0];
  const guide = primaryKey ? guides[primaryKey] : null;
  if (!guide) addIssue(issues, program, "error", "missing-source", "official-guides.json", "Lipsește sursa oficială principală asociată programului.", primaryKey, "absent");
  else {
    compare(issues, program, "source-mismatch", "official-guides.json", program.officialSourceUrl, guide.url, "URL-ul sursei diferă de registru.");
    compare(issues, program, "source-mismatch", "official-guides.json", program.sourceDocumentName, guide.title || guide.name, "Denumirea documentului diferă de registru.");
    compare(issues, program, "authority-mismatch", "official-guides.json", program.authority, guide.institution, "Autoritatea diferă de registru.");
    compare(issues, program, "status-mismatch", "official-guides.json", program.status, guide.programStatus, "Statusul sursei diferă de registru.");
    compare(issues, program, "label-mismatch", "official-guides.json", program.statusLabel, guide.statusLabel, "Eticheta statusului diferă de registru.");
    compare(issues, program, "freshness-mismatch", "official-guides.json", program.verifiedAt, guide.verifiedAt || guide.accessedAt, "Data verificării sursei diferă de registru.");
  }

  const banner = bannersByProgram.get(program.id);
  if (banner) {
    compare(issues, program, "status-mismatch", "banners.json", program.status, banner.programStatus, "Statusul bannerului diferă de registru.");
    compare(issues, program, "label-mismatch", "banners.json", program.statusLabel, banner.statusLabel, "Eticheta bannerului diferă de registru.");
    compare(issues, program, "amount-mismatch", "banners.json", fundingSummary(program) || null, banner.fundingSummary, "Rezumatul financiar al bannerului diferă de registru.");
    compare(issues, program, "meta-mismatch", "banners.json", program.metaDescription, banner.description, "Descrierea factuală a bannerului diferă de config.");
    compare(issues, program, "source-mismatch", "banners.json", program.sourceUrl, banner.sourceUrl, "Sursa bannerului diferă de registru.");
  }

  const priority = priorityByRoute.get(program.route);
  if (priority) {
    compare(issues, program, "identity-mismatch", "config/priority-pages.json", program.id, priority.programId, "Pagina prioritară nu indică programul canonic.");
    compare(issues, program, "source-mismatch", "config/priority-pages.json", program.officialSourceUrl, priority.source?.url, "Sursa din priority-pages diferă de config.");
    compare(issues, program, "freshness-mismatch", "config/priority-pages.json", program.reviewedAt, priority.lastReviewed, "Data din priority-pages diferă de config.");
  }

  const url = `https://atelierdeconsultanta.ro${program.route}`;
  const llmsIndex = llms.indexOf(url);
  if (llmsIndex === -1) addIssue(issues, program, "error", "missing-llms-entry", "llms.txt", "Programul lipsește din llms.txt.", url, "absent");
  else {
    const lines = llms.split(/\r?\n/);
    const lineIndex = lines.findIndex((line) => line.includes(url));
    const llmsFragment = [lines[lineIndex], /^\s{2}\S/.test(lines[lineIndex + 1] || "") ? lines[lineIndex + 1] : ""].filter(Boolean).join("\n");
    if (!comparable(llmsFragment).includes(comparable(program.statusLabel))) addIssue(issues, program, "error", "status-mismatch", "llms.txt", "Statusul programului lipsește sau diferă în llms.txt.", program.statusLabel, llmsFragment);
  }

  if (ACTIVE_STATUSES.has(program.status) && daysSince(program.verifiedAt) > 30) {
    addIssue(issues, program, STRICT_FRESHNESS ? "error" : "warning", "stale-active-program", "freshness", "reviewedAt este mai vechi de 30 de zile pentru un apel activ.", "maximum 30 zile", `${daysSince(program.reviewedAt)} zile`);
  }
  if (program.status === "apel_deschis" && (!program.applicationStart || !program.applicationEnd)) {
    addIssue(issues, program, "error", "open-without-period", "config", "Un program open trebuie să aibă perioadă confirmată.", "applicationStart și applicationEnd", "incomplet");
  }

  const file = programFile(program);
  if (!fs.existsSync(file)) {
    addIssue(issues, program, "error", "missing-page", "html", "Lipsește pagina canonică a programului.", file, "absent");
    return;
  }
  const html = fs.readFileSync(file, "utf8");
  const $ = cheerio.load(html, { decodeEntities: false });
  compare(issues, program, "identity-mismatch", "page-html", program.id, $("body").attr("data-program-id"), "Pagina HTML nu indică programul canonic.");
  compare(issues, program, "status-mismatch", "page-html", program.status, $("body").attr("data-program-status"), "Statusul paginii HTML diferă de registru.");
  compare(issues, program, "label-mismatch", "page-html", program.statusLabel, $("body").attr("data-status-label"), "Eticheta paginii HTML diferă de registru.");
  compare(issues, program, "freshness-mismatch", "page-html", program.verifiedAt, $("body").attr("data-verified-at"), "Data paginii HTML diferă de registru.");
  compare(issues, program, "meta-mismatch", "page-html", program.metaTitle, $("head > title").first().text(), "Title-ul HTML diferă de config.");
  compare(issues, program, "meta-mismatch", "page-html", program.metaDescription, $("meta[name='description']").attr("content"), "Meta-description HTML diferă de config.");
  const note = $(".program-factual-status").first();
  if (!note.length) addIssue(issues, program, "error", "missing-factual-status", "page-html", "Lipsește nota factuală vizibilă sincronizată.");
  else {
    compare(issues, program, "identity-mismatch", "page-status", program.id, note.attr("data-program-id"), "Nota factuală indică alt program.");
    compare(issues, program, "status-mismatch", "page-status", program.status, note.attr("data-program-status"), "Nota factuală are alt status.");
    compare(issues, program, "label-mismatch", "page-status", program.statusLabel, note.attr("data-status-label"), "Nota factuală are altă etichetă de status.");
    compare(issues, program, "source-mismatch", "page-status", program.officialSourceUrl, note.find("a[data-analytics-event='source_document_click']").attr("href"), "Sursa vizibilă diferă de config.");
    const noteText = normalizeText(note.text());
    for (const required of [statusStatement(program), fundingSummary(program), program.editorialDisclaimer].filter(Boolean)) {
      if (!noteText.includes(required)) addIssue(issues, program, "error", "factual-note-mismatch", "page-status", "Nota factuală nu reproduce informația canonică.", required, noteText);
    }
    if (program.status === "consultare_publica" && !comparable(noteText).includes("consult")) {
      addIssue(issues, program, "error", "missing-consultation-disclaimer", "page-status", "Programul consultativ nu este delimitat explicit în conținut.");
    }
    if (program.status === "apel_inchis" && note.find("a[href^='/']").length === 0) {
      addIssue(issues, program, "error", "closed-without-alternative", "page-status", "Un apel închis trebuie să trimită către un program actual relevant.");
    }
  }

  const nodes = jsonLdNodes($, issues, program);
  const programNode = nodes.find((node) => hasType(node, "DefinedTerm") && node["@id"] === `https://atelierdeconsultanta.ro${program.route}#funding-program`);
  if (!programNode) addIssue(issues, program, "error", "missing-program-jsonld", "json-ld", "Lipsește entitatea factuală DefinedTerm a programului.");
  else {
    compare(issues, program, "identity-mismatch", "json-ld", program.officialName, programNode.name, "Numele programului din JSON-LD diferă de config.");
    compare(issues, program, "source-mismatch", "json-ld", program.officialSourceUrl, programNode.sameAs, "Sursa programului din JSON-LD diferă de config.");
    const properties = propertyMap(programNode);
    compare(issues, program, "status-mismatch", "json-ld", program.status, properties.get("status"), "Statusul JSON-LD diferă de registru.");
    compare(issues, program, "label-mismatch", "json-ld", program.statusLabel, properties.get("statusLabel"), "Eticheta JSON-LD diferă de registru.");
    compare(issues, program, "freshness-mismatch", "json-ld", program.verifiedAt, properties.get("verifiedAt"), "Data JSON-LD diferă de registru.");
  }
  auditNarrativeClaims(issues, program, $);
}

function csvCell(value) {
  return `"${String(value ?? "").replace(/"/g, '""')}"`;
}

function writeReports(programs, issues) {
  fs.mkdirSync(path.dirname(REPORT_MD), { recursive: true });
  const today = new Date().toISOString().slice(0, 10);
  const errors = issues.filter((issue) => issue.severity === "error").length;
  const warnings = issues.filter((issue) => issue.severity === "warning").length;
  const statusCounts = Object.fromEntries([...new Set(programs.map((program) => program.status))].sort().map((status) => [status, programs.filter((program) => program.status === status).length]));
  const rows = issues.length
    ? issues.map((issue) => `| ${issue.severity} | ${issue.route || "—"} | ${issue.category} | ${issue.surface} | ${issue.message.replace(/\|/g, "\\|")} |`).join("\n")
    : "| — | — | — | — | Nu au fost identificate inconsistențe. |";
  const statusRows = programs.map((program) => `| ${program.shortName} | ${program.status} | ${program.verifiedAt} | ${program.applicationStart || "—"} | ${program.applicationEnd || "—"} |`).join("\n");
  const markdown = `# Audit de consistență factuală a programelor\n\nData auditului: ${today}\n\n## Rezultat\n\n- Programe în registrul canonic: ${programs.length}\n- Erori: ${errors}\n- Avertismente: ${warnings}\n- Statusuri: ${Object.entries(statusCounts).map(([status, count]) => `${status}=${count}`).join(", ")}\n- Mod strict pentru freshness: ${STRICT_FRESHNESS ? "activ" : "inactiv"}\n\nAuditul este local și determinist. Nu interoghează URL-urile oficiale, nu deduce statusul din răspunsuri HTTP și nu rescrie date factuale. Registrul aprobat din \`config/seo-programs.json#programs\` rămâne singura sursă de adevăr.\n\n## Freshness și status\n\n| Program | Status | Verificat | Început | Sfârșit |\n|---|---|---:|---:|---:|\n${statusRows}\n\n## Verificări efectuate\n\n- identitate, sursă, \`status\`, \`statusLabel\`, \`verifiedAt\`, grant și cofinanțare între registru, meniu, homepage, carduri, pagină și JSON-LD;\n- paritatea desktop/mobil și interdicția valorilor locale în navbar;\n- existența perioadei pentru \`status=apel_deschis\`;\n- freshness de maximum 30 de zile pentru \`apel_deschis\`;\n- afirmații de tip „apel deschis” și valori financiare nesusținute în conținutul paginii;\n- excluderea înregistrărilor \`pending_validation\` din suprafețele publice.\n\n## Constatări\n\n| Severitate | Rută | Categorie | Suprafață | Detaliu |\n|---|---|---|---|---|\n${rows}\n\n## Workflow recomandat\n\n1. Datele factuale se actualizează manual numai în \`config/seo-programs.json#programs\`, după verificarea documentului oficial.\n2. Se rulează \`npm run validate:program-registry\` și \`npm run sync:program-facts\`.\n3. Se rulează \`npm run test:program-registry\` și \`npm run audit:program-facts\`.\n4. Un URL indisponibil generează un caz de verificare separat; nu schimbă automat statusul și nu rescrie pagina.\n`;
  fs.writeFileSync(REPORT_MD, markdown, "utf8");

  const headers = ["slug", "pageUrl", "auditResult", "status", "statusLabel", "publicationState", "verifiedAt", "applicationStart", "applicationEnd", "sourceUrl", "grantSummary", "cofinancingSummary", "errorCount", "warningCount", "issueCategories"];
  const csvRows = programs.map((program) => {
    const programIssues = issues.filter((issue) => issue.programId === program.id);
    const errorCount = programIssues.filter((issue) => issue.severity === "error").length;
    const warningCount = programIssues.filter((issue) => issue.severity === "warning").length;
    return {
      slug: program.slug,
      pageUrl: program.pageUrl,
      auditResult: errorCount ? "FAIL" : warningCount ? "WARN" : "PASS",
      status: program.status,
      statusLabel: program.statusLabel,
      publicationState: program.publicationState,
      verifiedAt: program.verifiedAt,
      applicationStart: program.applicationStart || "",
      applicationEnd: program.applicationEnd || "",
      sourceUrl: program.sourceUrl,
      grantSummary: JSON.stringify(program.grantSummary),
      cofinancingSummary: JSON.stringify(program.cofinancingSummary),
      errorCount,
      warningCount,
      issueCategories: [...new Set(programIssues.map((issue) => issue.category))].join("; ")
    };
  });
  const csv = [headers.map(csvCell).join(","), ...csvRows.map((row) => headers.map((header) => csvCell(row[header])).join(","))].join("\n");
  fs.writeFileSync(REPORT_CSV, `${csv}\n`, "utf8");
  return { errors, warnings };
}

function main() {
  let loaded;
  try {
    loaded = loadProgramConfig();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
    return;
  }
  const { config, programs } = loaded;
  const guides = readJson(path.join(ROOT, "official-guides.json"));
  const banners = readJson(path.join(ROOT, "banners.json"));
  const priority = readJson(path.join(ROOT, "config", "priority-pages.json"));
  const header = fs.readFileSync(path.join(ROOT, "partials", "global-header.html"), "utf8");
  const llms = fs.readFileSync(path.join(ROOT, "llms.txt"), "utf8");
  const context = {
    pagesByRoute: new Map((config.pages || []).filter((page) => !page.redirectTo).map((page) => [`/${page.slug}`, page])),
    guides,
    bannersByProgram: new Map(banners.filter((banner) => banner.programId).map((banner) => [banner.programId, banner])),
    priorityByRoute: new Map(Object.values(priority.pages || {}).map((page) => [page.route, page])),
    llms
  };
  const issues = [];
  auditHeader(issues, programs, header);
  for (const program of programs) auditProgram(issues, program, context);
  const result = writeReports(programs, issues);
  console.log(`Audit factual: ${programs.length} programe, ${result.errors} erori, ${result.warnings} avertismente.`);
  console.log(path.relative(ROOT, REPORT_MD));
  console.log(path.relative(ROOT, REPORT_CSV));
  if (result.errors) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { auditHeader, auditNarrativeClaims, auditProgram, financialClaimTokens, writeReports };
