#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { buildInventory } = require("./generate-route-inventory");
const { loadProgramConfig, programForRoute } = require("./program-factual-governance");
const {
  LEGAL_ROUTES,
  faqSchemaItems,
  isGenericFillerFaq,
  routeFiles,
  temporalFaqIssues
} = require("./faq-governance");
const {
  cleanText,
  comparableText,
  graphNodes,
  hasType,
  visibleFaqItems
} = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DATE = "2026-08-24";
const JSON_REPORT = path.join(ROOT, "reports", `faq-governance-audit-${REPORT_DATE}.json`);
const MARKDOWN_REPORT = path.join(ROOT, "reports", `faq-governance-audit-${REPORT_DATE}.md`);
const PROGRAMS = loadProgramConfig().programs;

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function inspectFaqHtml(html, route, program = null) {
  const issues = [];
  const $ = cheerio.load(html, { decodeEntities: false });
  const visible = visibleFaqItems($);
  const nodes = [];
  $("script[type='application/ld+json']").each((_, script) => {
    const raw = $(script).html().trim();
    if (!raw) return;
    try {
      nodes.push(...graphNodes(JSON.parse(raw)));
    } catch (error) {
      issues.push(`JSON-LD invalid: ${error.message}`);
    }
  });
  const schemas = nodes.filter((node) => hasType(node, "FAQPage"));
  const schema = faqSchemaItems(nodes);
  const seen = new Set();

  for (const item of visible) {
    const key = comparableText(item.question);
    if (seen.has(key)) issues.push(`întrebare vizibilă duplicată: „${item.question}”`);
    seen.add(key);
    if (isGenericFillerFaq(item.question, item.answer)) issues.push(`FAQ fallback generic: „${item.question}”`);
  }

  if (visible.length >= 2 && schemas.length !== 1) {
    issues.push(`FAQ vizibil cu ${visible.length} întrebări, dar FAQPage găsite: ${schemas.length}`);
  }
  if (visible.length < 2 && schemas.length) {
    issues.push(`FAQPage publicat fără minimum două întrebări FAQ vizibile reale`);
  }
  if (schemas.length > 1) issues.push(`FAQPage duplicat: ${schemas.length}`);
  if (schemas.length === 1) {
    if (schema.length !== visible.length) issues.push(`FAQPage are ${schema.length} întrebări, HTML are ${visible.length}`);
    const length = Math.max(schema.length, visible.length);
    for (let index = 0; index < length; index += 1) {
      const schemaItem = schema[index];
      const visibleItem = visible[index];
      if (!schemaItem || !visibleItem) continue;
      if (comparableText(schemaItem.question) !== comparableText(visibleItem.question)) {
        issues.push(`întrebarea ${index + 1} diferă între FAQPage și HTML`);
      }
      if (comparableText(schemaItem.answer) !== comparableText(visibleItem.answer)) {
        issues.push(`răspunsul ${index + 1} diferă între FAQPage și HTML`);
      }
    }
  }
  if (LEGAL_ROUTES.has(route) && schemas.length) issues.push(`pagina juridică publică FAQPage fără necesitate semantică`);
  issues.push(...temporalFaqIssues(visible, program, REPORT_DATE));

  return {
    visible,
    schema,
    schemaCount: schemas.length,
    issues: [...new Set(issues)]
  };
}

function auditFaqs(root = ROOT, options = {}) {
  const inventory = buildInventory();
  const deployment = options.deployment === true;
  const results = [];
  const routesByAnswer = new Map();
  let sourceCount = 0;

  for (const routeEntry of inventory.routes) {
    const files = routeFiles(root, routeEntry, deployment).filter((file) => fs.existsSync(file));
    const routeIssues = [];
    const inspections = [];
    const program = programForRoute(routeEntry.route, PROGRAMS);
    if (!files.length) routeIssues.push("fișier public inexistent");
    for (const file of files) {
      sourceCount += 1;
      const inspected = inspectFaqHtml(fs.readFileSync(file, "utf8"), routeEntry.route, program);
      if (!inspections.length) {
        for (const item of inspected.visible) {
          const answer = comparableText(item.answer);
          if (answer.length < 50) continue;
          if (!routesByAnswer.has(answer)) routesByAnswer.set(answer, new Set());
          routesByAnswer.get(answer).add(routeEntry.route);
        }
      }
      const fileName = toPosix(path.relative(root, file));
      inspections.push({
        file: fileName,
        visibleFaqCount: inspected.visible.length,
        schemaFaqCount: inspected.schema.length,
        schemaCount: inspected.schemaCount
      });
      routeIssues.push(...inspected.issues.map((issue) => `${fileName}: ${issue}`));
    }
    const issues = [...new Set(routeIssues)];
    results.push({
      route: routeEntry.route,
      status: issues.length ? "FAIL" : "PASS",
      programId: program?.id || null,
      files: inspections,
      visibleFaqCount: inspections[0]?.visibleFaqCount || 0,
      schemaFaqCount: inspections[0]?.schemaFaqCount || 0,
      issues
    });
  }

  const repeatedAnswerGroups = [...routesByAnswer.entries()]
    .filter(([, routes]) => routes.size >= 5)
    .map(([answer, routes]) => ({ answer, routes: [...routes].sort() }));
  for (const group of repeatedAnswerGroups) {
    for (const route of group.routes) {
      const result = results.find((entry) => entry.route === route);
      if (!result) continue;
      result.issues.push(`răspuns FAQ identic pe ${group.routes.length} rute canonice`);
      result.status = "FAIL";
    }
  }
  const failed = results.filter((result) => result.status === "FAIL");
  return {
    schemaVersion: 1,
    generatedFor: "TASK-15",
    generatedAt: REPORT_DATE,
    scope: deployment
      ? "Output Cloudflare pentru toate cele 105 rute publice/indexabile"
      : "Toate sursele canonice/deploy pentru cele 105 rute din inventarul stabil",
    summary: {
      routeCount: results.length,
      sourceCount,
      pass: results.length - failed.length,
      fail: failed.length,
      routesWithVisibleFaq: results.filter((result) => result.visibleFaqCount > 0).length,
      routesWithFaqPage: results.filter((result) => result.schemaFaqCount > 0).length,
      visibleQuestionCount: results.reduce((sum, result) => sum + result.visibleFaqCount, 0),
      schemaQuestionCount: results.reduce((sum, result) => sum + result.schemaFaqCount, 0),
      legalRoutesWithFaqPage: results.filter((result) => LEGAL_ROUTES.has(result.route) && result.schemaFaqCount > 0).length,
      repeatedAnswerGroupCount: repeatedAnswerGroups.length
    },
    repeatedAnswerGroups,
    results
  };
}

function markdownReport(report) {
  const rows = report.results.map((result) => `| \`${result.route}\` | ${result.status} | ${result.visibleFaqCount} | ${result.schemaFaqCount} | ${result.files.map((file) => `\`${file.file}\``).join("<br>") || "—"} | ${result.issues.join("; ") || "—"} |`);
  return [
    "# Task 15 — FAQ vizibil, util și FAQPage fără schema spam",
    "",
    `Data auditului: ${report.generatedAt}`,
    "",
    `Rezultat: **${report.summary.fail ? "FAIL" : "PASS"}** — ${report.summary.pass}/${report.summary.routeCount} rute și ${report.summary.sourceCount} surse HTML verificate.`,
    "",
    `FAQ vizibil apare pe **${report.summary.routesWithVisibleFaq}** rute; FAQPage pe **${report.summary.routesWithFaqPage}**. Întrebări vizibile/schema: **${report.summary.visibleQuestionCount}/${report.summary.schemaQuestionCount}**. Grupuri de răspunsuri identice pe minimum cinci rute: **${report.summary.repeatedAnswerGroupCount}**.`,
    "",
    "Regula auditului: numai elementele vizibile formulate ca întrebări reale intră în FAQ; acordeoanele de surse și containerele de secțiune sunt excluse. Dacă există cel puțin două întrebări, ordinea, întrebarea și răspunsul trebuie să fie identice în HTML și FAQPage. Paginile juridice nu primesc FAQPage automat.",
    "",
    "| Rută | Rezultat | FAQ vizibil | FAQPage | Surse HTML | Probleme |",
    "|---|---:|---:|---:|---|---|",
    ...rows,
    ""
  ].join("\n");
}

function main() {
  const deployment = process.argv.includes("--dist");
  const check = process.argv.includes("--check");
  const noReport = process.argv.includes("--no-report");
  const root = deployment ? path.join(ROOT, "dist") : ROOT;
  if (deployment && !fs.existsSync(root)) throw new Error("Lipsește dist; rulează build-ul înainte de auditul FAQ din output.");
  const report = auditFaqs(root, { deployment });
  if (!noReport && !deployment) {
    fs.mkdirSync(path.dirname(JSON_REPORT), { recursive: true });
    fs.writeFileSync(JSON_REPORT, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    fs.writeFileSync(MARKDOWN_REPORT, markdownReport(report), "utf8");
  }
  const message = `FAQ governance ${report.summary.fail ? "FAIL" : "PASS"}: ${report.summary.pass}/${report.summary.routeCount} rute, ${report.summary.sourceCount} surse, ${report.summary.visibleQuestionCount}/${report.summary.schemaQuestionCount} întrebări vizibile/schema.`;
  if (report.summary.fail) {
    console.error(`${message}\n${report.results.filter((result) => result.status === "FAIL").map((result) => `- ${result.route}: ${result.issues.join("; ")}`).join("\n")}`);
    if (check) process.exitCode = 1;
    return;
  }
  console.log(message);
}

if (require.main === module) main();

module.exports = { auditFaqs, inspectFaqHtml, markdownReport };
