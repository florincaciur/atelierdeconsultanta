#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const {
  SITE,
  breadcrumbRouteEntries,
  canonicalUrl,
  normalizeRoute
} = require("./breadcrumb-registry");
const {
  fileForRoute,
  graphNodes,
  hasType,
  sitemapRoutes
} = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DATE = "2026-07-21";

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function redirectSources(root) {
  const file = path.join(root, "_redirects");
  if (!fs.existsSync(file)) return new Set();
  const sources = new Set();
  for (const rawLine of fs.readFileSync(file, "utf8").split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const source = line.split(/\s+/u)[0];
    if (!source.startsWith("/") || /[*:?]/u.test(source)) continue;
    const pathname = source.split(/[?#]/u)[0];
    const normalized = normalizeRoute(pathname);
    if (pathname === normalized || (pathname === "/" && normalized === "/")) sources.add(normalized);
  }
  return sources;
}

function jsonLdNodes($, issues) {
  const nodes = [];
  $("script[type='application/ld+json']").each((_, script) => {
    try {
      nodes.push(...graphNodes(JSON.parse($(script).html().trim())));
    } catch (error) {
      issues.push(`JSON-LD invalid: ${error.message}`);
    }
  });
  return nodes;
}

function targetIssues(root, targetRoute, sitemapSet, redirects) {
  const issues = [];
  if (!sitemapSet.has(targetRoute)) issues.push(`părintele ${targetRoute} lipsește din sitemap`);
  if (redirects.has(targetRoute)) issues.push(`părintele ${targetRoute} este sursă de redirect`);
  const file = fileForRoute(root, targetRoute);
  if (!fs.existsSync(file)) return [...issues, `părintele ${targetRoute} nu are fișier local (404)`];
  const $ = cheerio.load(fs.readFileSync(file, "utf8"));
  const canonical = $("link[rel='canonical']").first().attr("href");
  if (canonical !== canonicalUrl(targetRoute)) issues.push(`părintele ${targetRoute} nu este self-canonical (${canonical || "lipsește"})`);
  const robots = cleanText($("meta[name='robots']").attr("content")).toLowerCase();
  if (robots.includes("noindex")) issues.push(`părintele ${targetRoute} este noindex`);
  return issues;
}

function auditBreadcrumbs(root = ROOT) {
  const routes = sitemapRoutes(root);
  const sitemapSet = new Set(routes);
  const redirects = redirectSources(root);
  const results = [];

  for (const route of routes) {
    const issues = [];
    const file = fileForRoute(root, route);
    if (!fs.existsSync(file)) {
      results.push({ route, file: path.relative(root, file), status: "FAIL", depth: 0, intermediates: [], issues: ["fișier local inexistent (404)"] });
      continue;
    }
    const html = fs.readFileSync(file, "utf8");
    const $ = cheerio.load(html);
    const title = cleanText($("h1").first().text());
    const expected = breadcrumbRouteEntries(route, title);
    const visible = $("nav[aria-label='Breadcrumb'][data-breadcrumb]");
    const nodes = jsonLdNodes($, issues);
    const schemas = nodes.filter((node) => hasType(node, "BreadcrumbList"));

    if (route === "/") {
      if (visible.length) issues.push("homepage afișează breadcrumb");
      if (schemas.length) issues.push("homepage publică BreadcrumbList fără echivalent vizibil");
      results.push({ route, file: path.relative(root, file).replace(/\\/gu, "/"), status: issues.length ? "FAIL" : "PASS", depth: 0, intermediates: [], issues });
      continue;
    }

    if (visible.length !== 1) issues.push(`breadcrumb HTML: găsite ${visible.length}, necesar exact 1`);
    const list = visible.first().find("ol").first();
    const listItems = list.children("li");
    if (!list.length) issues.push("breadcrumb HTML fără <ol>");
    if (listItems.length !== expected.length) issues.push(`breadcrumb HTML are ${listItems.length} niveluri; registrul cere ${expected.length}`);

    const visibleEntries = [];
    listItems.each((index, element) => {
      const link = $(element).children("a");
      const current = $(element).attr("aria-current") === "page";
      const entry = {
        name: cleanText($(element).text()),
        route: link.length ? normalizeRoute(link.attr("href")) : route,
        current
      };
      visibleEntries.push(entry);
      if (index === listItems.length - 1) {
        if (!current) issues.push("ultimul element HTML nu are aria-current=page");
        if (link.length) issues.push("ultimul element HTML este link către sine");
      } else {
        if (current) issues.push(`aria-current apare înainte de ultimul nivel (${index + 1})`);
        if (link.length !== 1) issues.push(`nivelul intermediar ${index + 1} nu are exact un link`);
      }
    });

    expected.forEach((entry, index) => {
      const actual = visibleEntries[index];
      if (!actual) return;
      if (actual.name !== entry.name) issues.push(`nume HTML divergent la poziția ${index + 1}: „${actual.name}” vs „${entry.name}”`);
      if (actual.route !== entry.route) issues.push(`destinație HTML divergentă la poziția ${index + 1}: ${actual.route} vs ${entry.route}`);
    });

    if (schemas.length !== 1) issues.push(`BreadcrumbList: găsite ${schemas.length}, necesar exact 1`);
    const schemaItems = schemas[0]?.itemListElement || [];
    if (schemaItems.length !== expected.length) issues.push(`BreadcrumbList are ${schemaItems.length} niveluri; HTML/registrul au ${expected.length}`);
    const positions = new Set();
    schemaItems.forEach((item, index) => {
      positions.add(item.position);
      if (item.position !== index + 1) issues.push(`poziție JSON-LD invalidă la nivelul ${index + 1}`);
      if (cleanText(item.name) !== expected[index]?.name) issues.push(`nume JSON-LD divergent la poziția ${index + 1}`);
      if (item.item !== canonicalUrl(expected[index]?.route || route)) issues.push(`URL JSON-LD divergent la poziția ${index + 1}: ${item.item}`);
    });
    if (positions.size !== schemaItems.length) issues.push("BreadcrumbList are poziții duplicate");

    const intermediates = expected.slice(0, -1).map((entry) => entry.route);
    for (const targetRoute of intermediates) issues.push(...targetIssues(root, targetRoute, sitemapSet, redirects));
    if (!$("link[href='/assets/breadcrumbs.css']").length) issues.push("lipsește stylesheet-ul breadcrumbs");

    results.push({
      route,
      file: path.relative(root, file).replace(/\\/gu, "/"),
      status: issues.length ? "FAIL" : "PASS",
      depth: expected.length,
      intermediates,
      issues: [...new Set(issues)]
    });
  }

  const failed = results.filter((result) => result.status === "FAIL");
  return {
    schemaVersion: 1,
    generatedFor: "P1.04",
    generatedAt: REPORT_DATE,
    scope: "URL-uri canonice/indexabile din sitemap.xml",
    summary: {
      routeCount: results.length,
      pass: results.length - failed.length,
      fail: failed.length,
      internalWithBreadcrumb: results.filter((result) => result.route !== "/").length,
      maxDepth: Math.max(...results.map((result) => result.depth), 0)
    },
    results
  };
}

function markdownReport(report) {
  const rows = report.results.map((result) => `| \`${result.route}\` | ${result.status} | ${result.depth || "—"} | ${result.intermediates.map((route) => `\`${route}\``).join(" → ") || "—"} | ${result.issues.join("; ") || "—"} |`);
  return [
    "# P1.04 — Breadcrumbs standardizate și schema sincronizată",
    "",
    `Data auditului: ${report.generatedAt}`,
    "",
    `Rezultat: **${report.summary.fail ? "FAIL" : "PASS"}** — ${report.summary.pass}/${report.summary.routeCount} URL-uri conforme.`,
    "",
    "## Mapping pe tipuri",
    "",
    "| Tip | Părinte canonic | Regulă |",
    "|---|---|---|",
    "| Program | `/fonduri-europene` → hub de familie | Ruta programului vine din registrul unic; familia din `discovery.parentHub`. |",
    "| Ghid / întrebare | `/ghiduri` | Ghidul răspunde complet, apoi oferă următorul pas. |",
    "| Serviciu | `/consultanta-fonduri-europene` | Landing-ul principal este rădăcină; nu se inventează o rută `/servicii`. |",
    "| Instrument | `/instrumente` | Instrumentele rămân sub hub-ul canonic existent. |",
    "| Despre / metodologie | `/despre-faber` | Paginile de încredere folosesc rădăcina de brand. |",
    "| Legal / Contact | `/` | Traseu direct, fără nivel intermediar artificial. |",
    "",
    "## Validare crawl și paritate",
    "",
    "| URL | Rezultat | Niveluri | Părinți verificați | Probleme |",
    "|---|---:|---:|---|---|",
    ...rows,
    ""
  ].join("\n");
}

function main() {
  const check = process.argv.includes("--check");
  const noReport = process.argv.includes("--no-report");
  const report = auditBreadcrumbs(ROOT);
  if (!noReport) {
    fs.writeFileSync(path.join(ROOT, "reports", `breadcrumbs-validation-${REPORT_DATE}.json`), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    fs.writeFileSync(path.join(ROOT, "reports", `breadcrumbs-validation-${REPORT_DATE}.md`), markdownReport(report), "utf8");
  }
  if (report.summary.fail) {
    console.error(`Breadcrumb audit FAIL: ${report.summary.fail}/${report.summary.routeCount} URL-uri neconforme.`);
    for (const result of report.results.filter((item) => item.status === "FAIL").slice(0, 20)) {
      console.error(`- ${result.route}: ${result.issues.join("; ")}`);
    }
    if (check) process.exit(1);
    return;
  }
  console.log(`Breadcrumb audit PASS: ${report.summary.pass}/${report.summary.routeCount} URL-uri; HTML și JSON-LD sunt identice.`);
}

if (require.main === module) main();

module.exports = { auditBreadcrumbs, markdownReport };
