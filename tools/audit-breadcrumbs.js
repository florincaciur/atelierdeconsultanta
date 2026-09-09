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
const { buildInventory } = require("./generate-route-inventory");
const { fileForRoute, graphNodes, hasType } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const REPORT_DATE = "2026-08-24";

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function toPosix(value) {
  return value.split(path.sep).join("/");
}

function redirectSources(root = ROOT) {
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

function routeFiles(root, routeEntry, deployment = false) {
  const route = routeEntry.route;
  if (deployment) {
    const slug = route.replace(/^\/+|\/+$/gu, "");
    const candidates = route === "/"
      ? [path.join(root, "index.html")]
      : [path.join(root, `${slug}.html`), path.join(root, slug, "index.html")];
    const existing = candidates.filter((file) => fs.existsSync(file));
    return existing.length ? [...new Set(existing)] : [fileForRoute(root, route)];
  }
  return [...new Set([
    fileForRoute(root, route),
    path.join(root, routeEntry.sourceFile)
  ].filter(Boolean))];
}

function inspectBreadcrumbHtml(html, route, options = {}) {
  const issues = [];
  const $ = cheerio.load(html);
  const title = cleanText($("h1").first().text());
  const expected = breadcrumbRouteEntries(route, title);
  const visibleCandidates = $("nav.breadcrumb, nav[data-breadcrumb], nav[aria-label='Breadcrumb']");
  const visible = $("nav[aria-label='Breadcrumb'][data-breadcrumb]");
  const nodes = jsonLdNodes($, issues);
  const schemas = nodes.filter((node) => hasType(node, "BreadcrumbList"));
  const canonical = $("link[rel~='canonical']").first().attr("href");
  const robots = cleanText($("meta[name='robots']").attr("content")).toLowerCase();

  if (canonical !== canonicalUrl(route)) issues.push(`pagina nu este self-canonical (${canonical || "lipsește"})`);
  if (robots.includes("noindex")) issues.push("pagina este noindex");
  if (options.redirects?.has(route)) issues.push("ruta canonical este sursă de redirect");

  if (route === "/") {
    if (visibleCandidates.length) issues.push("homepage afișează breadcrumb");
    if (schemas.length) issues.push("homepage publică BreadcrumbList fără echivalent vizibil");
    return { depth: 0, expected, intermediates: [], issues: [...new Set(issues)] };
  }

  if (visibleCandidates.length !== 1) issues.push(`breadcrumb vizibil: găsite ${visibleCandidates.length}, necesar exact 1`);
  if (visible.length !== 1) issues.push(`breadcrumb semantic nav+aria-label: găsite ${visible.length}, necesar exact 1`);
  const list = visible.first().children("ol").first();
  const listItems = list.children("li");
  if (!list.length) issues.push("breadcrumb HTML fără <ol> copil direct");
  if (listItems.length !== expected.length) issues.push(`breadcrumb HTML are ${listItems.length} niveluri; registrul cere ${expected.length}`);

  const visibleEntries = [];
  listItems.each((index, element) => {
    const link = $(element).children("a");
    const current = $(element).attr("aria-current") === "page";
    const href = link.attr("href") || "";
    const entry = {
      name: cleanText($(element).text()),
      route: link.length ? normalizeRoute(href) : route,
      href,
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
    if (!entry.current && actual.href !== entry.route) issues.push(`link HTML necanonic la poziția ${index + 1}: ${actual.href || "lipsește"} vs ${entry.route}`);
    if (!entry.current && options.redirects?.has(actual.route)) issues.push(`link HTML către redirect la poziția ${index + 1}: ${actual.route}`);
  });

  if (schemas.length !== 1) issues.push(`BreadcrumbList: găsite ${schemas.length}, necesar exact 1`);
  const schemaItems = Array.isArray(schemas[0]?.itemListElement) ? schemas[0].itemListElement : [];
  if (schemaItems.length !== expected.length) issues.push(`BreadcrumbList are ${schemaItems.length} niveluri; HTML/registrul au ${expected.length}`);
  const positions = new Set();
  schemaItems.forEach((item, index) => {
    positions.add(item.position);
    if (!hasType(item, "ListItem")) issues.push(`element JSON-LD fără @type ListItem la poziția ${index + 1}`);
    if (item.position !== index + 1) issues.push(`poziție JSON-LD invalidă la nivelul ${index + 1}`);
    if (cleanText(item.name) !== expected[index]?.name) issues.push(`nume JSON-LD divergent la poziția ${index + 1}`);
    if (cleanText(item.name) !== visibleEntries[index]?.name) issues.push(`nume JSON-LD diferit de breadcrumb-ul vizibil la poziția ${index + 1}`);
    const expectedUrl = canonicalUrl(expected[index]?.route || route);
    if (item.item !== expectedUrl) issues.push(`URL JSON-LD divergent la poziția ${index + 1}: ${item.item || "lipsește"}`);
    try {
      const parsed = new URL(item.item);
      if (parsed.origin !== SITE || parsed.search || parsed.hash) issues.push(`URL JSON-LD necanonic la poziția ${index + 1}: ${item.item}`);
    } catch {
      issues.push(`URL JSON-LD invalid la poziția ${index + 1}: ${item.item || "lipsește"}`);
    }
  });
  if (positions.size !== schemaItems.length) issues.push("BreadcrumbList are poziții duplicate");
  if (!$("link[href='/assets/breadcrumbs.css']").length) issues.push("lipsește stylesheet-ul breadcrumbs");

  return {
    depth: expected.length,
    expected,
    intermediates: expected.slice(0, -1).map((entry) => entry.route),
    issues: [...new Set(issues)]
  };
}

function targetIssues(root, targetRoute, routeByPath, redirects, deployment) {
  const issues = [];
  const target = routeByPath.get(targetRoute);
  if (!target) return [`părintele ${targetRoute} lipsește din inventarul canonical`];
  if (redirects.has(targetRoute)) issues.push(`părintele ${targetRoute} este sursă de redirect`);
  const files = routeFiles(root, target, deployment).filter((file) => fs.existsSync(file));
  if (!files.length) return [...issues, `părintele ${targetRoute} nu are fișier public (404)`];
  const $ = cheerio.load(fs.readFileSync(files[0], "utf8"));
  const canonical = $("link[rel~='canonical']").first().attr("href");
  if (canonical !== canonicalUrl(targetRoute)) issues.push(`părintele ${targetRoute} nu este self-canonical (${canonical || "lipsește"})`);
  const robots = cleanText($("meta[name='robots']").attr("content")).toLowerCase();
  if (robots.includes("noindex")) issues.push(`părintele ${targetRoute} este noindex`);
  return issues;
}

function auditBreadcrumbs(root = ROOT, options = {}) {
  const inventory = buildInventory();
  const routeByPath = new Map(inventory.routes.map((entry) => [entry.route, entry]));
  const redirects = redirectSources(fs.existsSync(path.join(root, "_redirects")) ? root : ROOT);
  const deployment = options.deployment === true;
  const results = [];
  let sourceCount = 0;

  for (const routeEntry of inventory.routes) {
    const { route } = routeEntry;
    const files = routeFiles(root, routeEntry, deployment);
    const existing = files.filter((file) => fs.existsSync(file));
    const routeIssues = [];
    let depth = 0;
    let intermediates = [];

    if (!existing.length) routeIssues.push("fișier public inexistent (404)");
    for (const file of existing) {
      sourceCount += 1;
      const inspected = inspectBreadcrumbHtml(fs.readFileSync(file, "utf8"), route, { redirects });
      depth = inspected.depth;
      intermediates = inspected.intermediates;
      const fileName = toPosix(path.relative(root, file));
      routeIssues.push(...inspected.issues.map((issue) => `${fileName}: ${issue}`));
    }
    for (const targetRoute of intermediates) {
      routeIssues.push(...targetIssues(root, targetRoute, routeByPath, redirects, deployment));
    }

    const issues = [...new Set(routeIssues)];
    results.push({
      route,
      files: existing.map((file) => toPosix(path.relative(root, file))),
      status: issues.length ? "FAIL" : "PASS",
      depth,
      intermediates,
      issues
    });
  }

  const failed = results.filter((result) => result.status === "FAIL");
  return {
    schemaVersion: 2,
    generatedFor: "TASK-14",
    generatedAt: REPORT_DATE,
    scope: deployment
      ? "Toate reprezentările HTML din output-ul Cloudflare pentru cele 105 rute publice/indexabile"
      : "Toate sursele canonice/deploy pentru cele 105 rute publice/indexabile din inventarul stabil",
    summary: {
      routeCount: results.length,
      sourceCount,
      pass: results.length - failed.length,
      fail: failed.length,
      internalWithBreadcrumb: results.filter((result) => result.route !== "/").length,
      maxDepth: Math.max(...results.map((result) => result.depth), 0)
    },
    results
  };
}

function markdownReport(report) {
  const rows = report.results.map((result) => `| \`${result.route}\` | ${result.status} | ${result.depth || "—"} | ${result.intermediates.map((route) => `\`${route}\``).join(" → ") || "—"} | ${result.files.map((file) => `\`${file}\``).join("<br>") || "—"} | ${result.issues.join("; ") || "—"} |`);
  return [
    "# Task 14 — Breadcrumbs vizibile și BreadcrumbList coerent",
    "",
    `Data auditului: ${report.generatedAt}`,
    "",
    `Rezultat: **${report.summary.fail ? "FAIL" : "PASS"}** — ${report.summary.pass}/${report.summary.routeCount} URL-uri și ${report.summary.sourceCount} surse HTML verificate.`,
    "",
    "## Mapping pe tipuri",
    "",
    "| Tip | Părinte canonic | Regulă |",
    "|---|---|---|",
    "| Program | `/fonduri-europene` → hub de familie | Ruta programului vine din registrul unic; familia din `discovery.parentHub`. |",
    "| Ghid / articol / întrebare | `/resurse` | Resurse este rădăcina publică; `/ghiduri`, `/blog` și celelalte huburi rămân copii canonici. |",
    "| Serviciu | `/consultanta-fonduri-europene` | Landing-ul principal este rădăcină și este etichetat «Servicii» când apare ca părinte. |",
    "| Instrument | `/instrumente` | Instrumentele rămân sub hub-ul canonic existent. |",
    "| Despre / metodologie / cazuri | `/despre-faber` | Paginile de încredere folosesc rădăcina de brand. |",
    "| Legal / Contact | `/` | Traseu direct, fără nivel intermediar artificial. |",
    "",
    "## Validare crawl și paritate",
    "",
    "| URL | Rezultat | Niveluri | Părinți verificați | Surse HTML | Probleme |",
    "|---|---:|---:|---|---|---|",
    ...rows,
    ""
  ].join("\n");
}

function main() {
  const check = process.argv.includes("--check");
  const noReport = process.argv.includes("--no-report");
  const deployment = process.argv.includes("--dist");
  const root = deployment ? path.join(ROOT, "dist") : ROOT;
  const report = auditBreadcrumbs(root, { deployment });
  if (!noReport && !deployment) {
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
  console.log(`Breadcrumb audit PASS: ${report.summary.pass}/${report.summary.routeCount} URL-uri și ${report.summary.sourceCount} surse; HTML și JSON-LD sunt identice.`);
}

if (require.main === module) main();

module.exports = {
  auditBreadcrumbs,
  inspectBreadcrumbHtml,
  markdownReport,
  redirectSources
};
