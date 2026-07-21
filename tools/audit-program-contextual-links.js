#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { loadProgramConfig } = require("./program-factual-governance");
const { loadConfig, resolvedLinks } = require("./sync-program-contextual-links");
const { SITE, fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const DATE = "2026-07-21";
const JSON_REPORT = path.join(ROOT, "reports", `program-contextual-links-crawl-${DATE}.json`);
const CSV_REPORT = path.join(ROOT, "reports", `program-contextual-links-crawl-${DATE}.csv`);
const MD_REPORT = path.join(ROOT, "reports", `program-contextual-links-crawl-${DATE}.md`);
const BANNED_ANCHORS = ["află mai multe", "click aici", "citește aici", "vezi pagina"];

function cleanText(value) {
  return String(value || "").replace(/\s+/gu, " ").trim();
}

function csv(value) {
  const text = String(value ?? "");
  return /[",\r\n]/u.test(text) ? `"${text.replace(/"/gu, '""')}"` : text;
}

function redirectSources() {
  const sources = new Set();
  for (const rawLine of fs.readFileSync(path.join(ROOT, "_redirects"), "utf8").split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const source = line.split(/\s+/u)[0];
    if (!source.startsWith("/") || /[*:?]/u.test(source) || source.endsWith("/") || source.endsWith(".html")) continue;
    sources.add(source);
  }
  return sources;
}

function validateTarget(href, sitemapSet, redirects) {
  const url = new URL(href, SITE);
  if (url.origin !== SITE) return { route: url.toString(), status: "EXTERNAL", issues: ["destinație externă nepermisă în matrice"] };
  const route = url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/u, "");
  const issues = [];
  if (redirects.has(route)) issues.push("destinație 3xx");
  if (!sitemapSet.has(route)) issues.push("destinație absentă din sitemap");
  const file = fileForRoute(ROOT, route);
  if (!fs.existsSync(file)) return { route, status: "404", issues: [...issues, "fișier local inexistent"] };
  const $ = cheerio.load(fs.readFileSync(file, "utf8"));
  const canonical = $("link[rel='canonical']").first().attr("href");
  if (canonical !== `${SITE}${route}`) issues.push(`canonical divergent: ${canonical || "lipsește"}`);
  if (/noindex/iu.test($("meta[name='robots']").attr("content") || "")) issues.push("destinație noindex");
  return { route, status: issues.length ? "FAIL" : "200_SELF_CANONICAL", issues };
}

function auditProgramContextualLinks() {
  const config = loadConfig();
  const programs = loadProgramConfig().programs;
  const sitemapSet = new Set(sitemapRoutes(ROOT));
  const redirects = redirectSources();
  const errors = [];
  const rows = [];
  const routeResults = [];
  const contact = cheerio.load(fs.readFileSync(fileForRoute(ROOT, "/contact"), "utf8"));

  for (const program of programs) {
    const file = fileForRoute(ROOT, program.pageUrl);
    const routeIssues = [];
    if (!fs.existsSync(file)) {
      errors.push(`${program.pageUrl}: fișier canonic inexistent`);
      continue;
    }
    const $ = cheerio.load(fs.readFileSync(file, "utf8"));
    const block = $("main [data-program-contextual-links]");
    if (block.length !== 1) routeIssues.push(`blocuri contextuale: ${block.length}, necesar 1`);
    if ($("main .related-links, main [data-contextual-next-step]").length) routeIssues.push("au rămas containere automate legacy");
    const actual = block.find(".program-contextual-links__list > li > a");
    const expected = resolvedLinks(program, config);
    if (actual.length !== 4) routeIssues.push(`linkuri în matrice: ${actual.length}, necesar 4`);
    const tracked = actual.filter("[data-analytics-event]");
    if (tracked.length !== 1 || tracked.attr("data-link-relation") !== "conversion") routeIssues.push("analytics trebuie să existe numai pe CTA-ul conversion");

    expected.forEach((link, index) => {
      const element = actual.eq(index);
      const href = element.attr("href") || "";
      const anchor = cleanText(element.find(".program-contextual-links__anchor").text());
      const explanation = cleanText(element.find(".program-contextual-links__explanation").text());
      if (href !== link.href) routeIssues.push(`poziția ${index + 1}: destinație ${href} vs ${link.href}`);
      if (anchor !== link.anchor) routeIssues.push(`poziția ${index + 1}: ancoră divergentă`);
      if (explanation !== link.explanation) routeIssues.push(`poziția ${index + 1}: explicație divergentă`);
      if (element.attr("data-link-relation") !== link.relation) routeIssues.push(`poziția ${index + 1}: relație divergentă`);
      if (BANNED_ANCHORS.some((banned) => anchor.toLocaleLowerCase("ro-RO").includes(banned))) routeIssues.push(`ancoră generică interzisă: ${anchor}`);

      const analyticsEvent = element.attr("data-analytics-event") || "";
      if (link.relation === "conversion") {
        if (analyticsEvent !== "cta_click") routeIssues.push("CTA conversion fără cta_click");
        if (element.attr("data-analytics-program-slug") !== program.slug) routeIssues.push("CTA fără program_slug corect");
        if (element.attr("data-analytics-program-family") !== program.family) routeIssues.push("CTA fără program_family corect");
        if (!contact(`select[name='program_slug'] option[value='${program.slug}']`).length) routeIssues.push("formularul Contact nu poate precompleta programul");
      } else if (analyticsEvent || Object.keys(element.attr() || {}).some((name) => name.startsWith("data-analytics-"))) {
        routeIssues.push(`linkul editorial ${link.relation} conține tracking`);
      }

      const target = validateTarget(href, sitemapSet, redirects);
      routeIssues.push(...target.issues.map((issue) => `${link.relation} ${target.route}: ${issue}`));
      const allMainLinks = $("main a[href]").toArray();
      const pageOrdinal = allMainLinks.indexOf(element.get(0)) + 1;
      rows.push({
        source_url: `${SITE}${program.pageUrl}`,
        anchor,
        destination: new URL(href, SITE).toString(),
        relation: link.relation,
        target_status: target.status,
        position: `main > program-contextual-links > item ${index + 1} (link ${pageOrdinal}/${allMainLinks.length})`,
        analytics_event: analyticsEvent || "—",
        source_state: program.publicationState
      });
    });

    const uniqueTargets = new Set(actual.toArray().map((element) => $(element).attr("href")));
    if (uniqueTargets.size !== actual.length) routeIssues.push("destinații duplicate în bloc");
    if (!$("link[href='/assets/program-contextual-links.css']").length) routeIssues.push("stylesheet lipsă");
    routeResults.push({ route: program.pageUrl, programId: program.slug, status: routeIssues.length ? "FAIL" : "PASS", issues: [...new Set(routeIssues)] });
    errors.push(...routeIssues.map((issue) => `${program.pageUrl}: ${issue}`));
  }

  const relationCounts = Object.fromEntries(["parent", "instrument", "comparison", "conversion"].map((relation) => [relation, rows.filter((row) => row.relation === relation).length]));
  return {
    schemaVersion: 1,
    generatedFor: "P1.05",
    generatedAt: DATE,
    evidence: config.evidence,
    summary: {
      programs: programs.length,
      links: rows.length,
      trackedCtas: rows.filter((row) => row.analytics_event === "cta_click").length,
      editorialLinksWithoutTracking: rows.filter((row) => row.relation !== "conversion" && row.analytics_event === "—").length,
      legacyCloudsRemaining: routeResults.filter((result) => result.issues.some((issue) => issue.includes("legacy"))).length,
      relationCounts,
      pass: routeResults.filter((result) => result.status === "PASS").length,
      fail: routeResults.filter((result) => result.status === "FAIL").length
    },
    routes: routeResults,
    rows,
    errors: [...new Set(errors)]
  };
}

function markdown(report) {
  const routeRows = report.routes.map((row) => `| \`${row.route}\` | ${row.status} | ${row.issues.join("; ") || "—"} |`);
  return [
    "# P1.05 — Matrice și crawl pentru legăturile programelor",
    "",
    `Data: ${report.generatedAt}`,
    "",
    `Rezultat: **${report.summary.fail ? "FAIL" : "PASS"}** — ${report.summary.pass}/${report.summary.programs} pagini de program conforme, ${report.summary.links} legături intenționate.`,
    "",
    "## Politica aplicată",
    "",
    `- ${report.evidence.removalPolicy}`,
    `- Dovezi GSC: \`${report.evidence.gscPages}\` și \`${report.evidence.gscQueries}\`.`,
    `- Tracking: ${report.summary.trackedCtas} CTA-uri \`cta_click\`; ${report.summary.editorialLinksWithoutTracking} linkuri editoriale fără analytics.`,
    "- Destinațiile și pozițiile exacte sunt în fișierul CSV asociat.",
    "",
    "## Rezultat pe pagină",
    "",
    "| Rută | Status | Probleme |",
    "|---|---:|---|",
    ...routeRows,
    ""
  ].join("\n");
}

function writeReports(report) {
  fs.writeFileSync(JSON_REPORT, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  const header = ["source_url", "anchor", "destination", "relation", "target_status", "position", "analytics_event", "source_state"];
  fs.writeFileSync(CSV_REPORT, [header, ...report.rows.map((row) => header.map((key) => row[key]))].map((row) => row.map(csv).join(",")).join("\n") + "\n", "utf8");
  fs.writeFileSync(MD_REPORT, markdown(report), "utf8");
}

function main() {
  const check = process.argv.includes("--check");
  const noReport = process.argv.includes("--no-report");
  const report = auditProgramContextualLinks();
  if (!noReport) writeReports(report);
  if (report.errors.length) {
    console.error(`Program contextual crawl FAIL: ${report.summary.fail}/${report.summary.programs} pagini.`);
    console.error(report.errors.slice(0, 30).map((error) => `- ${error}`).join("\n"));
    if (check) process.exit(1);
    return;
  }
  console.log(`Program contextual crawl PASS: ${report.summary.programs} programe, ${report.summary.links} linkuri, ${report.summary.trackedCtas} CTA-uri instrumentate.`);
}

if (require.main === module) main();

module.exports = { auditProgramContextualLinks, markdown, validateTarget };
