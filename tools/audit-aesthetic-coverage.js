#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute, sitemapRoutes } = require("./structured-data-utils");

const ROOT = path.resolve(__dirname, "..");
const DATE = "2026-08-09";
const REPORT_JSON = path.join(ROOT, "reports", `aesthetic-coverage-audit-${DATE}.json`);
const REPORT_MD = path.join(ROOT, "reports", `aesthetic-coverage-audit-${DATE}.md`);
const WRITE = !process.argv.includes("--no-report");

const BESPOKE_SIGNALS = [
  "site-refresh-2026.css",
  "homepage-decision-flow.css",
  "program-page-template.css",
  "dr14-final.css",
  "projectare-refresh-2026.css",
  "program-showcase-2026.css",
  "calculator-so-methodology.css",
  "core-pages.css",
  "program-family-hubs.css",
  "about-faber.css"
];

const BASELINE_SIGNALS = [
  "design-system.css",
  "design-profiles.css",
  "long-form-layout.css",
  "program-heroes.css",
  "editorial-clusters.css"
];

function recommendation(route, bodyClass) {
  if (route.startsWith("/intrebari/")) return "Aplică un șablon answer-first: răspuns direct, card de dovezi, pași și întrebări conexe; elimină spațiile mari dintre blocurile scurte.";
  if (/service/.test(bodyClass)) return "Unifică hero-ul, beneficiile, etapele și CTA-ul într-o grilă de servicii cu ritm vertical și carduri egale.";
  if (/cluster|hub/.test(bodyClass)) return "Transformă lista de destinații într-un hub vizual cu filtre/carduri uniforme, stare factuală și ierarhie clară pe mobil.";
  if (/editorial|caen/.test(bodyClass)) return "Adaugă rezumat vizual, cuprins compact doar când este util, exemple în carduri și o încheiere cu pașii următori.";
  if (/legal/.test(bodyClass)) return "Păstrează sobrietatea juridică, dar îmbunătățește măsura textului, navigarea pe secțiuni și contrastul notelor.";
  return "Aplică sistemul vizual actual: container coerent, tipografie de lectură, carduri egale, spațiere responsive și CTA final clar.";
}

function audit() {
  const pages = sitemapRoutes(ROOT).map((route) => {
    const file = fileForRoute(ROOT, route);
    const html = fs.readFileSync(file, "utf8");
    const $ = cheerio.load(html, { decodeEntities: false });
    const body = $("body");
    const styles = $("link[rel='stylesheet']").map((_, element) => $(element).attr("href") || "").get();
    const bespokeSignals = BESPOKE_SIGNALS.filter((signal) => styles.some((href) => href.includes(signal)));
    const baselineSignals = BASELINE_SIGNALS.filter((signal) => styles.some((href) => href.includes(signal)));
    const isProgram = body.attr("data-analytics-page-type") === "program" && Boolean(body.attr("data-program-id"));
    const status = isProgram || bespokeSignals.length
      ? "current"
      : (baselineSignals.length ? "baseline_only" : "needs_full_refresh");
    return {
      route,
      file: path.relative(ROOT, file).replace(/\\/gu, "/"),
      bodyClass: body.attr("class") || "",
      status,
      bespokeSignals,
      baselineSignals,
      recommendation: status === "current" ? null : recommendation(route, body.attr("class") || "")
    };
  });
  return {
    generatedAt: DATE,
    method: "Clasificare reproductibilă după integrarea în sistemele vizuale comune și componentele responsive prezente în HTML.",
    summary: {
      pages: pages.length,
      current: pages.filter((page) => page.status === "current").length,
      baselineOnly: pages.filter((page) => page.status === "baseline_only").length,
      needsFullRefresh: pages.filter((page) => page.status === "needs_full_refresh").length
    },
    pages
  };
}

function markdown(report) {
  const full = report.pages.filter((page) => page.status === "needs_full_refresh");
  const baseline = report.pages.filter((page) => page.status === "baseline_only");
  const rows = (pages) => pages.map((page) => `| \`${page.route}\` | ${page.recommendation} |`).join("\n");
  return `# Audit de acoperire estetică — ${DATE}

Metodă: ${report.method}

- Pagini canonice analizate: ${report.summary.pages}
- Integrare vizuală actuală sau șablon de program unificat: ${report.summary.current}
- Au numai stratul vizual generic și necesită o trecere dedicată: ${report.summary.baselineOnly}
- Necesită refresh complet: ${report.summary.needsFullRefresh}

## Prioritatea 1 — refresh complet

| Pagină | Modificări recomandate |
| --- | --- |
${rows(full) || "| — | Nu există pagini în această categorie. |"}

## Prioritatea 2 — trecere estetică dedicată

Aceste pagini au tipografie/layout responsive de bază, dar nu o compoziție vizuală dedicată conținutului lor.

| Pagină | Modificări recomandate |
| --- | --- |
${rows(baseline) || "| — | Nu există pagini în această categorie. |"}

## Pagini acoperite

${report.pages.filter((page) => page.status === "current").map((page) => `- \`${page.route}\``).join("\n")}
`;
}

function main() {
  const report = audit();
  if (WRITE) {
    fs.writeFileSync(REPORT_JSON, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    fs.writeFileSync(REPORT_MD, markdown(report), "utf8");
  }
  console.log(`Aesthetic coverage audit: ${report.summary.pages} pagini, ${report.summary.needsFullRefresh} refresh complet, ${report.summary.baselineOnly} trecere dedicată.`);
}

if (require.main === module) main();
module.exports = { audit, markdown };
