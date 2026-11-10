#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");
const cheerio = require("cheerio");
const { fileForRoute } = require("./structured-data-utils");
const { readerText, reviseHtml } = require("./editorial-review-content");
const ROOT = path.resolve(__dirname, "..");
const INPUT = "reports/audit-pagini-seo-ai-prioritizat-2026-11-09.csv";
const OUTPUT = "reports/editorial-review-2026-11-10";
const WRITE = process.argv.includes("--write");
function parseCsv(text) {
  const rows = []; let row = [], value = "", quoted = false;
  text = text.replace(/^\uFEFF/u, "");
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { if (quoted && text[i + 1] === '"') { value += '"'; i++; } else quoted = !quoted; }
    else if (c === "," && !quoted) { row.push(value); value = ""; }
    else if ((c === "\n" || c === "\r") && !quoted) {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(value); if (row.some(Boolean)) rows.push(row); row = []; value = "";
    } else value += c;
  }
  if (value || row.length) { row.push(value); rows.push(row); }
  const headers = rows.shift();
  return rows.map(cells => Object.fromEntries(headers.map((key, i) => [key, cells[i] || ""])));
}
function orderedRows() {
  const rows = parseCsv(fs.readFileSync(path.join(ROOT, INPUT), "utf8"));
  if (rows.length !== 106) throw new Error(`Expected 106 audit rows; found ${rows.length}`);
  return rows.sort((a, b) => Number(b["Scor prioritate"]) - Number(a["Scor prioritate"]) || Number(a.Ordine) - Number(b.Ordine));
}
function sourceRoute(value, fallback) {
  if (!value || typeof value !== "object") return fallback;
  if (value.pageUrl || value.route) return value.pageUrl || value.route;
  if (value.output) return `/${value.output.replace(/\/index\.html$|\.html$/u, "")}`;
  return value.slug ? `/${value.slug}` : fallback;
}
function reviseSources() {
  const files = ["blog.json", "config/seo-programs.json", "config/seo-programmatic-pages.json", "config/editorial-pages.json", "config/priority-pages.json", "config/contextual-next-steps.json", "config/seo-snippets.json", "config/editorial-clusters.json", "config/program-family-hubs.json", "config/priority-conversion-pages.json", "config/search-intent-routing.json", "config/contextual-ctas.json"];
  const changes = [];
  const protectedKey = /(?:^id$|slug|url|href|file|output|source|version|date|^type$|status|intentid|template|schema|updated|review|verified|published|icon|image|^route$|^target$|^key$|^programid$)/iu;
  for (const relative of files) {
    const absolute = path.join(ROOT, relative);
    if (!fs.existsSync(absolute)) continue;
    const input = fs.readFileSync(absolute, "utf8");
    function visit(value, key, location, route) {
      if (relative === "config/seo-programs.json" && location[0] === "programs") return value;
      if (typeof value === "string") {
        if (protectedKey.test(key) || /^(?:https?:|mailto:|tel:|\/)/iu.test(value.trim())) return value;
        let next;
        if (/<[a-z][\s\S]*>/iu.test(value)) {
          const fragment = reviseHtml(`<main><article class="panel">${value}</article></main>`, route || "", []);
          next = cheerio.load(fragment)("main > article").html();
        } else next = readerText(value);
        if (next !== value) changes.push({ route: route || null, sourceFile: relative, location: location.join("."), before: value, after: next });
        return next;
      }
      if (Array.isArray(value)) return value.map((item, i) => visit(item, key, [...location, i], route));
      if (!value || typeof value !== "object") return value;
      const owner = sourceRoute(value, route);
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, visit(v, k, [...location, k], owner)]));
    }
    const result = visit(JSON.parse(input), "", [], null);
    if (changes.some(change => change.sourceFile === relative) && WRITE) fs.writeFileSync(absolute, JSON.stringify(result, null, 2) + "\n");
  }
  return changes;
}
function main() {
  const rows = orderedRows();
  const sourceChanges = reviseSources();
  const pageChanges = [];
  for (const row of rows) {
    const route = new URL(row["URL canonic"]).pathname;
    const file = fileForRoute(ROOT, route);
    const before = fs.readFileSync(file, "utf8");
    const changes = [];
    const after = reviseHtml(before, route, changes);
    if (after !== before) {
      pageChanges.push({ order: Number(row.Ordine), priority: Number(row["Scor prioritate"]), route, file: path.relative(ROOT, file).replace(/\\/gu, "/"), changes });
      if (WRITE) fs.writeFileSync(file, after, "utf8");
    }
  }
  if (WRITE) {
    fs.mkdirSync(path.join(ROOT, OUTPUT), { recursive: true });
    const logFile = path.join(ROOT, OUTPUT, "corrections.json");
    const previous = fs.existsSync(logFile) ? JSON.parse(fs.readFileSync(logFile, "utf8")) : { pagePasses: [], sourcePasses: [] };
    if (pageChanges.length) previous.pagePasses.push(pageChanges);
    if (sourceChanges.length) previous.sourcePasses.push(sourceChanges);
    fs.writeFileSync(logFile, JSON.stringify(previous, null, 2) + "\n");
  }
  console.log(`Editorial review ${WRITE ? "applied" : "check"}: 106 rows, ${pageChanges.length} pages and ${sourceChanges.length} source fields ${WRITE ? "corrected" : "pending"}.`);
  if (!WRITE && (pageChanges.length || sourceChanges.length)) process.exitCode = 1;
}
if (require.main === module) main();
module.exports = { orderedRows, parseCsv, sourceRoute };
