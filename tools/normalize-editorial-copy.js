#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const cheerio = require("cheerio");
const {
  auditEditorialCopy,
  processCanonicalPages,
  processEditorialSources
} = require("./editorial-copy-governance");
const { collectSiteState } = require("./generate-sitemap");

const ROOT = path.resolve(__dirname, "..");
const REPORT_MD = path.join(ROOT, "reports", "editorial-corrections-2026-07-21.md");
const REPORT_CSV = path.join(ROOT, "reports", "editorial-corrections-2026-07-21.csv");
const REPORT_JSON = path.join(ROOT, "reports", "editorial-corrections-2026-07-21.json");

function csv(value) {
  const text = String(value ?? "");
  return /[",\r\n]/u.test(text) ? `"${text.replace(/"/gu, '""')}"` : text;
}

function md(value) {
  return String(value ?? "").replace(/\|/gu, "\\|").replace(/\r?\n/gu, " ");
}

function parseCsv(content) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < content.length; index += 1) {
    const char = content[index];
    if (quoted) {
      if (char === '"' && content[index + 1] === '"') {
        field += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        field += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field.replace(/\r$/u, ""));
      if (row.some(Boolean)) rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function previousChanges() {
  if (fs.existsSync(REPORT_JSON)) {
    return JSON.parse(fs.readFileSync(REPORT_JSON, "utf8")).changes || [];
  }
  if (!fs.existsSync(REPORT_CSV)) return [];
  return parseCsv(fs.readFileSync(REPORT_CSV, "utf8")).slice(1).map((row) => ({
    route: row[0],
    sourceFile: row[1],
    location: row[2],
    oldFragment: row[3],
    newFragment: row[4],
    reason: row[5]
  }));
}

function baselineLegacyChanges() {
  const changes = [];
  for (const entry of collectSiteState().entries) {
    const routePart = entry.route === "/" ? "index" : entry.route.replace(/^\//u, "");
    const candidates = [
      path.join(ROOT, "dist", `${routePart}.html`),
      path.join(ROOT, "dist", routePart, "index.html")
    ];
    let baseline = "";
    for (const candidate of candidates) {
      if (!fs.existsSync(candidate)) continue;
      baseline = fs.readFileSync(candidate, "utf8");
      if (baseline.includes("audit-design-summary")) break;
    }
    if (!baseline.includes("audit-design-summary")) {
      try {
        baseline = execFileSync("git", ["show", `HEAD:${entry.sourceFile.replace(/\\/gu, "/")}`], {
          cwd: ROOT,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"]
        });
      } catch {
        baseline = "";
      }
    }
    if (!baseline.includes("audit-design-summary")) continue;
    const $ = cheerio.load(baseline, { decodeEntities: false });
    $(".audit-design-summary").each((_, element) => {
      changes.push({
        route: entry.route,
        sourceFile: entry.sourceFile.replace(/\\/gu, "/"),
        location: "legacy-summary",
        oldFragment: $(element).text().replace(/\s+/gu, " ").trim().slice(0, 219),
        newFragment: "[bloc eliminat]",
        reason: "Etichetă internă și rezumat generic redundant"
      });
    });
  }
  return changes;
}

function coalesceChanges(input) {
  const changes = input.map((change) => ({ ...change }));
  let merged = true;
  while (merged) {
    merged = false;
    for (let leftIndex = 0; leftIndex < changes.length; leftIndex += 1) {
      const left = changes[leftIndex];
      const rightIndex = changes.findIndex((right, index) => index !== leftIndex
        && right.route === left.route
        && right.sourceFile === left.sourceFile
        && right.location === left.location
        && right.oldFragment === left.newFragment);
      if (rightIndex < 0) continue;
      left.newFragment = changes[rightIndex].newFragment;
      if (!left.reason.includes(changes[rightIndex].reason)) left.reason = `${left.reason}; ${changes[rightIndex].reason}`;
      changes.splice(rightIndex, 1);
      merged = true;
      break;
    }
  }
  return changes.filter((change) => change.oldFragment !== change.newFragment);
}

const sources = processEditorialSources({ write: true });
const pages = processCanonicalPages({ write: true });
const priorChanges = previousChanges();
const legacyBaseline = priorChanges.some((change) => change.location === "legacy-summary") ? [] : baselineLegacyChanges();
const cumulative = [...priorChanges, ...legacyBaseline, ...sources.changes, ...pages.changes];
const coalesced = coalesceChanges(cumulative);
const unique = new Map(coalesced.map((change) => [JSON.stringify(change), change]));
const changes = [...unique.values()].sort((left, right) =>
  `${left.route}|${left.sourceFile}|${left.location}|${left.oldFragment}`.localeCompare(`${right.route}|${right.sourceFile}|${right.location}|${right.oldFragment}`, "ro")
);

const byRoute = new Map();
for (const change of changes) byRoute.set(change.route, (byRoute.get(change.route) || 0) + 1);
const htmlFilesInJournal = new Set(changes.filter((change) => change.sourceFile.endsWith(".html")).map((change) => change.sourceFile));
const sourceFilesInJournal = new Set(changes.filter((change) => change.sourceFile.startsWith("config/")).map((change) => change.sourceFile));

const markdown = [
  "# Jurnal corectură editorială P0.13",
  "",
  `- URL-uri canonice procesate: ${pages.canonicalCount}`,
  `- Fișiere HTML documentate: ${htmlFilesInJournal.size}`,
  `- Surse editoriale/CMS documentate: ${sourceFilesInJournal.size}`,
  `- Fragmente documentate: ${changes.length}`,
  `- URL-uri cu intervenții: ${byRoute.size}`,
  "- Valorile, procentele, datele, statusurile și câmpurile de proveniență sunt protejate de normalizator.",
  "- În paginile juridice s-au eliminat doar etichete interne și s-au corectat forme lingvistice; sensul juridic nu a fost rescris.",
  "",
  "| URL | Sursă/câmp | Fragment vechi | Fragment nou | Motiv |",
  "|---|---|---|---|---|",
  ...changes.map((change) => `| ${md(change.route)} | ${md(`${change.sourceFile}:${change.location}`)} | ${md(change.oldFragment)} | ${md(change.newFragment)} | ${md(change.reason)} |`),
  ""
].join("\n");

const csvRows = [
  ["url", "source_file", "location", "old_fragment", "new_fragment", "reason"],
  ...changes.map((change) => [change.route, change.sourceFile, change.location, change.oldFragment, change.newFragment, change.reason])
];

fs.writeFileSync(REPORT_MD, markdown, "utf8");
fs.writeFileSync(REPORT_CSV, `${csvRows.map((row) => row.map(csv).join(",")).join("\n")}\n`, "utf8");
fs.writeFileSync(REPORT_JSON, `${JSON.stringify({
  generatedAt: new Date().toISOString(),
  canonicalUrlCount: pages.canonicalCount,
  changes
}, null, 2)}\n`, "utf8");

const audit = auditEditorialCopy();
if (audit.issueCount) {
  console.error(`Corectura a lăsat ${audit.issueCount} problemă(e); rulează auditul pentru detalii.`);
  process.exitCode = 1;
} else {
  console.log(`Corectură editorială aplicată: ${pages.canonicalCount} URL-uri, ${changes.length} fragmente, zero apariții rămase.`);
  console.log(path.relative(ROOT, REPORT_MD));
  console.log(path.relative(ROOT, REPORT_CSV));
}
