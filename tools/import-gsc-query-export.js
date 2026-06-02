#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const ROOT = path.resolve(__dirname, "..");
const SITE = "https://atelierdeconsultanta.ro";
const REPORT_DIR = path.join(ROOT, "reports");
const DEFAULT_MIN_POSITION = 4;
const DEFAULT_MAX_POSITION = 15;

const ROUTE_HINTS = [
  ["/consultanta-fonduri-europene", ["consultanta fonduri europene", "firma consultanta fonduri", "consultant fonduri", "depunere proiect"]],
  ["/fonduri-europene", ["fonduri europene", "programe fonduri", "program fonduri", "eligibilitate programe"]],
  ["/fonduri-europene-nerambursabile-2026", ["fonduri europene nerambursabile 2026", "fonduri europene 2026", "fonduri nerambursabile 2026"]],
  ["/fonduri-europene-imm", ["fonduri europene imm", "fonduri pentru imm", "granturi imm"]],
  ["/fonduri-europene-nord-est", ["fonduri europene iasi", "fonduri europene nord est", "fonduri europene suceava", "fonduri europene bacau"]],
  ["/afir", ["afir", "fonduri fermieri", "fonduri agricultura"]],
  ["/calculator-soc", ["calculator so", "calcul so", "calculator soc", "calcul soc", "standard output"]],
  ["/dr12-afir", ["dr12", "dr 12", "tineri fermieri"]],
  ["/dr14", ["dr14", "dr 14"]],
  ["/dr14-afir-ferme-mici", ["dr14", "dr 14", "ferme mici"]],
  ["/blog-afir-fotovoltaice-ferme-2026", ["afir fotovoltaice", "fotovoltaice ferme", "autoconsum ferme"]],
  ["/pnrr", ["pnrr", "consultanta pnrr"]],
  ["/digitalizare-imm", ["digitalizare imm", "grant digitalizare", "software imm", "crm", "erp", "cloud"]],
  ["/pnrr-digitalizare-imm-cheltuieli-eligibile", ["pnrr digitalizare imm cheltuieli", "cheltuieli eligibile digitalizare"]],
  ["/fondul-de-modernizare", ["fondul de modernizare"]],
  ["/e-move", ["e-move", "statii incarcare", "mobilitate electrica"]],
  ["/consultanta-start-up-nation-2026", ["consultanta start up nation", "consultanta startup nation"]],
  ["/start-up-nation-2026", ["start up nation 2026", "startup nation 2026"]],
  ["/start-up-nation-2026-idei-afaceri", ["start up nation idei", "idei afaceri start up nation"]],
  ["/start-up-nation-2026-cheltuieli-eligibile", ["start up nation cheltuieli", "cheltuieli eligibile startup"]],
  ["/femeia-antreprenor-2026", ["femeia antreprenor 2026"]],
  ["/fonduri-europene-femei-antreprenor", ["fonduri femei antreprenor", "fonduri europene femei"]],
  ["/investitii-modernizarea-microintreprinderilor-apel-2", ["modernizarea microintreprinderilor", "microintreprinderi apel 2"]],
  ["/pro-infra", ["pro infra"]],
  ["/por-adr-nord-est", ["por adr nord est", "adr nord est"]],
  ["/acte-necesare-fonduri-europene-nerambursabile", ["acte necesare fonduri", "documente fonduri europene"]],
  ["/verificare-eligibilitate-fonduri-europene", ["verificare eligibilitate", "cum se verifica eligibilitatea"]],
  ["/eligibilitate-fonduri-europene", ["eligibilitate fonduri europene"]],
  ["/cum-alegi-programul-potrivit-fonduri-europene-2026", ["cum aleg programul", "program potrivit fonduri"]],
  ["/intrebari-frecvente", ["intrebari frecvente fonduri", "faq fonduri"]],
  ["/surse-oficiale-fonduri-europene", ["surse oficiale fonduri", "ghid oficial fonduri"]],
  ["/glosar-fonduri-europene", ["ce inseamna", "glosar fonduri"]]
];

function usage() {
  console.error(`Usage:
  node tools/import-gsc-query-export.js <gsc-export.csv|xlsx|zip> [--min-position 4] [--max-position 15] [--min-impressions 1] [--page /optional-page]

Expected columns:
  page/url (optional if --page is provided), query, clicks, impressions, ctr, position

Output:
  reports/gsc-query-priorities-YYYY-MM-DD.csv
  reports/gsc-query-priorities-YYYY-MM-DD.md
  reports/gsc-performance-priorities-YYYY-MM-DD.md when input is a Search Console ZIP`);
}

function parseArgs(argv) {
  const args = { minPosition: DEFAULT_MIN_POSITION, maxPosition: DEFAULT_MAX_POSITION, minImpressions: 1, page: "" };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === "--min-position") args.minPosition = Number(argv[++i]);
    else if (item === "--max-position") args.maxPosition = Number(argv[++i]);
    else if (item === "--min-impressions") args.minImpressions = Number(argv[++i]);
    else if (item === "--page") args.page = argv[++i] || "";
    else positional.push(item);
  }
  args.input = positional[0] || "";
  return args;
}

function stripDiacritics(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[ăâ]/gi, (match) => /[A-Z]/.test(match) ? "A" : "a")
    .replace(/[î]/gi, (match) => /[A-Z]/.test(match) ? "I" : "i")
    .replace(/[șş]/gi, (match) => /[A-Z]/.test(match) ? "S" : "s")
    .replace(/[țţ]/gi, (match) => /[A-Z]/.test(match) ? "T" : "t");
}

function compactHeader(value) {
  return stripDiacritics(value).toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function headerRole(header) {
  const key = compactHeader(header);
  if (["page", "pages", "toppages", "pagina", "url", "pageurl", "landingpage", "adresapagina"].includes(key)) return "page";
  if (["query", "queries", "topqueries", "interogare", "interogari", "keyword", "keywords", "cuvantcheie"].includes(key)) return "query";
  if (["clicks", "clicuri"].includes(key)) return "clicks";
  if (["impressions", "impresii", "afisari"].includes(key)) return "impressions";
  if (["ctr", "clickthroughrate"].includes(key)) return "ctr";
  if (["position", "averageposition", "pozitie", "pozitiemedie", "pozitiemedieurl"].includes(key)) return "position";
  return "";
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (quoted && ch === "\"" && next === "\"") {
      cell += "\"";
      i += 1;
    } else if (ch === "\"") {
      quoted = !quoted;
    } else if (!quoted && ch === ",") {
      row.push(cell);
      cell = "";
    } else if (!quoted && (ch === "\n" || ch === "\r")) {
      if (ch === "\r" && next === "\n") i += 1;
      row.push(cell);
      if (row.some((value) => String(value).trim())) rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += ch;
    }
  }
  row.push(cell);
  if (row.some((value) => String(value).trim())) rows.push(row);
  return rows;
}

function readZipTextEntries(input) {
  const buffer = fs.readFileSync(input);
  let eocd = -1;
  for (let offset = buffer.length - 22; offset >= Math.max(0, buffer.length - 66000); offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0) throw new Error("Invalid ZIP: central directory not found.");
  const totalEntries = buffer.readUInt16LE(eocd + 10);
  let cursor = buffer.readUInt32LE(eocd + 16);
  const entries = new Map();

  for (let index = 0; index < totalEntries; index += 1) {
    if (buffer.readUInt32LE(cursor) !== 0x02014b50) throw new Error("Invalid ZIP: central directory entry is corrupt.");
    const method = buffer.readUInt16LE(cursor + 10);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const fileNameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.subarray(cursor + 46, cursor + 46 + fileNameLength).toString("utf8");
    cursor += 46 + fileNameLength + extraLength + commentLength;

    if (buffer.readUInt32LE(localOffset) !== 0x04034b50) throw new Error(`Invalid ZIP: local header missing for ${name}.`);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
    let data;
    if (method === 0) data = compressed;
    else if (method === 8) data = zlib.inflateRawSync(compressed);
    else continue;
    entries.set(name.replace(/\\/g, "/"), data.toString("utf8").replace(/^\uFEFF/, ""));
  }
  return entries;
}

function rowsFromZipEntry(entries, name) {
  const exact = entries.get(name);
  const text = exact || entries.get([...entries.keys()].find((key) => key.toLowerCase() === name.toLowerCase()));
  return text ? parseCsv(text) : [];
}

async function readRows(input) {
  const ext = path.extname(input).toLowerCase();
  if (ext === ".csv" || ext === ".tsv") {
    const raw = fs.readFileSync(input, "utf8").replace(/^\uFEFF/, "");
    const rows = parseCsv(raw);
    if (ext === ".tsv") return rows.map((row) => row.length === 1 ? String(row[0]).split("\t") : row);
    return rows;
  }
  if (ext === ".xlsx" || ext === ".xlsm") {
    let ExcelJS;
    try {
      ExcelJS = require("exceljs");
    } catch {
      throw new Error("XLSX support requires the exceljs dependency. Use a CSV export or run npm install before importing XLSX.");
    }
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.readFile(input);
    const sheet = workbook.worksheets[0];
    const rows = [];
    sheet.eachRow((row) => rows.push(row.values.slice(1).map((value) => value == null ? "" : String(value))));
    return rows;
  }
  throw new Error(`Unsupported input extension: ${ext}`);
}

function parseNumber(value) {
  if (typeof value === "number") return value;
  const raw = String(value || "").trim().replace(/\s+/g, "").replace("%", "").replace(",", ".");
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : 0;
}

function cleanRoute(raw) {
  if (!raw) return "";
  let parsed;
  try {
    parsed = new URL(raw, SITE);
  } catch {
    return "";
  }
  let pathname = decodeURIComponent(parsed.pathname || "/");
  if (pathname === "/index.html") pathname = "/";
  pathname = pathname.replace(/\/index\.html$/i, "");
  pathname = pathname.replace(/\.html$/i, "");
  if (pathname !== "/") pathname = pathname.replace(/\/+$/g, "");
  return pathname || "/";
}

function redirectMap() {
  const file = path.join(ROOT, "_redirects");
  const map = new Map();
  if (!fs.existsSync(file)) return map;
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const [from, to, status = "301"] = trimmed.split(/\s+/);
    if (Number(status) >= 300 && Number(status) < 400 && from && to) {
      map.set(cleanRoute(from), cleanRoute(to));
    }
  }
  return map;
}

function canonicalRoute(raw, redirects) {
  let route = cleanRoute(raw);
  const seen = new Set();
  while (redirects.has(route) && !seen.has(route)) {
    seen.add(route);
    route = redirects.get(route);
  }
  return route;
}

function inferRoute(query) {
  const normalized = stripDiacritics(query).toLowerCase();
  let best = { route: "", score: 0, term: "" };
  for (const [route, terms] of ROUTE_HINTS) {
    for (const term of terms) {
      const cleanTerm = stripDiacritics(term).toLowerCase();
      if (normalized.includes(cleanTerm) && cleanTerm.length > best.score) {
        best = { route, score: cleanTerm.length, term };
      }
    }
  }
  return best.route ? { route: best.route, matchedBy: `query hint: ${best.term}` } : { route: "", matchedBy: "" };
}

function opportunityScore({ impressions, clicks, ctr, position }) {
  const ctrRate = ctr > 1 ? ctr / 100 : ctr;
  const positionWeight = Math.max(0, 16 - position) / 12;
  const clickGap = Math.max(0.2, 1 - Math.min(0.8, ctrRate || 0));
  return Math.round(impressions * positionWeight * clickGap * 100) / 100;
}

function actionFor(route) {
  if (/calculator-soc/.test(route)) return "Calculator SO/SOC: consolideaza intentia calcul SO, explica coeficientii si trimite catre DR12/DR14.";
  if (/dr12|dr14|afir/.test(route)) return "AFIR cluster: checklist, SO/SOC, documente agricole, link catre hub AFIR si consultanta.";
  if (/start-up-nation/.test(route)) return "Start-Up Nation: separa pagina principala de articole suport si mentine CTA de verificare.";
  if (/femeia-antreprenor/.test(route)) return "Femeia Antreprenor: separa programul 2026 de hub-ul general pentru femei antreprenor.";
  if (/digitalizare|pnrr/.test(route)) return "PNRR/digitalizare: clarifica buget, cheltuieli, indicatori si sursa oficiala.";
  if (/fonduri-europene-nord-est|por-adr/.test(route)) return "Regional: consolideaza unghiul local Nord-Est, RIS3 si documentele ADR.";
  if (/acte|eligibilitate|cum-alegi/.test(route)) return "Funnel informativ: raspuns scurt, checklist practic si link catre serviciul comercial.";
  return "Hub/serviciu: intareste intentia principala, linkurile interne si blocurile de incredere.";
}

function rowsToRecords(rows, options, redirects) {
  if (!rows.length) return [];
  const headers = rows[0].map((value) => String(value || "").trim());
  const roles = headers.map(headerRole);
  const roleIndex = (role) => roles.indexOf(role);
  const queryIndex = roleIndex("query");
  const pageIndex = roleIndex("page");
  const clicksIndex = roleIndex("clicks");
  const impressionsIndex = roleIndex("impressions");
  const ctrIndex = roleIndex("ctr");
  const positionIndex = roleIndex("position");
  if (queryIndex < 0 || impressionsIndex < 0 || positionIndex < 0) {
    throw new Error(`Missing required columns. Found headers: ${headers.join(", ")}`);
  }

  return rows.slice(1).map((row) => {
    const query = String(row[queryIndex] || "").trim();
    const page = options.page || (pageIndex >= 0 ? row[pageIndex] : "");
    const inferred = page ? { route: "", matchedBy: "" } : inferRoute(query);
    const route = page ? canonicalRoute(page, redirects) : inferred.route;
    const clicks = clicksIndex >= 0 ? parseNumber(row[clicksIndex]) : 0;
    const impressions = parseNumber(row[impressionsIndex]);
    const ctr = ctrIndex >= 0 ? parseNumber(row[ctrIndex]) : 0;
    const position = parseNumber(row[positionIndex]);
    return {
      route,
      query,
      clicks,
      impressions,
      ctr,
      position,
      matchedBy: page ? "page column" : inferred.matchedBy,
      action: actionFor(route)
    };
  }).filter((record) => (
    record.query &&
    record.route &&
    record.position >= options.minPosition &&
    record.position <= options.maxPosition &&
    record.impressions >= options.minImpressions
  )).map((record) => ({
    ...record,
    opportunity: opportunityScore(record)
  })).sort((a, b) => b.opportunity - a.opportunity || b.impressions - a.impressions);
}

function rowsToPageRecords(rows, options, redirects) {
  if (!rows.length) return [];
  const headers = rows[0].map((value) => String(value || "").trim());
  const roles = headers.map(headerRole);
  const roleIndex = (role) => roles.indexOf(role);
  const pageIndex = roleIndex("page");
  const clicksIndex = roleIndex("clicks");
  const impressionsIndex = roleIndex("impressions");
  const ctrIndex = roleIndex("ctr");
  const positionIndex = roleIndex("position");
  if (pageIndex < 0 || impressionsIndex < 0 || positionIndex < 0) {
    throw new Error(`Missing page export columns. Found headers: ${headers.join(", ")}`);
  }

  return rows.slice(1).map((row) => {
    const rawPage = String(row[pageIndex] || "").trim();
    const route = canonicalRoute(rawPage, redirects);
    const clicks = clicksIndex >= 0 ? parseNumber(row[clicksIndex]) : 0;
    const impressions = parseNumber(row[impressionsIndex]);
    const ctr = ctrIndex >= 0 ? parseNumber(row[ctrIndex]) : 0;
    const position = parseNumber(row[positionIndex]);
    return {
      route,
      rawPage,
      clicks,
      impressions,
      ctr,
      position,
      action: actionFor(route)
    };
  }).filter((record) => (
    record.route &&
    record.position >= options.minPosition &&
    record.position <= options.maxPosition &&
    record.impressions >= options.minImpressions
  )).map((record) => ({
    ...record,
    opportunity: opportunityScore(record)
  })).sort((a, b) => b.opportunity - a.opportunity || b.impressions - a.impressions);
}

function csvCell(value) {
  return JSON.stringify(String(value ?? ""));
}

function mdCell(value) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
}

function writeReports(records, input) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
  const date = new Date().toISOString().slice(0, 10);
  const csvPath = path.join(REPORT_DIR, `gsc-query-priorities-${date}.csv`);
  const mdPath = path.join(REPORT_DIR, `gsc-query-priorities-${date}.md`);
  const csvHeader = ["route", "query", "clicks", "impressions", "ctr", "position", "opportunity", "matched_by", "suggested_action"];
  const csv = [
    csvHeader.map(csvCell).join(","),
    ...records.map((record) => [
      record.route,
      record.query,
      record.clicks,
      record.impressions,
      record.ctr,
      record.position,
      record.opportunity,
      record.matchedBy,
      record.action
    ].map(csvCell).join(","))
  ].join("\n");
  fs.writeFileSync(csvPath, `${csv}\n`, "utf8");

  const grouped = new Map();
  for (const record of records) {
    if (!grouped.has(record.route)) grouped.set(record.route, []);
    grouped.get(record.route).push(record);
  }
  const groups = [...grouped.entries()].sort((a, b) => {
    const scoreA = a[1].reduce((sum, row) => sum + row.opportunity, 0);
    const scoreB = b[1].reduce((sum, row) => sum + row.opportunity, 0);
    return scoreB - scoreA;
  });

  const md = `# GSC query priorities

Generated: ${new Date().toISOString()}
Source: \`${path.relative(ROOT, path.resolve(input)).replace(/\\/g, "/")}\`
Filter: average position ${DEFAULT_MIN_POSITION}-${DEFAULT_MAX_POSITION}

## Summary

- Rows kept: ${records.length}
- Routes with opportunities: ${groups.length}
- Ranking: opportunity score favors high impressions, low CTR, and average position 4-15.

## Top routes

| Route | Queries | Impressions | Clicks | Opportunity |
| --- | ---: | ---: | ---: | ---: |
${groups.map(([route, rows]) => `| ${mdCell(route)} | ${rows.length} | ${rows.reduce((sum, row) => sum + row.impressions, 0)} | ${rows.reduce((sum, row) => sum + row.clicks, 0)} | ${Math.round(rows.reduce((sum, row) => sum + row.opportunity, 0) * 100) / 100} |`).join("\n")}

## Top queries

| Route | Query | Clicks | Impressions | CTR | Position | Opportunity | Action |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
${records.slice(0, 150).map((record) => `| ${mdCell(record.route)} | ${mdCell(record.query)} | ${record.clicks} | ${record.impressions} | ${record.ctr} | ${record.position} | ${record.opportunity} | ${mdCell(record.action)} |`).join("\n")}
`;
  fs.writeFileSync(mdPath, md, "utf8");
  console.log(`Wrote ${path.relative(ROOT, csvPath)} and ${path.relative(ROOT, mdPath)}.`);
}

function summarizeRows(rows) {
  if (!rows.length) return { clicks: 0, impressions: 0, ctr: 0, position: 0 };
  const headers = rows[0].map(headerRole);
  const clicksIndex = headers.indexOf("clicks");
  const impressionsIndex = headers.indexOf("impressions");
  const ctrIndex = headers.indexOf("ctr");
  const positionIndex = headers.indexOf("position");
  const body = rows.slice(1);
  const clicks = body.reduce((sum, row) => sum + (clicksIndex >= 0 ? parseNumber(row[clicksIndex]) : 0), 0);
  const impressions = body.reduce((sum, row) => sum + (impressionsIndex >= 0 ? parseNumber(row[impressionsIndex]) : 0), 0);
  const weightedPositionNumerator = body.reduce((sum, row) => {
    const impressionsForRow = impressionsIndex >= 0 ? parseNumber(row[impressionsIndex]) : 0;
    const positionForRow = positionIndex >= 0 ? parseNumber(row[positionIndex]) : 0;
    return sum + impressionsForRow * positionForRow;
  }, 0);
  return {
    clicks,
    impressions,
    ctr: impressions ? Math.round((clicks / impressions) * 10000) / 100 : 0,
    position: impressions ? Math.round((weightedPositionNumerator / impressions) * 100) / 100 : 0,
    ctrIndex
  };
}

function writePerformanceReports({ queryRecords, pageRecords, rowsByName, input }) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
  const date = new Date().toISOString().slice(0, 10);
  const pageCsvPath = path.join(REPORT_DIR, `gsc-page-priorities-${date}.csv`);
  const combinedPath = path.join(REPORT_DIR, `gsc-performance-priorities-${date}.md`);
  const pageCsvHeader = ["route", "raw_page", "clicks", "impressions", "ctr", "position", "opportunity", "suggested_action"];
  const pageCsv = [
    pageCsvHeader.map(csvCell).join(","),
    ...pageRecords.map((record) => [
      record.route,
      record.rawPage,
      record.clicks,
      record.impressions,
      record.ctr,
      record.position,
      record.opportunity,
      record.action
    ].map(csvCell).join(","))
  ].join("\n");
  fs.writeFileSync(pageCsvPath, `${pageCsv}\n`, "utf8");

  const filters = rowsByName.get("Filters.csv") || [];
  const devices = rowsByName.get("Devices.csv") || [];
  const countries = rowsByName.get("Countries.csv") || [];
  const chartSummary = summarizeRows(rowsByName.get("Chart.csv") || []);
  const filterLines = filters.slice(1).map((row) => `- ${row[0]}: ${row[1]}`).join("\n") || "- No filters found.";

  const md = `# GSC performance priorities

Generated: ${new Date().toISOString()}
Source: \`${path.relative(ROOT, path.resolve(input)).replace(/\\/g, "/")}\`

## Export context

${filterLines}

## Search summary

- Clicks: ${chartSummary.clicks}
- Impressions: ${chartSummary.impressions}
- CTR: ${chartSummary.ctr}%
- Average position: ${chartSummary.position}

## Highest-priority pages

| Route | Raw GSC page | Clicks | Impressions | CTR | Position | Opportunity | Action |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
${pageRecords.slice(0, 80).map((record) => `| ${mdCell(record.route)} | ${mdCell(record.rawPage)} | ${record.clicks} | ${record.impressions} | ${record.ctr} | ${record.position} | ${record.opportunity} | ${mdCell(record.action)} |`).join("\n")}

## Highest-priority queries

| Route | Query | Clicks | Impressions | CTR | Position | Opportunity | Action |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
${queryRecords.slice(0, 120).map((record) => `| ${mdCell(record.route)} | ${mdCell(record.query)} | ${record.clicks} | ${record.impressions} | ${record.ctr} | ${record.position} | ${record.opportunity} | ${mdCell(record.action)} |`).join("\n")}

## Devices

| Device | Clicks | Impressions | CTR | Position |
| --- | ---: | ---: | ---: | ---: |
${devices.slice(1).map((row) => `| ${mdCell(row[0])} | ${mdCell(row[1])} | ${mdCell(row[2])} | ${mdCell(row[3])} | ${mdCell(row[4])} |`).join("\n")}

## Countries

| Country | Clicks | Impressions | CTR | Position |
| --- | ---: | ---: | ---: | ---: |
${countries.slice(1, 16).map((row) => `| ${mdCell(row[0])} | ${mdCell(row[1])} | ${mdCell(row[2])} | ${mdCell(row[3])} | ${mdCell(row[4])} |`).join("\n")}
`;
  fs.writeFileSync(combinedPath, md, "utf8");
  console.log(`Wrote ${path.relative(ROOT, pageCsvPath)} and ${path.relative(ROOT, combinedPath)}.`);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.input) {
    usage();
    process.exitCode = 2;
    return;
  }
  const input = path.resolve(options.input);
  if (!fs.existsSync(input)) throw new Error(`Input file not found: ${input}`);
  if (path.extname(input).toLowerCase() === ".zip") {
    const entries = readZipTextEntries(input);
    const rowsByName = new Map();
    for (const name of ["Filters.csv", "Queries.csv", "Pages.csv", "Chart.csv", "Devices.csv", "Countries.csv", "Search appearance.csv"]) {
      rowsByName.set(name, rowsFromZipEntry(entries, name));
    }
    const redirects = redirectMap();
    const queryRecords = rowsToRecords(rowsByName.get("Queries.csv") || [], options, redirects);
    const pageRecords = rowsToPageRecords(rowsByName.get("Pages.csv") || [], options, redirects);
    writeReports(queryRecords, input);
    writePerformanceReports({ queryRecords, pageRecords, rowsByName, input });
    return;
  }
  const rows = await readRows(input);
  const records = rowsToRecords(rows, options, redirectMap());
  writeReports(records, input);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
