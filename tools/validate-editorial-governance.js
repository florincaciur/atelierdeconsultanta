#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  ROOT,
  loadEditorialGovernance,
  programContradictions,
  recordIssues,
  reviewExpired,
  reviewerMissing,
  sourceMissing
} = require("./editorial-governance");

const REPORT_PATH = path.join(ROOT, "reports", "editorial-governance-expiry.md");
const CSV_PATH = path.join(ROOT, "reports", "editorial-governance-expiry.csv");

function sameTextContent(actual, expected) {
  const normalize = (value) => String(value).replace(/\r\n?/gu, "\n");
  return normalize(actual) === normalize(expected);
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\r\n]/u.test(text) ? `"${text.replace(/"/gu, '""')}"` : text;
}

function reportData(today = new Date().toISOString().slice(0, 10)) {
  const { config, programs, records } = loadEditorialGovernance();
  const programById = new Map(programs.map((program) => [program.id, program]));
  const rows = records.map((record) => {
    const program = record.programId ? programById.get(record.programId) : null;
    const issues = recordIssues(record, program, today);
    return {
      route: record.route,
      contentType: record.contentType,
      governanceState: record.governanceState,
      programStatus: program?.status || "—",
      datePublished: record.datePublished,
      verifiedAt: record.verifiedAt,
      officialSourceUpdatedAt: record.officialSourceUpdatedAt,
      nextReviewAt: record.nextReviewAt,
      lastMeaningfulUpdate: record.lastMeaningfulUpdate,
      sourceMissing: sourceMissing(record) ? "da" : "nu",
      reviewExpired: reviewExpired(record, today) ? "da" : "nu",
      reviewerMissing: reviewerMissing(record) ? "da" : "nu",
      contradiction: programContradictions(record, program).join("; ") || "nu",
      issues: issues.join(", ") || "—"
    };
  });
  return { config, records, rows, today };
}

function markdownReport(data) {
  const expired = data.rows.filter((row) => row.reviewExpired === "da");
  const missingSources = data.rows.filter((row) => row.sourceMissing === "da");
  const missingReviewers = data.rows.filter((row) => row.reviewerMissing === "da");
  const contradictions = data.rows.filter((row) => row.contradiction !== "nu");
  const rows = data.rows.map((row) => `| \`${row.route}\` | ${row.contentType} | ${row.governanceState} | ${row.programStatus} | ${row.datePublished} | ${row.lastMeaningfulUpdate} | ${row.verifiedAt} | ${row.officialSourceUpdatedAt} | ${row.nextReviewAt} | ${row.sourceMissing} | ${row.reviewExpired} | ${row.reviewerMissing} | ${row.contradiction.replace(/\|/gu, "\\|")} |`).join("\n");
  return `# Raport de prospețime și guvernanță editorială

Data evaluării: **${data.today}**. Registru: \`config/editorial-governance.json\`.

## Rezumat

- Pagini guvernate: **${data.records.length}**
- Pagini publice cu metadate complete: **${data.records.filter((record) => record.governanceState === "public").length}**
- Verificări expirate: **${expired.length}**
- Surse lipsă/incomplete: **${missingSources.length}**
- Reviewer lipsă: **${missingReviewers.length}**
- Contradicții program–pagină: **${contradictions.length}**

O expirare produce warning intern și nu schimbă automat statusul, textul, \`verifiedAt\`, \`dateModified\` sau \`lastmod\`. \`nextReviewAt\` rămâne intern. Un apel deschis expirat este blocat până la reverificare.

## Înregistrări

| Rută | Tip | Guvernanță | Status program | Publicat | Modificat editorial | Verificat | Sursă actualizată | Reverificare internă | Sursă lipsă | Expirat | Reviewer lipsă | Contradicție |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
${rows}

## Reguli de prospețime

- Apel deschis: maximum **${data.config.policy.openCallReviewDays} zile**.
- Altă pagină de program: maximum **${data.config.policy.programReviewDays} zile**.
- Ghid sau instrument evergreen: maximum **${data.config.policy.evergreenReviewDays} zile**.
- Nicio alertă și niciun build nu rescriu automat datele editoriale.
`;
}

function csvReport(data) {
  const headers = ["route", "contentType", "governanceState", "programStatus", "datePublished", "lastMeaningfulUpdate", "verifiedAt", "officialSourceUpdatedAt", "nextReviewAt", "sourceMissing", "reviewExpired", "reviewerMissing", "contradiction", "issues"];
  return `${headers.join(",")}\n${data.rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")).join("\n")}\n`;
}

function writeOrCheck(file, content, check) {
  if (check) {
    const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
    if (!sameTextContent(current, content)) throw new Error(`Raport nesincronizat: ${path.relative(ROOT, file)}`);
    return;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
}

function main() {
  try {
    const data = reportData();
    const check = process.argv.includes("--check-report");
    writeOrCheck(REPORT_PATH, markdownReport(data), check);
    writeOrCheck(CSV_PATH, csvReport(data), check);
    const expired = data.rows.filter((row) => row.reviewExpired === "da").length;
    console.log(`Guvernanță editorială validă: ${data.records.length} pagini, ${expired} verificări expirate identificate pentru CMS.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { CSV_PATH, REPORT_PATH, csvReport, markdownReport, reportData };
