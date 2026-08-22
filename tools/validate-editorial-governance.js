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
      verifiedAt: record.verifiedAt,
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
  const rows = data.rows.map((row) => `| \`${row.route}\` | ${row.contentType} | ${row.governanceState} | ${row.programStatus} | ${row.verifiedAt} | ${row.nextReviewAt} | ${row.lastMeaningfulUpdate} | ${row.sourceMissing} | ${row.reviewExpired} | ${row.reviewerMissing} | ${row.contradiction.replace(/\|/gu, "\\|")} |`).join("\n");
  return `# Raport de prospețime și guvernanță editorială\n\nData evaluării: **${data.today}**. Registru: \`config/editorial-governance.json\`.\n\n## Rezumat\n\n- Pagini guvernate: **${data.records.length}**\n- Pagini publice cu metadate complete: **${data.records.filter((record) => record.governanceState === "public").length}**\n- Verificări expirate: **${expired.length}**\n- Surse lipsă/incomplete: **${missingSources.length}**\n- Reviewer lipsă: **${missingReviewers.length}**\n- Contradicții program–pagină: **${contradictions.length}**\n\nO expirare produce warning intern și nu schimbă automat statusul, textul, \`verifiedAt\`, \`dateModified\` sau \`lastmod\`. Un status de program expirat nu poate fi schimbat până când reviewerul reînnoiește verificarea și \`nextReviewAt\`.\n\n## Înregistrări\n\n| Rută | Tip | Guvernanță | Status program | Verificat | Reverificare | Modificare substanțială | Sursă lipsă | Expirat | Reviewer lipsă | Contradicție |\n|---|---|---|---|---|---|---|---|---|---|---|\n${rows}\n\n## Reguli de prospețime\n\n- Apel deschis: maximum **${data.config.policy.openCallReviewDays} zile**.\n- Altă pagină de program: maximum **${data.config.policy.programReviewDays} zile**.\n- Ghid sau instrument evergreen: maximum **${data.config.policy.evergreenReviewDays} zile**.\n- Nicio alertă nu rescrie automat conținutul sau datele editoriale.\n`;
}

function csvReport(data) {
  const headers = ["route", "contentType", "governanceState", "programStatus", "verifiedAt", "nextReviewAt", "lastMeaningfulUpdate", "sourceMissing", "reviewExpired", "reviewerMissing", "contradiction", "issues"];
  return `${headers.join(",")}\n${data.rows.map((row) => headers.map((header) => csvCell(row[header])).join(",")).join("\n")}\n`;
}

function writeOrCheck(file, content, check) {
  if (check) {
    const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
    if (current !== content) throw new Error(`Raport nesincronizat: ${path.relative(ROOT, file)}`);
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
