#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { auditEditorialCopy } = require("./editorial-copy-governance");

const ROOT = path.resolve(__dirname, "..");
const REPORT_MD = path.join(ROOT, "reports", "editorial-qa-2026-07-21.md");
const REPORT_JSON = path.join(ROOT, "reports", "editorial-qa-2026-07-21.json");
const audit = auditEditorialCopy();

const issues = [
  ...audit.pageIssues.map((issue) => ({ scope: "page", ...issue })),
  ...audit.sourceIssues.map((issue) => ({ scope: "source", ...issue })),
  ...audit.generatorIssues.map((issue) => ({ scope: "generator", route: "—", ...issue }))
];

const report = {
  generatedAt: new Date().toISOString(),
  canonicalUrlCount: audit.canonicalCount,
  issueCount: audit.issueCount,
  remainingForbiddenTemplateLabels: issues.filter((issue) => /etichetă internă|legacy-summary|short|generic/iu.test(`${issue.reason || ""} ${issue.type || ""} ${issue.location || ""}`)).length,
  remainingRomanianCopyIssues: issues.filter((issue) => /Diacritice|normă editorială/iu.test(issue.reason || "")).length,
  issues
};

const markdown = [
  "# Raport QA editorial P0.13",
  "",
  `- URL-uri publice și indexabile verificate: ${audit.canonicalCount}`,
  `- Apariții rămase: ${audit.issueCount}`,
  `- Etichete interne/blocuri legacy rămase: ${report.remainingForbiddenTemplateLabels}`,
  `- Forme din lista de control care necesită normalizare: ${report.remainingRomanianCopyIssues}`,
  `- Rezultat: **${audit.issueCount === 0 ? "PASS" : "FAIL"}**`,
  "",
  ...(issues.length
    ? ["| Scope | URL | Sursă | Problemă |", "|---|---|---|---|", ...issues.map((issue) => `| ${issue.scope} | ${issue.route || "—"} | ${issue.sourceFile || "—"} | ${(issue.reason || issue.type || issue.oldFragment || "problemă").replace(/\|/gu, "\\|")} |`)]
    : ["Nu au rămas etichete interne, blocuri `.audit-design-summary` sau forme detectabile de normalizatorul editorial."]),
  ""
].join("\n");

fs.writeFileSync(REPORT_MD, markdown, "utf8");
fs.writeFileSync(REPORT_JSON, `${JSON.stringify(report, null, 2)}\n`, "utf8");

if (audit.issueCount) {
  console.error(`Editorial QA FAIL: ${audit.issueCount} issue(s).`);
  for (const issue of issues.slice(0, 30)) console.error(` - ${issue.scope}: ${issue.route || issue.sourceFile}: ${issue.reason || issue.type || issue.oldFragment}`);
  process.exitCode = 1;
} else {
  console.log(`Editorial QA PASS: ${audit.canonicalCount} canonical URLs, zero forbidden labels or Romanian copy issues.`);
}

module.exports = { report };
