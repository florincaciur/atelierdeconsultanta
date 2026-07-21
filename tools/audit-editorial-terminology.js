#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { auditTerminology } = require("./editorial-terminology-governance");

const ROOT = path.resolve(__dirname, "..");
const audit = auditTerminology();
const report = { generatedAt: new Date().toISOString(), ...audit };
fs.writeFileSync(path.join(ROOT, "reports", "editorial-terminology-qa-2026-07-21.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
const markdown = [
  "# Raport QA terminologie și ton P0.14",
  "",
  `- URL-uri canonice verificate pentru afirmații interzise: ${audit.canonicalCount}`,
  `- Suprafețe P0.14 verificate contextual: ${audit.targetCount}`,
  `- Probleme absolute: ${audit.absoluteIssueCount}`,
  `- Probleme contextuale: ${audit.contextualIssueCount}`,
  `- Cerințe structurale lipsă: ${audit.requirementIssueCount}`,
  `- Probleme în sursele editoriale: ${audit.sourceIssueCount}`,
  `- Statusuri «apel deschis» controlate verificate: ${audit.openProgramsChecked.length}`,
  `- Rezultat: **${audit.issueCount === 0 ? "PASS" : "FAIL"}**`,
  "",
  ...(audit.issues.length ? ["| URL | Scope | Regulă | Fragment |", "|---|---|---|---|", ...audit.issues.map((item) => `| ${item.route || "—"} | ${item.scope || "—"} | ${item.rule} | ${String(item.fragment || "").replace(/\|/gu, "\\|")} |`)] : ["Nu au fost detectate promisiuni nepermise, statusuri generice sau abateri de la lexicul controlat."]),
  ""
].join("\n");
fs.writeFileSync(path.join(ROOT, "reports", "editorial-terminology-qa-2026-07-21.md"), markdown, "utf8");
if (audit.issueCount) {
  console.error(`Terminology QA FAIL: ${audit.issueCount} issue(s).`);
  for (const item of audit.issues.slice(0, 40)) console.error(` - ${item.route} [${item.rule}]: ${item.fragment}`);
  process.exitCode = 1;
} else {
  console.log(`Terminology QA PASS: ${audit.canonicalCount} canonical URLs, ${audit.targetCount} target surfaces, zero issues.`);
}

module.exports = { report };
