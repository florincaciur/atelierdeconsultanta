#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { applyTargetPages, migrateTargetSources } = require("./editorial-terminology-governance");

const ROOT = path.resolve(__dirname, "..");
const migrateSources = process.argv.includes("--migrate-sources");
const pageResult = applyTargetPages({ write: true });
const sourceResult = migrateSources ? migrateTargetSources({ write: true }) : { changes: [], changed: false };
const changes = [...sourceResult.changes.map((item) => ({ ...item, sourceFile: "config/seo-programs.json" })), ...pageResult.changes];
const reportJson = path.join(ROOT, "reports", "editorial-terminology-changes-2026-07-21.json");
let previous = [];
let previousPayload = {};
if (fs.existsSync(reportJson)) {
  try {
    previousPayload = JSON.parse(fs.readFileSync(reportJson, "utf8"));
    previous = previousPayload.changes || [];
  } catch { previous = []; }
}
const unique = new Map();
for (const item of [...previous, ...changes]) unique.set(JSON.stringify([item.route, item.sourceFile, item.location, item.before, item.after]), item);
const merged = [...unique.values()];
const sourceMigratedEver = Boolean(previousPayload.sourceMigratedEver || previousPayload.sourceMigrated || migrateSources || merged.some((item) => item.sourceFile === "config/seo-programs.json"));
const payload = { generatedAt: new Date().toISOString(), targetRoutes: pageResult.targetCount, changedFiles: pageResult.changedFiles, sourceMigrated: migrateSources, sourceMigratedEver, changes: merged };
fs.writeFileSync(reportJson, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

const escape = (value) => String(value || "").replace(/\|/gu, "\\|").replace(/\s+/gu, " ").trim();
const markdown = [
  "# Jurnal aplicare terminologie P0.14",
  "",
  `- Suprafețe țintă: ${pageResult.targetCount}`,
  `- Fișiere HTML actualizate la această rulare: ${pageResult.changedFiles.length}`,
  `- Fragmente documentate cumulativ: ${merged.length}`,
  `- Migrare surse editoriale realizată: ${sourceMigratedEver ? "da" : "nu"}`,
  "- Textele juridice nu fac parte din corpusul rescris automat.",
  "- Statusurile și câmpurile factuale din registrul programelor sunt protejate.",
  "",
  "| URL | Sursă/câmp | Înainte | După | Motiv |",
  "|---|---|---|---|---|",
  ...merged.map((item) => `| ${escape(item.route)} | ${escape(`${item.sourceFile || "—"}:${item.location || "—"}`)} | ${escape(item.before)} | ${escape(item.after)} | ${escape(item.reason)} |`),
  ""
].join("\n");
fs.writeFileSync(path.join(ROOT, "reports", "editorial-terminology-changes-2026-07-21.md"), markdown, "utf8");
const csv = ["route,source,location,before,after,reason", ...merged.map((item) => [item.route, item.sourceFile, item.location, item.before, item.after, item.reason].map((value) => `"${String(value || "").replace(/"/gu, '""').replace(/\s+/gu, " ").trim()}"`).join(","))].join("\n");
fs.writeFileSync(path.join(ROOT, "reports", "editorial-terminology-changes-2026-07-21.csv"), `${csv}\n`, "utf8");
console.log(`Terminologie P0.14 aplicată: ${pageResult.targetCount} suprafețe, ${pageResult.changedFiles.length} fișiere HTML actualizate, ${changes.length} modificări în această rulare.`);
