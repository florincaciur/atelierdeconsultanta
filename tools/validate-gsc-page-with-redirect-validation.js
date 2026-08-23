#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const REPORTS_DIR = path.join(ROOT, "reports");

function latestValidationPath() {
  const files = fs.readdirSync(REPORTS_DIR)
    .filter((file) => /^gsc-page-with-redirect-validation-\d{4}-\d{2}-\d{2}\.json$/u.test(file))
    .sort();
  if (!files.length) throw new Error("Lipseste snapshot-ul de validare GSC Page with redirect.");
  return path.join(REPORTS_DIR, files.at(-1));
}

function validExample(row) {
  if (!row || typeof row !== "object") return false;
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(String(row.lastCrawled || ""))) return false;
  try {
    const url = new URL(row.url);
    return ["http:", "https:"].includes(url.protocol) && url.hostname === "atelierdeconsultanta.ro";
  } catch {
    return false;
  }
}

function main() {
  const errors = [];
  const validationPath = latestValidationPath();
  const snapshot = JSON.parse(fs.readFileSync(validationPath, "utf8"));

  if (snapshot.property !== "sc-domain:atelierdeconsultanta.ro") errors.push("Proprietatea GSC este incorecta.");
  if (path.basename(validationPath) !== `gsc-page-with-redirect-validation-${snapshot.capturedAt}.json`) {
    errors.push("Data capturii nu corespunde numelui fisierului.");
  }
  if (snapshot.issue !== "Page with redirect") errors.push("Categoria GSC este incorecta.");
  if (snapshot.validationStatus !== "Failed") errors.push("Starea validarii trebuie sa reflecte captura: Failed.");
  if (snapshot.validationStartedAt !== "2026-08-18") errors.push("Data de start a validarii este incorecta.");
  if (snapshot.validationFailedAt !== "2026-08-22") errors.push("Data esecului validarii este incorecta.");
  if (!Array.isArray(snapshot.pending) || snapshot.pending.length !== snapshot.pendingExamples) {
    errors.push("Lista Pending nu corespunde numarului declarat.");
  }
  if (!Array.isArray(snapshot.failed) || snapshot.failed.length !== snapshot.failedExamples) {
    errors.push("Lista Failed nu corespunde numarului declarat.");
  }
  const examples = [...(snapshot.pending || []), ...(snapshot.failed || [])];
  if (snapshot.pendingExamples !== 70) errors.push(`Exemple pending ${snapshot.pendingExamples}/70.`);
  if (snapshot.failedExamples !== 16) errors.push(`Exemple failed ${snapshot.failedExamples}/16.`);
  if (snapshot.totalValidationExamples !== 86) errors.push(`Total exemple ${snapshot.totalValidationExamples}/86.`);
  if (examples.length !== snapshot.totalValidationExamples) {
    errors.push("Suma exemplelor pending/failed nu corespunde totalului.");
  }
  if (new Set(examples.map((row) => row.url)).size !== examples.length) errors.push("Exista URL-uri duplicate intre Pending si Failed.");
  if (examples.some((row) => !validExample(row))) errors.push("Exista exemple cu URL sau data lastCrawled invalida.");
  if (!Array.isArray(snapshot.evidence) || snapshot.evidence.length !== 2) errors.push("Lipsesc cele doua capturi GSC sursa.");
  if (!String(snapshot.interpretation || "").includes("not a code defect")) errors.push("Lipseste interpretarea SEO a redirecturilor intentionate.");
  if (!String(snapshot.recommendedGscAction || "").includes("Do not restart Validate fix")) errors.push("Lipseste actiunea GSC corecta.");

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }

  console.log(`GSC Page with redirect validation snapshot valid: ${snapshot.pendingExamples} pending, ${snapshot.failedExamples} failed, ${snapshot.totalValidationExamples} total; all example rows are recorded.`);
}

main();
