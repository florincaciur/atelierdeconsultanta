#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const VALIDATION_PATH = path.join(ROOT, "reports", "gsc-page-with-redirect-validation-2026-08-18.json");

function main() {
  const errors = [];
  const snapshot = JSON.parse(fs.readFileSync(VALIDATION_PATH, "utf8"));

  if (snapshot.property !== "sc-domain:atelierdeconsultanta.ro") errors.push("Proprietatea GSC este incorecta.");
  if (snapshot.capturedAt !== "2026-08-18") errors.push("Data capturii de validare este incorecta.");
  if (snapshot.issue !== "Page with redirect") errors.push("Categoria GSC este incorecta.");
  if (snapshot.validationStatus !== "Failed") errors.push("Starea validarii trebuie sa reflecte captura: Failed.");
  if (snapshot.validationStartedAt !== "2026-08-09") errors.push("Data de start a validarii este incorecta.");
  if (snapshot.validationFailedAt !== "2026-08-11") errors.push("Data esecului validarii este incorecta.");
  if (snapshot.passedExamples !== 49) errors.push(`Exemple passed ${snapshot.passedExamples}/49.`);
  if (snapshot.failedExamples !== 32) errors.push(`Exemple failed ${snapshot.failedExamples}/32.`);
  if (snapshot.totalValidationExamples !== 81) errors.push(`Total exemple ${snapshot.totalValidationExamples}/81.`);
  if (snapshot.passedExamples + snapshot.failedExamples !== snapshot.totalValidationExamples) {
    errors.push("Suma exemplelor passed/failed nu corespunde totalului.");
  }
  if (!Array.isArray(snapshot.evidence) || snapshot.evidence.length !== 2) errors.push("Lipsesc cele doua capturi GSC sursa.");
  if (!String(snapshot.interpretation || "").includes("intentional canonical aliases")) errors.push("Lipseste interpretarea SEO a redirecturilor intentionate.");
  if (!String(snapshot.recommendedGscAction || "").includes("Do not restart Validate fix")) errors.push("Lipseste actiunea GSC corecta.");

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }

  console.log("GSC Page with redirect validation snapshot valid: 49 passed, 32 failed, 81 total; intentional aliases are not code failures.");
}

main();
