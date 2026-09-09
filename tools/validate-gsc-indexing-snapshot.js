#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const REPORTS_DIR = path.join(ROOT, "reports");
const SNAPSHOT_PATH = fs.readdirSync(REPORTS_DIR)
  .filter((file) => /^gsc-indexing-snapshot-\d{4}-\d{2}-\d{2}\.json$/u.test(file))
  .sort()
  .map((file) => path.join(REPORTS_DIR, file))
  .at(-1);
const EXPECTED_COUNTS = new Map([
  ["Page with redirect", 86],
  ["Crawled - currently not indexed", 2],
  ["Excluded by ‘noindex’ tag", 6],
  ["Alternate page with proper canonical tag", 5],
  ["Redirect error", 4],
  ["Duplicate without user-selected canonical", 1],
  ["Blocked by robots.txt", 1],
  ["Discovered - currently not indexed", 5]
]);

function isIsoDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/u.test(String(value || "")) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function examplesFor(category, errors) {
  if (Array.isArray(category.examples)) return category.examples;
  if (Array.isArray(category.urls)) return category.urls.map((url) => ({ url }));
  if (!category.examplesFrom) return [];

  const sourcePath = path.resolve(REPORTS_DIR, category.examplesFrom);
  if (!sourcePath.startsWith(`${REPORTS_DIR}${path.sep}`) || !fs.existsSync(sourcePath)) {
    errors.push(`${category.reason}: sursa de exemple lipsește sau iese din reports/.`);
    return [];
  }
  const source = JSON.parse(fs.readFileSync(sourcePath, "utf8"));
  if (source.property !== "sc-domain:atelierdeconsultanta.ro") {
    errors.push(`${category.reason}: proprietatea din ${category.examplesFrom} este incorectă.`);
  }
  return [
    ...(source.pending || []).map((row) => ({ ...row, validationState: "Pending" })),
    ...(source.failed || []).map((row) => ({ ...row, validationState: "Failed" }))
  ];
}

function main() {
  const errors = [];
  if (!SNAPSHOT_PATH) throw new Error("Nu există niciun snapshot GSC de indexare.");
  const snapshot = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, "utf8"));
  const filenameDate = path.basename(SNAPSHOT_PATH).match(/(\d{4}-\d{2}-\d{2})\.json$/u)?.[1];

  if (snapshot.property !== "sc-domain:atelierdeconsultanta.ro") errors.push("Proprietatea GSC este incorectă.");
  if (!isIsoDate(snapshot.capturedAt) || snapshot.capturedAt !== filenameDate) errors.push("Data capturii nu corespunde numelui fișierului.");
  if (!isIsoDate(snapshot.gscLastUpdate)) errors.push("gscLastUpdate trebuie să fie o dată ISO validă.");
  if (snapshot.notIndexedTotal !== 110) errors.push(`Totalul GSC trebuie să fie 110, nu ${snapshot.notIndexedTotal}.`);
  if (!Array.isArray(snapshot.categories)) errors.push("Lipsește lista categoriilor.");
  if (!Array.isArray(snapshot.evidence) || snapshot.evidence.length < 2) errors.push("Lipsesc dovezile capturii și inspecției GSC.");

  const urls = [];
  for (const category of snapshot.categories || []) {
    const expected = EXPECTED_COUNTS.get(category.reason);
    if (expected === undefined) errors.push(`Categorie necunoscută: ${category.reason}`);
    if (category.affectedPages !== expected) errors.push(`${category.reason}: affectedPages ${category.affectedPages}/${expected}.`);
    if (!["Failed", "Started", "Passed"].includes(category.validation)) errors.push(`${category.reason}: stare de validare necunoscută.`);
    for (const field of ["validationStartedAt", "validationFailedAt"]) {
      if (category[field] !== undefined && !isIsoDate(category[field])) errors.push(`${category.reason}: ${field} nu este o dată ISO validă.`);
    }

    const examples = examplesFor(category, errors);
    if (examples.length !== expected) errors.push(`${category.reason}: URL-uri ${examples.length}/${expected}.`);
    for (const example of examples) {
      const value = example.url;
      try {
        const url = new URL(value);
        if (!["http:", "https:"].includes(url.protocol) || url.hostname !== "atelierdeconsultanta.ro") errors.push(`${value}: URL extern sau protocol invalid.`);
      } catch {
        errors.push(`${value}: URL invalid.`);
      }
      if (example.lastCrawled !== undefined && example.lastCrawled !== null && !isIsoDate(example.lastCrawled)) {
        errors.push(`${value}: lastCrawled nu este o dată ISO validă.`);
      }
      urls.push(value);
    }
  }

  for (const reason of EXPECTED_COUNTS.keys()) {
    if (!(snapshot.categories || []).some((category) => category.reason === reason)) errors.push(`Categorie lipsă: ${reason}`);
  }
  if (urls.length !== snapshot.notIndexedTotal) errors.push(`Total URL-uri ${urls.length}/${snapshot.notIndexedTotal}.`);
  if (new Set(urls).size !== urls.length) errors.push("Snapshot-ul conține URL-uri duplicate între categorii.");
  if (!snapshot.interpretation || !snapshot.action) errors.push("Snapshot-ul trebuie să documenteze interpretarea și acțiunea tehnică.");

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`GSC snapshot valid: ${urls.length} URL-uri în ${snapshot.categories.length} categorii, zero exemple lipsă (${path.basename(SNAPSHOT_PATH)}).`);
}

main();
