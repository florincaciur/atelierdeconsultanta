#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SNAPSHOT_PATH = path.join(ROOT, "reports", "gsc-indexing-snapshot-2026-08-08.json");
const EXPECTED_COUNTS = new Map([
  ["Page with redirect", 78],
  ["Excluded by noindex tag", 8],
  ["Alternate page with proper canonical tag", 6],
  ["Redirect error", 4],
  ["Duplicate without user-selected canonical", 1],
  ["Blocked by robots.txt", 1],
  ["Crawled - currently not indexed", 2],
  ["Discovered - currently not indexed", 6]
]);

function main() {
  const errors = [];
  const snapshot = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, "utf8"));
  if (snapshot.property !== "sc-domain:atelierdeconsultanta.ro") errors.push("Proprietatea GSC este incorectă.");
  if (snapshot.capturedAt !== "2026-08-08") errors.push("Data capturii este incorectă.");
  if (snapshot.notIndexedTotal !== 106) errors.push("Totalul GSC trebuie să fie 106.");
  if (!Array.isArray(snapshot.categories)) errors.push("Lipsește lista categoriilor.");

  const urls = [];
  for (const category of snapshot.categories || []) {
    const expected = EXPECTED_COUNTS.get(category.reason);
    if (expected === undefined) errors.push(`Categorie necunoscută: ${category.reason}`);
    if (category.affectedPages !== expected) errors.push(`${category.reason}: affectedPages ${category.affectedPages}/${expected}.`);
    if (!Array.isArray(category.urls) || category.urls.length !== expected) errors.push(`${category.reason}: URL-uri ${category.urls?.length || 0}/${expected}.`);
    if (!["Failed", "Started", "Passed"].includes(category.validation)) errors.push(`${category.reason}: stare de validare necunoscută.`);
    for (const value of category.urls || []) {
      try {
        const url = new URL(value);
        if (!["http:", "https:"].includes(url.protocol) || url.hostname !== "atelierdeconsultanta.ro") errors.push(`${value}: URL extern sau protocol invalid.`);
      } catch {
        errors.push(`${value}: URL invalid.`);
      }
      urls.push(value);
    }
  }

  for (const reason of EXPECTED_COUNTS.keys()) {
    if (!(snapshot.categories || []).some((category) => category.reason === reason)) errors.push(`Categorie lipsă: ${reason}`);
  }
  if (urls.length !== snapshot.notIndexedTotal) errors.push(`Total URL-uri ${urls.length}/${snapshot.notIndexedTotal}.`);
  if (new Set(urls).size !== urls.length) errors.push("Snapshot-ul conține URL-uri duplicate între categorii.");

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  console.log(`GSC snapshot valid: ${urls.length} URL-uri în ${snapshot.categories.length} categorii, zero exemple lipsă.`);
}

main();
