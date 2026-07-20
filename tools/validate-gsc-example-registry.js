#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const REGISTRY = path.join(ROOT, "reports", "gsc-example-registry-2026-07-20.csv");
const REQUIRED_COLUMNS = [
  "case_id",
  "gsc_reason",
  "url",
  "reported_status",
  "initial_http_status",
  "redirect_chain",
  "final_url",
  "declared_canonical",
  "meta_robots",
  "x_robots_tag",
  "in_sitemap",
  "internal_contextual_links",
  "decision",
  "action",
  "result",
  "verified_at",
  "notes"
];
const EXPECTED_COUNTS = new Map([
  ["Redirect error", 3],
  ["Excluded by noindex tag", 2],
  ["Duplicate without user-selected canonical", 1],
  ["Crawled - currently not indexed", 1],
  ["Alternate page with proper canonical tag", 1],
  ["Page with redirect", 2]
]);

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        cell += char;
      }
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n") {
      row.push(cell.replace(/\r$/u, ""));
      if (row.some((value) => value !== "")) rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += char;
    }
  }
  if (cell || row.length) {
    row.push(cell.replace(/\r$/u, ""));
    rows.push(row);
  }
  return rows;
}

function main() {
  const errors = [];
  if (!fs.existsSync(REGISTRY)) throw new Error(`Missing registry: ${REGISTRY}`);
  const [header = [], ...values] = parseCsv(fs.readFileSync(REGISTRY, "utf8"));
  if (header.join("|") !== REQUIRED_COLUMNS.join("|")) {
    errors.push("Registry columns differ from the required GSC audit schema.");
  }

  const rows = values.map((cells, index) => {
    if (cells.length !== header.length) errors.push(`Row ${index + 2} has ${cells.length}/${header.length} columns.`);
    return Object.fromEntries(header.map((column, cellIndex) => [column, cells[cellIndex] || ""]));
  });
  const ids = new Set();
  for (const row of rows) {
    if (!row.case_id) errors.push("Every registry row needs case_id.");
    if (ids.has(row.case_id)) errors.push(`Duplicate case_id: ${row.case_id}`);
    ids.add(row.case_id);
    if (!EXPECTED_COUNTS.has(row.gsc_reason)) errors.push(`Unexpected GSC reason: ${row.gsc_reason}`);
    if (!row.url && row.result !== "PENDING_GSC_EXAMPLE") {
      errors.push(`${row.case_id}: a row without an example URL must remain PENDING_GSC_EXAMPLE.`);
    }
    if (row.url) {
      try {
        const parsed = new URL(row.url);
        if (!/^https?:$/u.test(parsed.protocol)) errors.push(`${row.case_id}: unsupported URL protocol.`);
      } catch {
        errors.push(`${row.case_id}: invalid URL.`);
      }
    }
    if (/^(PASS|RESOLVED)/u.test(row.result) && !row.verified_at) {
      errors.push(`${row.case_id}: a resolved result needs verified_at.`);
    }
  }

  for (const [reason, expected] of EXPECTED_COUNTS) {
    const actual = rows.filter((row) => row.gsc_reason === reason).length;
    if (actual !== expected) errors.push(`${reason}: expected ${expected} rows, found ${actual}.`);
  }

  if (errors.length) {
    console.error(errors.map((error) => `- ${error}`).join("\n"));
    process.exit(1);
  }
  const pending = rows.filter((row) => row.result === "PENDING_GSC_EXAMPLE").length;
  console.log(`GSC registry valid: ${rows.length} cases, ${pending} pending exact example URLs, zero unverified resolutions.`);
}

main();
