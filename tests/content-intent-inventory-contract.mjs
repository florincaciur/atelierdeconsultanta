import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const { readSitemapEntries } = require(path.join(ROOT, "tools", "sitemap-utils.js"));
const taxonomy = JSON.parse(fs.readFileSync(path.join(ROOT, "config", "content-intent-taxonomy.json"), "utf8"));
const report = JSON.parse(fs.readFileSync(path.join(ROOT, "reports", "content-intent-inventory-2026-07-21.json"), "utf8"));
const html = fs.readFileSync(path.join(ROOT, "reports", "content-intent-inventory-2026-07-21.html"), "utf8");

const sitemapRoutes = readSitemapEntries(ROOT).entries.map(({ url }) => new URL(url).pathname).sort();
const rows = report.rows;
const routes = rows.map(({ route }) => route).sort();
const routeSet = new Set(routes);

assert.equal(rows.length, sitemapRoutes.length, "inventory must cover every canonical/indexable sitemap URL");
assert.equal(new Set(routes).size, rows.length, "each canonical route must occur exactly once");
assert.deepEqual(routes, sitemapRoutes, "inventory and sitemap must have exact route parity");
assert.equal(report.summary.inventoriedUrlCount, rows.length, "summary count must match rows");
assert.equal(report.summary.canonicalUrlCount, sitemapRoutes.length, "canonical summary must match sitemap");

const requiredTextFields = [
  "url", "route", "sourceFile", "type", "primaryAudience", "mainQuestion", "queryCluster", "primaryIntent",
  "h1", "uniquePromise", "cta", "ctaTarget", "microConversion", "parent", "demonstrableUniqueValue",
  "recommendation", "recommendationReason", "decisionState", "owner", "nextReviewAt",
];

for (const row of rows) {
  for (const key of requiredTextFields) assert.ok(typeof row[key] === "string" && row[key].trim(), `${row.route}: ${key} is required`);
  assert.ok(taxonomy.controlledValues.types.includes(row.type), `${row.route}: uncontrolled type ${row.type}`);
  assert.ok(taxonomy.controlledValues.intents.includes(row.primaryIntent), `${row.route}: uncontrolled primary intent ${row.primaryIntent}`);
  assert.ok(taxonomy.controlledValues.recommendations.includes(row.recommendation), `${row.route}: uncontrolled recommendation`);
  assert.ok(taxonomy.controlledValues.decisionStates.includes(row.decisionState), `${row.route}: uncontrolled decision state`);
  assert.ok(row.parent === "ROOT" || routeSet.has(row.parent), `${row.route}: parent ${row.parent} is not canonical`);
  assert.ok(Array.isArray(row.competingUrls), `${row.route}: competingUrls must be an array`);
  assert.notEqual(row.h1, "LIPSĂ_H1", `${row.route}: canonical pages require an H1`);
  assert.match(row.url, /^https:\/\/atelierdeconsultanta\.ro\//u, `${row.route}: URL must use the canonical HTTPS host`);
  assert.ok(row.evidence && Number.isInteger(row.evidence.headingCount), `${row.route}: HTML evidence is required`);

  if (row.type === "program") {
    assert.ok(
      row.ctaTarget.startsWith("/contact") || row.ctaTarget.startsWith("/consultanta-"),
      `${row.route}: program CTA must lead to triage or a service`,
    );
  }
  if (row.recommendation === "merge" || row.recommendation === "noindex") {
    assert.equal(row.decisionState, "APROBARE_UMANĂ_NECESARĂ", `${row.route}: destructive SEO decisions require approval`);
  }
  if (row.recommendation === "merge") {
    assert.ok(row.recommendationTarget, `${row.route}: merge requires a target`);
    assert.ok(routeSet.has(row.recommendationTarget), `${row.route}: merge target must be a canonical row`);
  }
}

for (const pattern of taxonomy.scaledPatterns) {
  for (const row of rows.filter(({ route }) => new RegExp(pattern, "u").test(route))) {
    assert.equal(row.decisionState, "APROBARE_UMANĂ_NECESARĂ", `${row.route}: scaled local/CAEN route requires human evidence`);
  }
}

for (const blocked of taxonomy.blockedNonIndexableRoutes) {
  assert.ok(!routeSet.has(blocked.route), `${blocked.route}: blocked/nonindexable route must not be inventoried as canonical`);
  assert.ok(report.blockedDecisions.some(({ route }) => route === blocked.route), `${blocked.route}: blocked route must be documented`);
}

assert.match(html, /id="q"/u, "filterable report needs a text search control");
assert.match(html, /id="type"/u, "filterable report needs a type filter");
assert.match(html, /id="intent"/u, "filterable report needs an intent filter");
assert.match(html, /id="recommendation"/u, "filterable report needs a recommendation filter");

console.log(`PASS: P1.01 contract covers ${rows.length} canonical URLs with one controlled primary intent each.`);
