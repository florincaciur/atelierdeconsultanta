#!/usr/bin/env node

import assert from "node:assert/strict";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(ROOT, "dist");
const LIVE = process.argv.includes("--live");
const USE_DIST = process.argv.includes("--dist");
const {
  auditBreadcrumbs,
  inspectBreadcrumbHtml,
  redirectSources
} = require("../tools/audit-breadcrumbs");
const {
  SITE,
  breadcrumbRouteEntries,
  canonicalUrl,
  normalizeRoute
} = require("../tools/breadcrumb-registry");
const { buildInventory } = require("../tools/generate-route-inventory");

const inventory = buildInventory();
const canonicalRoutes = new Set(inventory.routes.map((entry) => entry.route));
const programs = require("../config/seo-programs.json").programs;
const familyHubs = require("../config/program-family-hubs.json").hubs;
const intentRows = require("../reports/content-intent-inventory-2026-07-21.json").rows;
const showcaseGenerator = require("../tools/generate-2026-program-pages");

function lineage(route) {
  return breadcrumbRouteEntries(route).map((entry) => entry.route);
}

function assertLineage(route, expected, group) {
  assert.deepEqual(lineage(route), expected, `${group} ${route}: ierarhie breadcrumb divergentă`);
}

const labeledFixtures = [
  {
    type: "program",
    route: "/dr12-afir",
    expected: [["/", "Acasă"], ["/fonduri-europene", "Programe"], ["/afir", "AFIR & agricultură"], ["/dr12-afir", "DR 12"]]
  },
  {
    type: "guide",
    route: "/eligibilitate-fonduri-europene",
    expected: [["/", "Acasă"], ["/resurse", "Resurse"], ["/eligibilitate-fonduri-europene", "Eligibilitate fonduri europene"]]
  },
  {
    type: "service",
    route: "/proiectare-fonduri-europene",
    expected: [["/", "Acasă"], ["/consultanta-fonduri-europene", "Servicii"], ["/proiectare-fonduri-europene", "Proiectare pentru investiții finanțate din fonduri europene"]]
  },
  {
    type: "about",
    route: "/metodologie-verificare-eligibilitate",
    expected: [["/", "Acasă"], ["/despre-faber", "Despre FABER"], ["/metodologie-verificare-eligibilitate", "Metodologie"]]
  }
];

for (const fixture of labeledFixtures) {
  const actual = breadcrumbRouteEntries(fixture.route).map((entry) => [entry.route, entry.name]);
  assert.deepEqual(actual, fixture.expected, `${fixture.type}: mapping breadcrumb divergent`);
}

const programBySlug = new Map(programs.map((program) => [program.slug, program]));
for (const [slug, content] of Object.entries(showcaseGenerator.PAGE_CONTENT)) {
  const program = programBySlug.get(slug);
  const generated = showcaseGenerator.renderSynchronizedPage(program, content);
  const inspected = inspectBreadcrumbHtml(generated, program.pageUrl, { redirects: redirectSources(ROOT) });
  assert.deepEqual(inspected.issues, [], `${slug}: generatorul showcase reintroduce breadcrumb legacy`);
}

assert.deepEqual(breadcrumbRouteEntries("/"), [], "homepage nu trebuie să aibă breadcrumb");
assert.equal(inventory.routes.length, 105, "schimbarea inventarului public necesită review explicit");

const familyRoutes = new Set(familyHubs.map((hub) => normalizeRoute(hub.route)));
assert.equal(familyRoutes.size, 5, "schimbarea taxonomiei de familii necesită review explicit");
for (const route of familyRoutes) {
  assertLineage(route, ["/", "/fonduri-europene", route], "family");
}

const publicPrograms = programs.filter((program) => canonicalRoutes.has(normalizeRoute(program.pageUrl)));
assert.equal(publicPrograms.length, 24, "schimbarea numărului de programe publice necesită review explicit");
for (const program of publicPrograms) {
  const route = normalizeRoute(program.pageUrl);
  const family = normalizeRoute(program.discovery?.parentHub);
  assert.ok(familyRoutes.has(family), `${route}: familia din registry nu este un hub aprobat`);
  const expected = family === route
    ? ["/", "/fonduri-europene", route]
    : ["/", "/fonduri-europene", family, route];
  assertLineage(route, expected, "program");
}

const serviceRows = intentRows.filter((row) => row.type === "serviciu");
assert.equal(serviceRows.length, 17, "schimbarea inventarului de servicii necesită review explicit");
for (const row of serviceRows) {
  const expected = row.route === "/consultanta-fonduri-europene"
    ? ["/", row.route]
    : ["/", "/consultanta-fonduri-europene", row.route];
  assertLineage(row.route, expected, "service");
}

const guideRows = intentRows.filter((row) => row.type === "ghid");
assert.equal(guideRows.length, 34, "schimbarea inventarului de ghiduri necesită review explicit");
for (const row of guideRows) {
  const expectedParent = row.route === "/metodologie-verificare-eligibilitate"
    ? "/despre-faber"
    : "/resurse";
  assertLineage(row.route, ["/", expectedParent, row.route], "guide/article");
}

const questionRows = intentRows.filter((row) => row.type === "întrebare");
assert.equal(questionRows.length, 3, "schimbarea inventarului de întrebări necesită review explicit");
for (const row of questionRows) assertLineage(row.route, ["/", "/resurse", row.route], "question");

assertLineage("/resurse", ["/", "/resurse"], "resource root");
for (const route of ["/ghiduri", "/resurse-utile", "/blog", "/intrebari-frecvente", "/webinarii"]) {
  assertLineage(route, ["/", "/resurse", route], "resource hub");
}
assertLineage("/instrumente", ["/", "/instrumente"], "instrument root");
for (const route of ["/calculator-soc", "/calendar-fonduri-europene"]) {
  assertLineage(route, ["/", "/instrumente", route], "instrument");
}
assertLineage("/despre-faber", ["/", "/despre-faber"], "about root");
for (const route of ["/metodologie-verificare-eligibilitate", "/studii-de-caz-fonduri-europene"]) {
  assertLineage(route, ["/", "/despre-faber", route], "about child");
}
for (const route of ["/gdpr", "/politica-de-confidentialitate", "/termeni-si-conditii", "/contact"]) {
  assertLineage(route, ["/", route], "direct root child");
}

async function liveAudit() {
  const redirects = redirectSources(ROOT);
  const failures = [];
  let checked = 0;
  for (let offset = 0; offset < inventory.routes.length; offset += 8) {
    const batch = inventory.routes.slice(offset, offset + 8);
    const responses = await Promise.all(batch.map(async ({ route }) => {
      const response = await fetch(canonicalUrl(route), {
        redirect: "manual",
        signal: AbortSignal.timeout(20000),
        headers: { "cache-control": "no-cache" }
      });
      return { route, response, html: await response.text() };
    }));
    for (const { route, response, html } of responses) {
      checked += 1;
      const issues = [];
      if (response.status !== 200) issues.push(`HTTP ${response.status}`);
      if (!String(response.headers.get("content-type") || "").includes("text/html")) issues.push("Content-Type nu este text/html");
      issues.push(...inspectBreadcrumbHtml(html, route, { redirects }).issues);
      if (issues.length) failures.push(`${route}: ${issues.join("; ")}`);
    }
  }
  assert.deepEqual(failures, [], failures.join("\n"));
  console.log(`Breadcrumb live contract PASS: ${checked} rute canonical HTTP 200, HTML vizibil și JSON-LD în paritate.`);
}

if (LIVE) {
  await liveAudit();
} else {
  const root = USE_DIST ? DIST : ROOT;
  const audit = auditBreadcrumbs(root, { deployment: USE_DIST });
  assert.equal(audit.summary.routeCount, 105, "auditul trebuie să acopere toate rutele publice, inclusiv /gdpr");
  if (!USE_DIST) assert.equal(audit.summary.sourceCount, 114, "auditul local trebuie să acopere sursele canonical și sursele efective de deploy");
  assert.equal(audit.summary.fail, 0, audit.results
    .filter((result) => result.status === "FAIL")
    .map((result) => `${result.route}: ${result.issues.join("; ")}`)
    .join("\n"));
  assert.ok(audit.summary.maxDepth >= 4, "programele trebuie să păstreze traseul complet prin familie");
  console.log(`Breadcrumb contract PASS: taxonomie completă + ${audit.summary.routeCount} URL-uri/${audit.summary.sourceCount} surse ${USE_DIST ? "dist" : "locale"}.`);
}
