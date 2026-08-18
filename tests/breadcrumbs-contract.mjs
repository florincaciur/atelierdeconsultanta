#!/usr/bin/env node

import assert from "node:assert/strict";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { auditBreadcrumbs } = require("../tools/audit-breadcrumbs");
const { breadcrumbRouteEntries } = require("../tools/breadcrumb-registry");

const fixtures = [
  {
    type: "program",
    route: "/dr12-afir",
    expected: [
      ["/", "Acasă"],
      ["/fonduri-europene", "Programe"],
      ["/afir", "AFIR & agricultură"],
      ["/dr12-afir", "DR 12"]
    ]
  },
  {
    type: "guide",
    route: "/eligibilitate-fonduri-europene",
    expected: [
      ["/", "Acasă"],
      ["/ghiduri", "Ghiduri"],
      ["/eligibilitate-fonduri-europene", "Eligibilitate fonduri europene"]
    ]
  },
  {
    type: "service",
    route: "/consultanta-fonduri-europene",
    expected: [
      ["/", "Acasă"],
      ["/consultanta-fonduri-europene", "Consultanță fonduri europene"]
    ]
  }
];

for (const fixture of fixtures) {
  const actual = breadcrumbRouteEntries(fixture.route).map((entry) => [entry.route, entry.name]);
  assert.deepEqual(actual, fixture.expected, `${fixture.type}: mapping breadcrumb divergent`);
}

assert.deepEqual(breadcrumbRouteEntries("/"), [], "homepage nu trebuie să aibă breadcrumb");

const audit = auditBreadcrumbs(ROOT);
assert.equal(audit.summary.routeCount, 101, "auditul trebuie să acopere inventarul canonic/indexabil, inclusiv DR18");
assert.equal(audit.summary.fail, 0, audit.results
  .filter((result) => result.status === "FAIL")
  .map((result) => `${result.route}: ${result.issues.join("; ")}`)
  .join("\n"));
assert.ok(audit.summary.maxDepth >= 4, "programele trebuie să poată păstra traseul complet prin familie");

console.log(`Breadcrumb contract PASS: 3 tipuri unitare + ${audit.summary.routeCount} URL-uri crawl/paritate.`);
