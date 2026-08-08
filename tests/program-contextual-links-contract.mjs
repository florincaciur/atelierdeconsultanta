#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { auditProgramContextualLinks } = require("../tools/audit-program-contextual-links");
const { loadConfig, resolvedLinks, validateMatrix } = require("../tools/sync-program-contextual-links");
const { loadProgramConfig } = require("../tools/program-factual-governance");

const allPrograms = loadProgramConfig().programs;
const programs = allPrograms.filter((program) => !program.discovery?.redirectTarget);
const config = loadConfig();
validateMatrix(programs, config);
assert.equal(allPrograms.length, 20, "registrul trebuie să conțină 20 de programe");
assert.ok(fs.existsSync(path.join(ROOT, config.evidence.gscPages)), "lipsește dovada GSC pe pagini");
assert.ok(fs.existsSync(path.join(ROOT, config.evidence.gscQueries)), "lipsește dovada GSC pe query-uri");

const dr12 = programs.find((program) => program.slug === "dr12-afir");
assert.deepEqual(resolvedLinks(dr12, config).map(({ relation, href, anchor }) => ({ relation, href, anchor })), [
  { relation: "parent", href: "/afir", anchor: "revino la hubul AFIR și agricultură" },
  { relation: "instrument", href: "/calculator-soc", anchor: "calculează dimensiunea economică SO" },
  { relation: "comparison", href: "/dr12-vs-dr14", anchor: "compară condițiile DR 12 și DR 14" },
  { relation: "conversion", href: "/contact#program_slug=dr12-afir&source_page=%2Fdr12-afir", anchor: "Verifică încadrarea în DR 12" }
]);

const audit = auditProgramContextualLinks();
assert.equal(audit.errors.length, 0, audit.errors.join("\n"));
assert.equal(audit.summary.programs, 15);
assert.equal(audit.summary.links, 60);
assert.equal(audit.summary.trackedCtas, 15);
assert.equal(audit.summary.editorialLinksWithoutTracking, 45);
assert.equal(audit.summary.legacyCloudsRemaining, 0);
assert.deepEqual(audit.summary.relationCounts, { parent: 15, instrument: 15, comparison: 15, conversion: 15 });

console.log("Program contextual links contract PASS: 15 programe publice listate, 60 de relații, tracking exclusiv pe 15 CTA-uri.");
