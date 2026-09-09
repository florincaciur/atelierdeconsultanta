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
const { isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");

const allPrograms = loadProgramConfig().programs;
const programs = allPrograms.filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget);
const config = loadConfig();
validateMatrix(programs, config);
assert(allPrograms.some((program) => program.slug === "dr18-afir"), "registrul trebuie să conțină DR 18");
assert.ok(fs.existsSync(path.join(ROOT, config.evidence.gscPages)), "lipsește dovada GSC pe pagini");
assert.ok(fs.existsSync(path.join(ROOT, config.evidence.gscQueries)), "lipsește dovada GSC pe query-uri");

const dr12 = programs.find((program) => program.slug === "dr12-afir");
assert.deepEqual(resolvedLinks(dr12, config, programs).map(({ relation, href, anchor }) => ({ relation, href, anchor })), [
  { relation: "parent", href: "/afir", anchor: "revino la hubul AFIR și agricultură" },
  { relation: "related", href: "/dr14", anchor: "compară cu DR14 AFIR" },
  { relation: "related", href: "/dr18", anchor: "compară cu DR18 AFIR" },
  { relation: "related", href: "/afir-autoconsum-agroalimentar", anchor: "compară cu AFIR Autoconsum Agroalimentar" },
  { relation: "service", href: "/consultanta-afir", anchor: "organizează verificarea și dosarul AFIR" },
  { relation: "instrument", href: "/calculator-soc", anchor: "calculează dimensiunea economică SO" },
  { relation: "guide", href: "/dr12-vs-dr14", anchor: "compară condițiile DR 12 și DR 14" },
  { relation: "conversion", href: "/contact#program_slug=dr12-afir&source_page=%2Fdr12-afir", anchor: "Verifică încadrarea în DR 12" }
]);

const audit = auditProgramContextualLinks();
assert.equal(audit.errors.length, 0, audit.errors.join("\n"));
assert.equal(audit.summary.programs, audit.summary.managedPrograms + audit.summary.excludedPrograms);
assert.equal(audit.summary.managedPrograms, audit.summary.programs - config.excludedRoutes.length);
assert.equal(audit.summary.excludedPrograms, config.excludedRoutes.length);
const expectedLinks = programs.reduce((sum, program) => sum + resolvedLinks(program, config, programs).length, 0);
const expectedRelated = programs.reduce((sum, program) => sum + resolvedLinks(program, config, programs).filter((link) => link.relation === "related").length, 0);
assert.equal(audit.summary.links, expectedLinks);
assert.equal(audit.summary.trackedCtas, audit.summary.managedPrograms);
assert.equal(audit.summary.editorialLinksWithoutTracking, expectedLinks - audit.summary.managedPrograms);
assert.equal(audit.summary.legacyCloudsRemaining, 0);
assert.deepEqual(audit.summary.relationCounts, {
  parent: audit.summary.managedPrograms,
  related: expectedRelated,
  service: audit.summary.managedPrograms,
  instrument: audit.summary.managedPrograms,
  guide: audit.summary.managedPrograms,
  conversion: audit.summary.managedPrograms
});
assert.deepEqual(config.excludedRoutes, []);
assert.equal(audit.routes.filter((route) => route.excluded && route.status === "PASS").length, 0);

console.log(`Program contextual links contract PASS: ${audit.summary.programs} programe publice și ${audit.summary.managedPrograms} blocuri gestionate.`);
