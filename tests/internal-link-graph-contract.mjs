#!/usr/bin/env node

import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { auditInternalLinkGraph, HOMEPAGE_CORE_ROUTES } = require("../tools/audit-internal-link-graph");
const { isPublicProgram, loadProgramConfig } = require("../tools/program-factual-governance");
const { loadConfig, resolvedLinks } = require("../tools/sync-program-contextual-links");

const audit = auditInternalLinkGraph();
const programs = loadProgramConfig().programs.filter((program) => isPublicProgram(program) && !program.discovery?.redirectTarget);
const config = loadConfig();
const expectedRelated = programs.reduce((sum, program) => sum + resolvedLinks(program, config, programs).filter((link) => link.relation === "related").length, 0);
assert.equal(audit.errors.length, 0, audit.errors.join("\n"));
assert.equal(audit.summary.programPages, 24, "graful trebuie să includă toate programele canonice publice");
assert.equal(audit.summary.familyHubs, 5, "graful trebuie să includă toate familiile din registry");
assert.equal(audit.summary.services, 7, "toate serviciile publice trebuie asociate semantic");
assert.equal(audit.summary.uncoveredServices, 0, "există servicii fără relație către programe");
assert.equal(audit.summary.homepageCoreEntities, HOMEPAGE_CORE_ROUTES.length);
assert.equal(audit.summary.zeroIncoming, 0, "există pagini canonice orfane");
assert.equal(audit.summary.legacyLinks, 0, "există linkuri către URL-uri legacy");
assert.equal(audit.summary.nonCanonicalLinks, 0, "există linkuri necanonice între pagini indexabile");
assert.equal(audit.summary.brokenOrRedirectedLinks, 0, "există linkuri interne rupte sau redirectate");
assert.equal(audit.duplicateRelatedLinks.length, 0, "există programe asociate duplicate");
assert.equal(audit.missingHomepageCore.length, 0, "homepage nu acoperă toate entitățile centrale");
assert.deepEqual(audit.summary.relationCounts, {
  parent: 24,
  related: expectedRelated,
  service: 24,
  instrument: 24,
  guide: 24,
  conversion: 24
});

console.log(`Internal link graph contract PASS: ${audit.summary.canonicalPages} pagini, ${audit.summary.canonicalEdges} muchii și zero orfani.`);
